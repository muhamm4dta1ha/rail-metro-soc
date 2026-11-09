"""Regression tests with explicitly artificial events and run metadata."""

import json
from datetime import timedelta

import numpy as np
import pandas as pd
import pytest

from railsoc_common.events import (
    EventValidationError,
    make_event,
    utc_iso,
    validate_event,
    write_events,
)
from railsoc_common.groundtruth import AttackRun
from railsoc_common.ids import new_run_id
from railsoc_ml.cli import main
from railsoc_ml.dataset import (
    build_dataset,
    load_dataset,
    normal_windows,
    save_dataset,
    split_windows,
)
from railsoc_ml.evaluate import evaluate_detector
from railsoc_ml.features import FEATURES, events_to_frame, window_features
from railsoc_ml.models import AnomalyDetector, SupervisedDetector, ThresholdBaseline
from railsoc_ml.serve import score_events, score_file, score_stream


def test_validation_rejects_broken_schema_and_impossible_timestamps(h):
    event = h.request(h.T0, h.ATTACKER)
    with pytest.raises(EventValidationError, match="forbidden"):
        build_dataset([{**event, "run_id": "secret"}], [])
    with pytest.raises(ValueError):
        build_dataset([{**event, "@timestamp": "2026-02-30T09:00:00Z"}], [])
    with pytest.raises(ValueError, match="positive integer"):
        build_dataset([], [], window_s=0)


def test_baselines_and_campaign_neighbors_are_grouped_and_normal_is_clean(h, tmp_path):
    def run(scenario, start_s, end_s, **fields):
        start = h.T0 + timedelta(seconds=start_s)
        return AttackRun(
            new_run_id(scenario, start), scenario, start, h.T0 + timedelta(seconds=end_s), **fields
        )

    baseline = run("BASELINE", 20, 43)
    attack = run("B", 64, 83, attacker_ips=(h.ATTACKER,), victim_ips=(h.VICTIM,))
    events = [
        h.request(h.T0 + timedelta(seconds=s), ip)
        for s in range(0, 140, 3)
        for ip in ("10.60.10.21", "10.60.10.22")
    ]
    events += [
        h.request(attack.start, h.ATTACKER),
        make_event(
            "svc.health",
            "availability",
            "healthcheck",
            "success",
            ts=attack.start,
            host={"name": "monitor"},
        ),
    ]
    data = build_dataset(events, [baseline, attack])
    path = tmp_path / "dataset.csv"
    save_dataset(data, path)
    loaded = load_dataset(path)
    assert data.attrs == loaded.attrs
    train, val, test = split_windows(loaded, 0.35, validation_fraction=0.2)
    for a, b in ((train, val), (val, test)):
        assert a["window_start"].max() + timedelta(seconds=10) <= b["window_start"].min()
    for run_id in (baseline.run_id, attack.run_id):
        assert sum(part["run_id"].eq(run_id).any() for part in (train, val, test)) == 1
    assert baseline.run_id in set(normal_windows(data)["run_id"])
    at_attack = data[data["campaign_overlap"]]
    assert set(at_attack["label"]) == {"attack", "attack_impact", "benign"}
    assert not normal_windows(data)["campaign_overlap"].any()
    assert at_attack.loc[at_attack["label"].eq("attack"), "attacker_ips"].item() == h.ATTACKER
    assert not set(FEATURES) & {"attacker_ips", "victim_ips", "label", "run_id"}


def test_feature_statistics_and_missing_fields(h):
    time = h.T0
    source = {"ip": h.ATTACKER}
    telemetry = [
        make_event(
            "scada.poll",
            "telemetry",
            "poll",
            "success",
            ts=time,
            host={"name": "plc"},
            source=source,
            modbus={"function_code": code},
            metric={"name": "station_temp_c", "value": value, "unit": "C"},
            network={"bytes": 10, "packets": 2},
        )
        for code, value in [(3, 22), (3, 26), (43, 24)]
    ]
    mqtt = make_event(
        "mqtt.broker",
        "network",
        "connect",
        ts=time,
        host={"name": "broker"},
        source=source,
        network={"protocol": "mqtt"},
        mqtt={"topic": "station/display"},
    )
    web = h.login(time, h.ATTACKER, False)
    web["http"]["response"]["latency_ms"] = 7.5
    bare = make_event(
        "svc.health", "availability", "healthcheck", ts=time, host={"name": "monitor"}
    )
    rows = window_features(events_to_frame([bare, mqtt, web, *telemetry])).set_index("src_ip")
    row = rows.loc[h.ATTACKER]
    assert row["n_modbus_read"] == 2 and row["modbus_fc_other_ratio"] == pytest.approx(1 / 3)
    assert row["modbus_fc_3_ratio"] == pytest.approx(2 / 3)
    assert row["station_temp_c_mean"] == 24 and row["station_temp_c_range"] == 4
    assert row["n_auth_failures"] == row["auth_failure_ratio"] == 1
    assert row["http_requests_per_s"] == 0.1 and row["mean_http_latency_ms"] == 7.5
    assert row["n_mqtt_connect"] == row["n_mqtt_topics"] == 1
    assert row["network_bytes"] == 30 and row["network_packets"] == 6
    assert rows.loc["", "n_events"] == 1 and rows.loc["", "n_http_latency_samples"] == 0
    assert np.isfinite(rows.to_numpy(dtype=float)).all()


def test_normal_only_fitting_and_separate_validation_calibration(stream):
    data = build_dataset(*stream)
    train, val, _ = split_windows(data, validation_fraction=0.2)
    with pytest.raises(ValueError, match="normal"):
        AnomalyDetector().fit(data)
    model = AnomalyDetector().fit(normal_windows(train))
    clean_val = normal_windows(val)
    assert model.calibrate(clean_val, target_fpr=0.01) == np.quantile(
        model.score(clean_val), 0.99, method="higher"
    )
    with pytest.raises(ValueError, match="normal"):
        model.calibrate(data)
    with pytest.raises(ValueError, match="catalogue"):
        SupervisedDetector(features=["run_id"])


def test_incremental_alerts_match_batch_and_ignore_feedback(stream, tmp_path):
    events, _ = stream
    baseline = ThresholdBaseline()
    batch = score_events(events, baseline)
    assert list(score_stream(iter(events), baseline)) == batch
    assert len({(a["@timestamp"], a["source"]["ip"]) for a in batch}) == len(batch)
    for alert in batch:
        validate_event(alert)
    combined = sorted([*events, *batch], key=lambda e: e["@timestamp"])
    assert list(score_stream(combined, baseline)) == batch
    path = tmp_path / "log.jsonl"
    out = tmp_path / "alerts.jsonl"
    write_events(path, events)
    assert score_file(path, baseline, out, streaming=True) == len(batch)
    previous = out.read_bytes()
    write_events(path, reversed(events))
    with pytest.raises(ValueError, match="timestamp order"):
        score_file(path, baseline, out, streaming=True)
    assert out.read_bytes() == previous
    with pytest.raises(ValueError, match="limit"):
        list(score_stream(events, baseline, max_window_events=1))


def test_evaluation_reports_scenario_recall_latency_and_false_alarms(h):
    start = h.T0 + timedelta(seconds=11)
    run = AttackRun(
        new_run_id("C", start), "C", start, start + timedelta(seconds=3), attacker_ips=(h.ATTACKER,)
    )
    events = [h.request(h.T0, "10.60.10.21", 500)] * 5
    events += [h.request(start, h.ATTACKER, 500)] * 5
    events += [h.request(start + timedelta(seconds=20), "10.60.10.21")]
    data = build_dataset(events, [run])
    report, alerts = evaluate_detector(ThresholdBaseline(), data, 10)
    assert (report["tp"], report["fp"], report["tn"], report["fn"]) == (1, 1, 1, 0)
    assert report["false_alarms_per_hour"] == pytest.approx(180)
    assert report["per_scenario_window_recall"] == {"A": None, "B": None, "C": 1.0}
    assert report["run_metrics"]["runs"][0]["time_to_detect_s"] == 9
    assert report["false_positive_examples"][0]["top_features"] == ["n_failures"]
    assert len(alerts) == 2


def test_dataset_order_and_csv_are_reproducible(stream, tmp_path):
    events, runs = stream
    first = build_dataset(events, runs)
    second = build_dataset(reversed(events), list(reversed(runs)))
    pd.testing.assert_frame_equal(first, second)
    one, two = tmp_path / "one.csv", tmp_path / "two.csv"
    save_dataset(first, one)
    save_dataset(second, two)
    assert one.read_bytes() == two.read_bytes()
    assert one.with_suffix(".meta.json").read_bytes() == two.with_suffix(".meta.json").read_bytes()


def test_compare_runs_all_models_on_a_synthetic_multiscenario_holdout(stream, h, tmp_path):
    events, runs = map(list, stream)
    for scenario, offset, ip in [("B", 1050, "10.60.30.99"), ("C", 1110, h.ATTACKER)]:
        start = h.T0 + timedelta(seconds=offset)
        runs.append(
            AttackRun(
                new_run_id(scenario, start),
                scenario,
                start,
                start + timedelta(seconds=5),
                attacker_ips=(ip,),
            )
        )
        for i in range(15):
            ts = start + timedelta(milliseconds=100 * i)
            if scenario == "B":
                events.append(
                    make_event(
                        "scada.command",
                        "configuration",
                        "write_register",
                        "success",
                        ts=ts,
                        host={"name": "fixture-plc"},
                        source={"ip": ip},
                        modbus={"function_code": 6},
                    )
                )
            else:
                events.append(h.request(ts, ip, status=503))

    dataset = tmp_path / "synthetic.csv"
    save_dataset(build_dataset(events, runs), dataset)
    report_dir = tmp_path / "report"
    models = tmp_path / "models"
    wazuh = tmp_path / "wazuh.jsonl"
    wazuh.write_text(
        json.dumps(
            {
                "timestamp": utc_iso(runs[-1].start + timedelta(seconds=1)),
                "rule": {"id": "100300", "level": 6},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    assert (
        main(
            [
                "compare",
                "--dataset",
                str(dataset),
                "--test-fraction",
                "0.25",
                "--models-dir",
                str(models),
                "--report-dir",
                str(report_dir),
                "--wazuh-alerts",
                str(wazuh),
            ]
        )
        == 0
    )
    report = json.loads((report_dir / "metrics.json").read_text(encoding="utf-8"))
    assert {row["model"] for row in report["models"]} == {
        "threshold_failures",
        "ocsvm",
        "isolation_forest",
        "random_forest",
    }
    assert report["supervised_skip"] is None
    assert report["wazuh_rules"]["per_scenario"]["C"]["detected"] == 1
    assert {row["scenario_id"] for row in report["models"][0]["run_metrics"]["runs"]} == {
        "A",
        "B",
        "C",
    }
    assert len(list(models.glob("*.joblib"))) == 4
    assert (report_dir / "false_positives.png").is_file()
    assert (report_dir / "confusion_matrices.png").is_file()


def test_dataset_rejects_a_mismatched_sidecar(h, tmp_path):
    path = tmp_path / "dataset.csv"
    save_dataset(build_dataset([h.request(h.T0, h.ATTACKER)], []), path)
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="does not match"):
        load_dataset(path)

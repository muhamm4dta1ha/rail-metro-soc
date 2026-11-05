import json

import pytest

from railsoc_common.events import read_events, validate_event, write_events
from railsoc_common.groundtruth import write_runs
from railsoc_ml.cli import main
from railsoc_ml.dataset import build_dataset
from railsoc_ml.models import AnomalyDetector
from railsoc_ml.serve import score_events, score_file


@pytest.fixture(scope="module")
def detector(stream):
    events, runs = stream
    data = build_dataset(events, runs)
    normal = data[data["run_id"] == ""]
    model = AnomalyDetector(seed=1).fit(normal)
    model.calibrate(normal, target_fpr=0.01)
    return model


def test_alerts_are_valid_contract_events_for_the_attacker(stream, detector, h):
    events, runs = stream
    alerts = score_events(events, detector)
    attacker_alerts = [a for a in alerts if a.get("source", {}).get("ip") == h.ATTACKER]
    assert len(attacker_alerts) == len(runs)  # one alert per burst
    assert len(alerts) <= len(runs) + 10  # and (almost) no false alarms on normal traffic
    for alert in attacker_alerts:
        validate_event(alert)
        assert alert["event"]["dataset"] == "ml.alert"
        assert alert["ml"]["model"] == "ocsvm"
        assert alert["ml"]["score"] > alert["ml"]["threshold"]
        assert alert["ml"]["top_features"]


def test_no_events_means_no_alerts(detector):
    assert score_events([], detector) == []


def test_score_file_writes_json_lines(stream, detector, tmp_path):
    events, runs = stream
    events_path = tmp_path / "events.jsonl"
    write_events(events_path, events)
    out_path = tmp_path / "alerts.jsonl"
    count = score_file(events_path, detector, out_path)
    assert count == len(list(read_events(out_path, validate=True)))
    assert count >= len(runs)


def test_cli_pipeline_end_to_end(stream, tmp_path, capsys, h):
    events, runs = stream
    events_path = tmp_path / "events.jsonl"
    write_events(events_path, events)
    runs_path = tmp_path / "runs.csv"
    write_runs(runs_path, runs)
    dataset = tmp_path / "dataset.csv"
    model = tmp_path / "anomaly.joblib"
    alerts = tmp_path / "alerts.jsonl"

    args = ["build-dataset", "--events", str(events_path), "--runs", str(runs_path)]
    assert main([*args, "--out", str(dataset)]) == 0
    assert f"{len(runs)} attack" in capsys.readouterr().out

    train_args = ["train", "--dataset", str(dataset), "--out", str(model), "--test-fraction", "0.5"]
    assert main(train_args) == 0
    report = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert report["model"] == "ocsvm" and "recall" in report and "fpr" in report
    assert model.exists()

    score_args = ["score", "--events", str(events_path), "--model", str(model), "--out", str(alerts)]
    assert main(score_args) == 0
    written = [json.loads(line) for line in alerts.read_text(encoding="utf-8").splitlines()]
    assert any(a["source"]["ip"] == h.ATTACKER for a in written)

from datetime import UTC, datetime, timedelta

import pytest

from railsoc_common.events import make_event
from railsoc_common.groundtruth import (
    ATTACK,
    ATTACK_IMPACT,
    BENIGN,
    AttackRun,
    append_run,
    label_event,
    load_runs,
    write_runs,
)
from railsoc_common.ids import new_run_id

START = datetime(2026, 1, 5, 9, 0, 0, tzinfo=UTC)


def make_run(scenario="A", seq=1, **overrides):
    fields = {
        "run_id": new_run_id(scenario, START, seq),
        "scenario_id": scenario,
        "start": START,
        "end": START + timedelta(minutes=2),
        "attacker_ips": ("10.60.66.10",),
        "victim_ips": ("10.60.20.10",),
        "victim_assets": ("PIS-01",),
        "techniques": ("T1110",),
    }
    fields.update(overrides)
    return AttackRun(**fields)


def event(offset_s, src, dst, asset=None):
    return make_event(
        "pis.app",
        "authentication",
        "login",
        "failure",
        ts=START + timedelta(seconds=offset_s),
        host={"name": "pis-01"},
        source={"ip": src},
        destination={"ip": dst},
        asset={"id": asset} if asset else None,
    )


def test_attacker_traffic_inside_the_window_is_attack():
    run = make_run()
    label = label_event(event(10, "10.60.66.10", "10.60.20.10"), [run])
    assert label == (ATTACK, run.run_id, "A")


def test_victim_side_effects_are_attack_impact():
    run = make_run()
    assert label_event(event(10, "10.60.10.21", "10.60.20.10"), [run]).label == ATTACK_IMPACT
    assert label_event(event(10, "10.60.30.11", "10.60.30.12", asset="PIS-01"), [run]).label == (
        ATTACK_IMPACT
    )


def test_events_outside_the_window_or_unrelated_are_benign():
    run = make_run()
    assert label_event(event(-5, "10.60.66.10", "10.60.20.10"), [run]).label == BENIGN
    assert label_event(event(600, "10.60.66.10", "10.60.20.10"), [run]).label == BENIGN
    assert label_event(event(10, "10.60.10.21", "10.60.10.22"), [run]).label == BENIGN


def test_baseline_runs_never_label_anything_as_attack():
    baseline = make_run("BASELINE", attacker_ips=(), victim_ips=())
    assert label_event(event(10, "10.60.66.10", "10.60.20.10"), [baseline]).label == BENIGN


def test_attack_beats_impact_when_runs_overlap():
    impact_run = make_run("C", victim_ips=("10.60.20.10",), attacker_ips=("10.60.66.11",))
    attack_run = make_run("A", seq=2)
    label = label_event(event(10, "10.60.66.10", "10.60.20.10"), [impact_run, attack_run])
    assert label.label == ATTACK and label.scenario_id == "A"


def test_runs_must_stay_inside_the_lab():
    with pytest.raises(ValueError, match="outside the lab"):
        make_run(victim_ips=("8.8.8.8",))
    with pytest.raises(ValueError, match="outside the lab"):
        make_run(attacker_ips=("192.168.1.5",))


def test_run_validation():
    with pytest.raises(ValueError, match="end must be after start"):
        make_run(end=START)
    with pytest.raises(ValueError, match="invalid run id"):
        make_run(run_id="nope")
    with pytest.raises(ValueError, match="BASELINE"):
        make_run("BASELINE")  # baseline cannot carry an attacker


def test_csv_roundtrip_and_single_header(tmp_path):
    path = tmp_path / "gt" / "attack_runs.csv"
    run_a = make_run("A", params={"rate_per_s": 2})
    run_b = make_run("B", seq=2, attacker_ips=("10.60.30.99",), victim_ips=("10.60.30.11",))
    append_run(path, run_a)
    append_run(path, run_b)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("run_id,scenario_id") and len(lines) == 3
    assert load_runs(path) == [run_a, run_b]

    write_runs(path, [run_b])
    assert load_runs(path) == [run_b]


def test_missing_ground_truth_file_means_no_runs(tmp_path):
    assert load_runs(tmp_path / "does_not_exist.csv") == []

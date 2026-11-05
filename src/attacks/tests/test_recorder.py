import json
from datetime import timedelta

import pytest

from railsoc_attacks.recorder import run_scenario
from railsoc_attacks.safety import KillSwitchEngaged, LabScope, TargetNotAllowed
from railsoc_common.groundtruth import load_runs


class Clock:
    """Returns the given times in order, then keeps returning the last one."""

    def __init__(self, *times):
        self.times = list(times)

    def __call__(self):
        return self.times.pop(0) if len(self.times) > 1 else self.times[0]


def test_dry_run_writes_a_manifest_but_no_ground_truth(tmp_path, noop_cls, scope, t0):
    gt = tmp_path / "gt.csv"
    result = run_scenario(
        noop_cls(), evidence_dir=tmp_path / "ev", ground_truth_csv=gt, clock=Clock(t0), scope=scope
    )
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "dry_run" and manifest["actions"] == []
    assert "dry_runs" in result.manifest_path.parts
    assert not gt.exists()


def test_live_run_appends_a_ground_truth_row(tmp_path, noop_cls, scope, t0):
    gt = tmp_path / "gt.csv"
    result = run_scenario(
        noop_cls(),
        dry_run=False,
        evidence_dir=tmp_path / "ev",
        ground_truth_csv=gt,
        clock=Clock(t0, t0 + timedelta(seconds=7)),
        scope=scope,
    )
    (run,) = load_runs(gt)
    assert run.run_id == "RUN-A-20260105T090000Z-01"
    assert run.start == t0 and run.end == t0 + timedelta(seconds=7)
    assert run.attacker_ips == ("10.60.66.10",) and run.victim_assets == ("PIS-01",)
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "completed" and manifest["actions"] == ["noop executed"]
    assert "dry_runs" not in result.manifest_path.parts


def test_targets_outside_the_lab_are_refused_even_in_a_dry_run(tmp_path, noop_cls, scope, t0):
    with pytest.raises(TargetNotAllowed):
        run_scenario(
            noop_cls(),
            {"target_ip": "8.8.8.8"},
            evidence_dir=tmp_path / "ev",
            ground_truth_csv=tmp_path / "gt.csv",
            clock=Clock(t0),
            scope=scope,
        )
    assert not (tmp_path / "ev").exists()


def test_kill_switch_blocks_a_live_run_before_anything_is_recorded(tmp_path, noop_cls, t0):
    kill = tmp_path / ".kill"
    kill.write_text("stop")
    with pytest.raises(KillSwitchEngaged):
        run_scenario(
            noop_cls(),
            dry_run=False,
            evidence_dir=tmp_path / "ev",
            ground_truth_csv=tmp_path / "gt.csv",
            clock=Clock(t0),
            scope=LabScope(kill_switch_file=kill),
        )
    assert not (tmp_path / "gt.csv").exists()


def test_a_run_aborted_mid_way_is_still_labelled(tmp_path, noop_cls, scope, t0):
    class KillMidRun(noop_cls):
        def execute(self, ctx):
            ctx.note("started")
            ctx.scope.kill_switch_file.write_text("stop")
            ctx.guard(ctx.params["target_ip"])  # raises KillSwitchEngaged

    gt = tmp_path / "gt.csv"
    with pytest.raises(KillSwitchEngaged):
        run_scenario(
            KillMidRun(),
            dry_run=False,
            evidence_dir=tmp_path / "ev",
            ground_truth_csv=gt,
            clock=Clock(t0, t0 + timedelta(seconds=3)),
            scope=scope,
        )
    (run,) = load_runs(gt)
    assert "status=aborted" in run.notes


def test_rate_and_duration_are_clamped_by_the_scope(tmp_path, noop_cls, t0):
    scope = LabScope(max_rate_per_s=5, max_duration_s=30, kill_switch_file=tmp_path / ".kill")
    result = run_scenario(
        noop_cls(),
        {"duration_s": 10_000, "rate_per_s": 10_000},
        evidence_dir=tmp_path / "ev",
        ground_truth_csv=tmp_path / "gt.csv",
        clock=Clock(t0),
        scope=scope,
    )
    assert result.run.params["duration_s"] == 30
    assert result.run.params["rate_per_s"] == 5

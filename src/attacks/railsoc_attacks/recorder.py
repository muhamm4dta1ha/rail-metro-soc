"""Run recorder: one call = guarded run + evidence manifest + ground-truth row (tasks M2-08/M2-09).

* The target check runs first, even for dry runs: nothing outside the lab is ever planned.
* Dry runs (the default) send no traffic and never touch lab/ground_truth/attack_runs.csv.
* Live runs append a ground-truth row even if the scenario aborts part-way, so partial attacks
  are still labelled.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from railsoc_attacks.safety import LabScope, load_scope
from railsoc_attacks.scenario import RunContext, ScenarioBase
from railsoc_common import CONTRACT_VERSION
from railsoc_common.events import as_utc, utc_iso
from railsoc_common.groundtruth import AttackRun, append_run
from railsoc_common.ids import new_run_id

DEFAULT_EVIDENCE_DIR = Path("lab/evidence/runs")
DEFAULT_GROUND_TRUTH = Path("lab/ground_truth/attack_runs.csv")


@dataclass(frozen=True)
class RunResult:
    run: AttackRun
    manifest_path: Path
    status: str
    dry_run: bool


def _utcnow() -> datetime:
    return datetime.now(UTC)


def git_commit() -> str | None:
    """Best-effort commit hash of the simulation and attack code that produced the evidence."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout.strip() or None


def run_scenario(
    scenario: ScenarioBase,
    params: dict[str, Any] | None = None,
    *,
    scope: LabScope | None = None,
    dry_run: bool = True,
    evidence_dir: Path = DEFAULT_EVIDENCE_DIR,
    ground_truth_csv: Path = DEFAULT_GROUND_TRUTH,
    clock: Callable[[], datetime] = _utcnow,
    seq: int = 1,
) -> RunResult:
    scope = scope or load_scope()
    merged = {**scenario.default_params, **(params or {})}
    if "duration_s" in merged:
        merged["duration_s"] = scope.clamp_duration(merged["duration_s"])
    if "rate_per_s" in merged:
        merged["rate_per_s"] = scope.clamp_rate(merged["rate_per_s"])

    plan = scenario.plan(merged)
    for ip in (*plan.attacker_ips, *plan.victim_ips):  # fail fast, even for dry runs
        scope.assert_target_allowed(ip)
    if not dry_run:
        scope.assert_not_killed()

    started = as_utc(clock())
    run_id = new_run_id(scenario.scenario_id, started, seq)
    ctx = RunContext(run_id=run_id, scope=scope, params=merged, dry_run=dry_run)
    status = "dry_run" if dry_run else "completed"
    error: str | None = None
    result: RunResult | None = None
    try:
        if not dry_run:
            scenario.execute(ctx)
    except BaseException as exc:
        status, error = "aborted", repr(exc)
        raise
    finally:
        if dry_run:
            ended = started + timedelta(seconds=max(1.0, float(merged.get("duration_s", 1.0))))
        else:
            ended = max(as_utc(clock()), started + timedelta(seconds=1))
        run_dir = evidence_dir / "dry_runs" / run_id if dry_run else evidence_dir / run_id
        run = AttackRun(
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            start=started,
            end=ended,
            attacker_ips=plan.attacker_ips,
            victim_ips=plan.victim_ips,
            victim_assets=plan.victim_assets,
            techniques=scenario.techniques,
            params=merged,
            evidence_dir=run_dir.as_posix(),
            notes=f"status={status}" + (f"; error={error}" if error else ""),
        )
        manifest = {
            "run_id": run_id,
            "scenario_id": scenario.scenario_id,
            "title": scenario.title,
            "status": status,
            "dry_run": dry_run,
            "start_utc": utc_iso(started),
            "end_utc": utc_iso(ended),
            "params": merged,
            "plan": {
                "attacker_ips": list(plan.attacker_ips),
                "victim_ips": list(plan.victim_ips),
                "victim_assets": list(plan.victim_assets),
            },
            "techniques": list(scenario.techniques),
            "expected_indicators": list(scenario.expected_indicators),
            "actions": ctx.actions,
            "error": error,
            "git_commit": git_commit(),
            "contract_version": CONTRACT_VERSION,
        }
        run_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = run_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if not dry_run:
            append_run(ground_truth_csv, run)
        result = RunResult(run=run, manifest_path=manifest_path, status=status, dry_run=dry_run)
    return result

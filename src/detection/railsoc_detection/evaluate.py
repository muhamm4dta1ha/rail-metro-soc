"""Detection evaluation (task M3-10): compare alerts with the ground-truth runs.

Works for any alert source - a Wazuh alerts.json export or ML alert events - so rules and ML are
scored the same way. Metrics: detected?, time-to-detect, false alarms (and per hour).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from railsoc_common.events import as_utc
from railsoc_common.groundtruth import AttackRun


@dataclass(frozen=True)
class Alert:
    ts: datetime
    source: str  # e.g. "wazuh:100101" or "ml:isolation_forest"
    level: int = 0
    src_ip: str | None = None


@dataclass(frozen=True)
class RunDetection:
    run_id: str
    scenario_id: str
    detected: bool
    time_to_detect_s: float | None
    n_alerts: int


@dataclass(frozen=True)
class Evaluation:
    runs: tuple[RunDetection, ...]
    false_alarms: int
    observed_hours: float | None = None

    @property
    def detection_rate(self) -> float | None:
        return sum(r.detected for r in self.runs) / len(self.runs) if self.runs else None

    @property
    def false_alarms_per_hour(self) -> float | None:
        return self.false_alarms / self.observed_hours if self.observed_hours else None


def _parse_wazuh_ts(value: str) -> datetime:
    """Wazuh writes e.g. 2026-11-05T09:14:03.120+0000 (offset without a colon)."""
    return as_utc(re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value))


def alerts_from_wazuh(path: str | Path) -> list[Alert]:
    """Parse a Wazuh alerts.json export (one JSON object per line)."""
    alerts: list[Alert] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        rule = obj.get("rule", {})
        data = obj.get("data") or {}
        source = data.get("source")
        src_ip = source.get("ip") if isinstance(source, dict) else data.get("srcip")
        alerts.append(
            Alert(
                ts=_parse_wazuh_ts(obj["timestamp"]),
                source=f"wazuh:{rule.get('id', '?')}",
                level=int(rule.get("level", 0)),
                src_ip=src_ip,
            )
        )
    return alerts


def alerts_from_events(path: str | Path) -> list[Alert]:
    """Parse ML alert events (dataset ml.alert) from a JSON Lines file."""
    alerts: list[Alert] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("event", {}).get("dataset") != "ml.alert":
            continue
        alerts.append(
            Alert(
                ts=as_utc(event["@timestamp"]),
                source=f"ml:{event.get('ml', {}).get('model', '?')}",
                level=0,
                src_ip=event.get("source", {}).get("ip"),
            )
        )
    return alerts


def evaluate(
    alerts: Iterable[Alert],
    runs: Iterable[AttackRun],
    *,
    grace_s: float = 30.0,
    observed_hours: float | None = None,
    min_level: int = 0,
) -> Evaluation:
    """Per attack run: detected? time-to-detect? Plus alerts outside every attack window."""
    attack_runs = [run for run in runs if run.scenario_id != "BASELINE"]
    grace = timedelta(seconds=grace_s)
    usable = [alert for alert in alerts if alert.level >= min_level]

    results: list[RunDetection] = []
    for run in attack_runs:
        hits = sorted(
            (a for a in usable if run.start <= a.ts <= run.end + grace), key=lambda a: a.ts
        )
        ttd = (hits[0].ts - run.start).total_seconds() if hits else None
        results.append(RunDetection(run.run_id, run.scenario_id, bool(hits), ttd, len(hits)))

    false_alarms = sum(
        1 for a in usable if not any(r.start <= a.ts <= r.end + grace for r in attack_runs)
    )
    return Evaluation(tuple(results), false_alarms, observed_hours)


def format_markdown(evaluation: Evaluation) -> str:
    """Render the result as a Markdown table for the report."""
    lines = [
        "| run | scenario | detected | time to detect (s) | alerts |",
        "|---|---|---|---|---|",
    ]
    for r in evaluation.runs:
        ttd = "-" if r.time_to_detect_s is None else f"{r.time_to_detect_s:.1f}"
        lines.append(
            f"| {r.run_id} | {r.scenario_id} | {'yes' if r.detected else 'NO'} | {ttd} | {r.n_alerts} |"
        )
    rate = evaluation.detection_rate
    fa_per_hour = evaluation.false_alarms_per_hour
    lines.append("")
    lines.append(f"Detection rate: {'n/a' if rate is None else f'{rate:.0%}'}")
    lines.append(f"False alarms: {evaluation.false_alarms}")
    if fa_per_hour is not None:
        lines.append(f"False alarms per hour: {fa_per_hour:.2f}")
    return "\n".join(lines)

"""Ground-truth contract: attack runs (written by Module 2) and event labelling (used by M3/M4).

Labels live ONLY here and in the ground-truth CSV - never inside events (HC-19).
Labelling rule (see docs/contracts/ground_truth.md):

* ``attack``        event inside a run window whose source/destination IP is an attacker IP;
* ``attack_impact`` event inside a run window that involves a victim IP/asset but no attacker IP;
* ``benign``        everything else (BASELINE runs are always benign).
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, NamedTuple

from railsoc_common.events import as_utc, utc_iso
from railsoc_common.ids import is_run_id
from railsoc_common.lab import in_lab

CSV_FIELDS = [
    "run_id",
    "scenario_id",
    "variant",
    "start_utc",
    "end_utc",
    "attacker_ips",
    "victim_ips",
    "victim_assets",
    "techniques",
    "params_json",
    "evidence_dir",
    "notes",
]
SCENARIOS = ("A", "B", "C", "BASELINE")
BENIGN = "benign"
ATTACK = "attack"
ATTACK_IMPACT = "attack_impact"


class Label(NamedTuple):
    label: str
    run_id: str | None
    scenario_id: str | None


def _split(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(";") if part.strip())


@dataclass(frozen=True)
class AttackRun:
    """One scripted run (attack or normal BASELINE window) inside the isolated lab."""

    run_id: str
    scenario_id: str
    start: datetime
    end: datetime
    attacker_ips: tuple[str, ...] = ()
    victim_ips: tuple[str, ...] = ()
    victim_assets: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    variant: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    evidence_dir: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "start", as_utc(self.start))
        object.__setattr__(self, "end", as_utc(self.end))
        for name in ("attacker_ips", "victim_ips", "victim_assets", "techniques"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        if not is_run_id(self.run_id):
            raise ValueError(f"invalid run id {self.run_id!r}")
        if self.scenario_id not in SCENARIOS:
            raise ValueError(f"scenario_id must be one of {SCENARIOS}, got {self.scenario_id!r}")
        if self.end <= self.start:
            raise ValueError("end must be after start")
        for ip in (*self.attacker_ips, *self.victim_ips):
            if not in_lab(ip):
                raise ValueError(f"{ip} is outside the lab address space (HC-18)")
        if self.scenario_id == "BASELINE" and self.attacker_ips:
            raise ValueError("BASELINE runs have no attacker")

    def to_row(self) -> dict[str, str]:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "variant": self.variant,
            "start_utc": utc_iso(self.start),
            "end_utc": utc_iso(self.end),
            "attacker_ips": ";".join(self.attacker_ips),
            "victim_ips": ";".join(self.victim_ips),
            "victim_assets": ";".join(self.victim_assets),
            "techniques": ";".join(self.techniques),
            "params_json": json.dumps(self.params, sort_keys=True),
            "evidence_dir": self.evidence_dir,
            "notes": self.notes,
        }

    @classmethod
    def from_row(cls, row: dict[str, str]) -> AttackRun:
        return cls(
            run_id=row["run_id"],
            scenario_id=row["scenario_id"],
            variant=row.get("variant", ""),
            start=as_utc(row["start_utc"]),
            end=as_utc(row["end_utc"]),
            attacker_ips=_split(row.get("attacker_ips", "")),
            victim_ips=_split(row.get("victim_ips", "")),
            victim_assets=_split(row.get("victim_assets", "")),
            techniques=_split(row.get("techniques", "")),
            params=json.loads(row.get("params_json") or "{}"),
            evidence_dir=row.get("evidence_dir", ""),
            notes=row.get("notes", ""),
        )


def load_runs(path: str | Path) -> list[AttackRun]:
    """Read lab/ground_truth/attack_runs.csv (missing file = no runs)."""
    source = Path(path)
    if not source.exists():
        return []
    with source.open(newline="", encoding="utf-8") as fh:
        return [AttackRun.from_row(row) for row in csv.DictReader(fh)]


def write_runs(path: str | Path, runs: Iterable[AttackRun]) -> None:
    """(Over)write the CSV with a header and the given runs."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        for run in runs:
            writer.writerow(run.to_row())


def append_run(path: str | Path, run: AttackRun) -> None:
    """Append one run, writing the header first if the file is new or empty."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    new_file = not target.exists() or target.stat().st_size == 0
    with target.open("a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, lineterminator="\n")
        if new_file:
            writer.writeheader()
        writer.writerow(run.to_row())


def label_event(event: dict[str, Any], runs: Iterable[AttackRun]) -> Label:
    """Label one event against the ground-truth runs (see module docstring for the rule)."""
    ts = as_utc(event["@timestamp"])
    src = event.get("source", {}).get("ip")
    dst = event.get("destination", {}).get("ip")
    asset = event.get("asset", {}).get("id")
    impact: Label | None = None
    for run in runs:
        if run.scenario_id == "BASELINE" or not (run.start <= ts <= run.end):
            continue
        if (src and src in run.attacker_ips) or (dst and dst in run.attacker_ips):
            return Label(ATTACK, run.run_id, run.scenario_id)
        involves_victim = (
            (src and src in run.victim_ips)
            or (dst and dst in run.victim_ips)
            or (asset and asset in run.victim_assets)
        )
        if impact is None and involves_victim:
            impact = Label(ATTACK_IMPACT, run.run_id, run.scenario_id)
    return impact or Label(BENIGN, None, None)

"""Run identifiers: RUN-<scenario>-<UTC timestamp>-<seq>, e.g. RUN-A-20261105T091403Z-01."""

from __future__ import annotations

import re
from datetime import UTC, datetime

SCENARIO_IDS = ("A", "B", "C", "BASELINE")
RUN_ID_RE = re.compile(r"^RUN-(A|B|C|BASELINE)-\d{8}T\d{6}Z-\d{2}$")


def new_run_id(scenario_id: str, now: datetime | None = None, seq: int = 1) -> str:
    """Build a run id. `now` defaults to the current UTC time (naive datetimes count as UTC)."""
    if scenario_id not in SCENARIO_IDS:
        raise ValueError(f"unknown scenario id {scenario_id!r}; expected one of {SCENARIO_IDS}")
    if not 0 <= seq <= 99:
        raise ValueError("seq must be between 0 and 99")
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    stamp = moment.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"RUN-{scenario_id}-{stamp}-{seq:02d}"


def is_run_id(value: str) -> bool:
    return bool(RUN_ID_RE.match(value))

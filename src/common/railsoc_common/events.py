"""Event contract: build, validate and (de)serialise schema-conformant events.

Rules (hard constraint HC-19):
* every event produced by any module validates against ``schemas/event.schema.json``;
* ground-truth labels never appear inside events (see ``FORBIDDEN_KEYS``);
* all timestamps are UTC, ISO-8601 with milliseconds and a trailing ``Z``.

``host.name`` is the machine that *produced* the log line; ``asset`` is the asset the event is
*about* (the target/subject), e.g. the controller that was polled.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "event.schema.json"

# Keys that would leak ground truth into the data seen by detectors / ML (HC-19).
FORBIDDEN_KEYS = frozenset(
    {
        "label",
        "labels",
        "is_attack",
        "attack",
        "attack_run",
        "scenario",
        "scenario_id",
        "run_id",
        "ground_truth",
    }
)

# Optional top-level dict groups an event may carry (order = output order).
GROUPS = (
    "host",
    "asset",
    "source",
    "destination",
    "network",
    "user",
    "http",
    "url",
    "modbus",
    "mqtt",
    "metric",
    "ml",
)


class EventValidationError(ValueError):
    """Raised when an event breaks the contract."""


def parse_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp (``Z`` or an offset) into an aware UTC datetime."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def as_utc(ts: datetime | str | None = None) -> datetime:
    """Normalise None (= now), a string or a datetime to an aware UTC datetime.

    Naive datetimes are assumed to already be UTC.
    """
    if ts is None:
        return datetime.now(UTC)
    if isinstance(ts, str):
        return parse_ts(ts)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC)


def utc_iso(ts: datetime | str | None = None) -> str:
    """Format as ``YYYY-MM-DDTHH:MM:SS.mmmZ`` (the only timestamp format of the contract)."""
    return as_utc(ts).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _drop_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _drop_none(v) for k, v in value.items() if v is not None}
    return value


def make_event(
    dataset: str,
    category: str,
    action: str,
    outcome: str = "unknown",
    *,
    ts: datetime | str | None = None,
    message: str | None = None,
    tags: list[str] | None = None,
    validate: bool = True,
    **groups: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a contract event. ``groups`` are the optional dict groups listed in ``GROUPS``."""
    unknown = sorted(set(groups) - set(GROUPS))
    if unknown:
        raise EventValidationError(f"unknown event group(s): {unknown}")
    event: dict[str, Any] = {
        "@timestamp": utc_iso(ts),
        "event": {"dataset": dataset, "category": category, "action": action, "outcome": outcome},
    }
    for name in GROUPS:
        value = groups.get(name)
        if value:
            event[name] = _drop_none(value)
    if message is not None:
        event["message"] = message
    if tags:
        event["tags"] = list(tags)
    if validate:
        validate_event(event)
    return event


@lru_cache(maxsize=1)
def _validator() -> Any:
    # Imported lazily so lightweight containers can run with validate=False and no jsonschema.
    from jsonschema import Draft202012Validator, FormatChecker

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _find_forbidden(obj: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in FORBIDDEN_KEYS:
                found.add(key)
            found |= _find_forbidden(value)
    elif isinstance(obj, list):
        for item in obj:
            found |= _find_forbidden(item)
    return found


def validate_event(event: dict[str, Any]) -> None:
    """Raise EventValidationError if ``event`` breaks the contract (schema or label leakage)."""
    errors: list[str] = []
    leaked = sorted(_find_forbidden(event))
    if leaked:
        errors.append(f"forbidden label-like key(s) {leaked} (labels never go into events)")
    found = sorted(_validator().iter_errors(event), key=lambda e: [str(p) for p in e.absolute_path])
    for err in found:
        where = ".".join(str(p) for p in err.absolute_path) or "<root>"
        errors.append(f"{where}: {err.message}")
    if errors:
        raise EventValidationError("; ".join(errors))


def dumps(event: dict[str, Any]) -> str:
    """Compact one-line JSON (the on-disk / on-the-wire form: JSON Lines)."""
    return json.dumps(event, separators=(",", ":"), ensure_ascii=False)


def write_events(path: str | Path, events: Iterable[dict[str, Any]]) -> int:
    """Write events as JSON Lines (UTF-8, LF). Returns the number of events written."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with target.open("w", encoding="utf-8", newline="\n") as fh:
        for event in events:
            fh.write(dumps(event) + "\n")
            count += 1
    return count


def read_events(path: str | Path, *, validate: bool = False) -> Iterator[dict[str, Any]]:
    """Yield events from a JSON Lines file, optionally validating each one."""
    with Path(path).open(encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            event = json.loads(line)
            if validate:
                try:
                    validate_event(event)
                except EventValidationError as exc:
                    raise EventValidationError(f"{path}:{line_no}: {exc}") from exc
            yield event

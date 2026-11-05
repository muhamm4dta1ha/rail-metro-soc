import json
from datetime import UTC, datetime

import pytest

from railsoc_common.events import (
    SCHEMA_PATH,
    EventValidationError,
    make_event,
    parse_ts,
    read_events,
    utc_iso,
    validate_event,
    write_events,
)
from railsoc_common.lab import ZONES

TS = datetime(2026, 1, 5, 8, 0, 0, tzinfo=UTC)


def login_failure(**overrides):
    fields = {
        "ts": TS,
        "host": {"name": "pis-01"},
        "source": {"ip": "10.60.10.21", "port": 40000},
        "destination": {"ip": "10.60.20.10", "port": 8080},
        "user": {"name": "ops_admin"},
    }
    fields.update(overrides)
    return make_event("pis.app", "authentication", "login", "failure", **fields)


def test_make_event_builds_a_valid_event():
    event = login_failure(message="login failed")
    assert event["@timestamp"] == "2026-01-05T08:00:00.000Z"
    assert event["event"] == {
        "dataset": "pis.app",
        "category": "authentication",
        "action": "login",
        "outcome": "failure",
    }
    validate_event(event)


def test_timestamps_are_utc_with_millis():
    assert utc_iso(datetime(2026, 1, 1, 0, 0, 0)) == "2026-01-01T00:00:00.000Z"  # naive == UTC
    assert utc_iso("2026-01-01T02:00:00+02:00") == "2026-01-01T00:00:00.000Z"
    assert parse_ts("2026-01-01T00:00:00.5Z") == datetime(2026, 1, 1, 0, 0, 0, 500000, tzinfo=UTC)


def test_invalid_category_is_rejected():
    with pytest.raises(EventValidationError):
        make_event("pis.app", "not_a_category", "login", host={"name": "x"})


def test_host_is_required():
    with pytest.raises(EventValidationError, match="host"):
        make_event("pis.app", "authentication", "login")


def test_bad_ip_is_rejected():
    with pytest.raises(EventValidationError):
        login_failure(source={"ip": "999.1.1.1"})


def test_unknown_group_is_rejected():
    with pytest.raises(EventValidationError, match="unknown event group"):
        make_event("pis.app", "authentication", "login", host={"name": "x"}, label={"x": 1})


def test_ground_truth_labels_can_never_leak_into_events():
    event = login_failure()
    event["event"]["label"] = "attack"
    with pytest.raises(EventValidationError, match="forbidden"):
        validate_event(event)

    event = login_failure()
    event["run_id"] = "RUN-A-20260105T080000Z-01"
    with pytest.raises(EventValidationError, match="forbidden"):
        validate_event(event)


def test_schema_zone_enum_matches_the_lab_zones():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert set(schema["properties"]["asset"]["properties"]["zone"]["enum"]) == set(ZONES)


def test_jsonl_roundtrip(tmp_path):
    events = [login_failure(), login_failure(ts=datetime(2026, 1, 5, 8, 0, 1, tzinfo=UTC))]
    path = tmp_path / "out" / "events.jsonl"
    assert write_events(path, events) == 2
    assert list(read_events(path, validate=True)) == events

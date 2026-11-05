from datetime import UTC, datetime

import pytest

from railsoc_common.events import validate_event
from railsoc_common.lab import in_lab
from railsoc_sim.assets import load_assets
from railsoc_sim.generator import generate_normal_events
from railsoc_sim.profiles import Profile, Schedule, load_schedule

START = datetime(2026, 1, 5, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def events():
    # 00:00-03:00 covers off-peak and the night-maintenance window (01:00-04:00).
    return generate_normal_events(START, hours=3, seed=7)


def test_events_are_schema_valid_and_sorted(events):
    for event in events:
        validate_event(event)
    stamps = [e["@timestamp"] for e in events]
    assert stamps == sorted(stamps)
    assert stamps[0] >= "2026-01-05T00:00:00.000Z"
    assert stamps[-1] < "2026-01-05T03:00:01.000Z"


def test_same_seed_gives_same_events_and_other_seed_differs():
    first = generate_normal_events(START, 1, seed=3)
    assert first == generate_normal_events(START, 1, seed=3)
    assert first != generate_normal_events(START, 1, seed=4)


def test_every_address_comes_from_the_asset_inventory(events):
    known = {a.ip for a in load_assets()}
    for event in events:
        for group in ("source", "destination"):
            ip = event.get(group, {}).get("ip")
            if ip:
                assert ip in known and in_lab(ip)


def test_expected_datasets_are_present(events):
    datasets = {e["event"]["dataset"] for e in events}
    assert {"scada.poll", "scada.command", "pis.app", "auth.ssh"} <= datasets


def test_maintenance_writes_only_come_from_the_engineering_workstation(events):
    writes = [e for e in events if e["event"]["dataset"] == "scada.command"]
    assert writes
    assert {w["source"]["ip"] for w in writes} == {"10.60.10.23"}
    assert {w["modbus"]["function_code"] for w in writes} == {6}


def test_benign_login_failures_exist_when_the_typo_rate_is_high():
    busy = Profile(
        name="busy",
        telemetry_poll_s=60,
        pis_requests_per_min=0,
        admin_logins_per_hour=1800,
        typo_failure_rate=0.5,
        maintenance_writes_per_hour=0,
        ssh_sessions_per_hour=0,
    )
    schedule = Schedule(default="busy", windows=(), profiles={"busy": busy})
    logins = [
        e
        for e in generate_normal_events(START, 1, seed=1, schedule=schedule)
        if e["event"]["action"] == "login"
    ]
    assert {e["event"]["outcome"] for e in logins} == {"success", "failure"}


def test_schedule_picks_the_right_profile():
    schedule = load_schedule()
    assert schedule.profile_at(datetime(2026, 1, 5, 8, 0, tzinfo=UTC)).name == "peak"
    assert schedule.profile_at(datetime(2026, 1, 5, 2, 0, tzinfo=UTC)).name == "night_maintenance"
    assert schedule.profile_at(datetime(2026, 1, 5, 12, 0, tzinfo=UTC)).name == "offpeak"


def test_hours_must_be_positive():
    with pytest.raises(ValueError):
        generate_normal_events(START, 0)

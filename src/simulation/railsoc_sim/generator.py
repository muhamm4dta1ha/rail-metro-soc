"""Deterministic generator of synthetic NORMAL traffic/log events for the simulated railway.

This is the starter version (Module 1 extends it in M1-08). It gives Modules 2-4 realistic,
schema-valid data from day one, including benign look-alikes (typo logins, authorised
maintenance writes) so that detectors cannot rely on "any failure / any write = attack".
Same seed + same inputs = same events.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Any

from railsoc_common.events import as_utc, make_event
from railsoc_sim.assets import Asset, by_type, first_of_type, load_assets
from railsoc_sim.profiles import Schedule, load_schedule
from railsoc_sim.protocol_map import METRICS, MODBUS_PORT, SETPOINT_REGISTER

USERS = (("ops_admin", "admin"), ("ops_lead", "admin"), ("eng_maint", "engineer"))
PIS_PORT = 8080


def _asset(asset: Asset) -> dict[str, str]:
    return {"id": asset.asset_id, "zone": asset.zone, "type": asset.type}


def _ephemeral_port(rng: random.Random) -> int:
    return rng.randint(32768, 60999)


def _poll_event(ts, occ: Asset, ctl: Asset, unit_id: int, metric, rng: random.Random) -> dict:
    name, unit, nominal, spread, address = metric
    value = round(nominal + rng.uniform(-spread, spread), 2)
    return make_event(
        "scada.poll",
        "telemetry",
        "poll",
        "success",
        ts=ts,
        host={"name": occ.hostname},
        asset=_asset(ctl),
        source={"ip": occ.ip, "port": _ephemeral_port(rng)},
        destination={"ip": ctl.ip, "port": MODBUS_PORT},
        network={"protocol": "modbus", "transport": "tcp"},
        modbus={"function_code": 3, "unit_id": unit_id, "address": address},
        metric={"name": name, "value": value, "unit": unit},
        message=f"read {name} from {ctl.asset_id}",
        validate=False,
    )


def _maintenance_write_event(ts, eng: Asset, ctl: Asset, unit_id: int, rng: random.Random) -> dict:
    return make_event(
        "scada.command",
        "configuration",
        "write_register",
        "success",
        ts=ts,
        host={"name": ctl.hostname},
        asset=_asset(ctl),
        source={"ip": eng.ip, "port": _ephemeral_port(rng)},
        destination={"ip": ctl.ip, "port": MODBUS_PORT},
        network={"protocol": "modbus", "transport": "tcp"},
        user={"name": "eng_maint", "role": "engineer"},
        modbus={"function_code": 6, "unit_id": unit_id, "address": SETPOINT_REGISTER},
        message=f"write single register on {ctl.asset_id}",
        validate=False,
    )


def _login_event(ts, pis: Asset, client: Asset, user: str, role: str, ok: bool, rng) -> dict:
    return make_event(
        "pis.app",
        "authentication",
        "login",
        "success" if ok else "failure",
        ts=ts,
        host={"name": pis.hostname},
        asset=_asset(pis),
        source={"ip": client.ip, "port": _ephemeral_port(rng)},
        destination={"ip": pis.ip, "port": PIS_PORT},
        network={"protocol": "http", "transport": "tcp"},
        user={"name": user, "role": role},
        http={"request": {"method": "POST"}, "response": {"status_code": 200 if ok else 401}},
        url={"path": "/api/login"},
        message=f"login {'succeeded' if ok else 'failed'} for {user}",
        validate=False,
    )


def _request_event(ts, pis: Asset, client: Asset, rng: random.Random) -> dict:
    server_error = rng.random() < 0.002  # rare benign 5xx so "5xx = attack" is not learnable
    status = 500 if server_error else 200
    latency = rng.uniform(150, 900) if server_error else rng.uniform(4, 40)
    return make_event(
        "pis.app",
        "web",
        "request",
        "failure" if server_error else "success",
        ts=ts,
        host={"name": pis.hostname},
        asset=_asset(pis),
        source={"ip": client.ip, "port": _ephemeral_port(rng)},
        destination={"ip": pis.ip, "port": PIS_PORT},
        network={"protocol": "http", "transport": "tcp"},
        http={
            "request": {"method": "GET"},
            "response": {"status_code": status, "latency_ms": round(latency, 1)},
        },
        url={"path": "/api/arrivals"},
        message="GET /api/arrivals",
        validate=False,
    )


def _ssh_event(ts, jump: Asset, client: Asset, rng: random.Random) -> dict:
    return make_event(
        "auth.ssh",
        "authentication",
        "login",
        "success",
        ts=ts,
        host={"name": jump.hostname},
        asset=_asset(jump),
        source={"ip": client.ip, "port": _ephemeral_port(rng)},
        destination={"ip": jump.ip, "port": 22},
        network={"protocol": "ssh", "transport": "tcp"},
        user={"name": "eng_maint", "role": "engineer"},
        message="accepted publickey for eng_maint",
        validate=False,
    )


def _arrivals(
    rng: random.Random, start: datetime, end: datetime, schedule: Schedule, rate_per_s
) -> Iterator[datetime]:
    """Poisson arrivals whose rate follows the schedule (rate_per_s: Profile -> events/second)."""
    t = start
    while t < end:
        rate = rate_per_s(schedule.profile_at(t))
        if rate <= 0:
            t += timedelta(minutes=1)
            continue
        t += timedelta(seconds=rng.expovariate(rate))
        if t < end:
            yield t


def generate_normal_events(
    start: datetime | str,
    hours: float,
    seed: int = 1,
    assets: list[Asset] | None = None,
    schedule: Schedule | None = None,
) -> list[dict[str, Any]]:
    """Return NORMAL events for [start, start + hours), sorted by timestamp."""
    if hours <= 0:
        raise ValueError("hours must be > 0")
    rng = random.Random(seed)
    assets = assets if assets is not None else load_assets()
    schedule = schedule or load_schedule()
    begin = as_utc(start)
    end = begin + timedelta(hours=hours)

    occ = first_of_type(assets, "scada_master")
    pis = first_of_type(assets, "pis_server")
    jump = first_of_type(assets, "jump_host")
    controllers = by_type(assets, "station_controller")
    displays = by_type(assets, "station_display")
    workstations = by_type(assets, "workstation")
    engineering = next((a for a in workstations if "ssh" in a.protocols), workstations[0])
    web_clients = displays + workstations

    events: list[dict[str, Any]] = []

    # 1) SCADA polling: fixed interval per controller, every register of the synthetic map.
    for unit_id, ctl in enumerate(controllers, start=1):
        t = begin + timedelta(seconds=rng.uniform(0, 5))
        while t < end:
            for i, metric in enumerate(METRICS):
                events.append(_poll_event(t + timedelta(milliseconds=50 * i), occ, ctl, unit_id, metric, rng))
            t += timedelta(seconds=schedule.profile_at(t).telemetry_poll_s)

    # 2) Passenger-information web traffic.
    for t in _arrivals(rng, begin, end, schedule, lambda p: p.pis_requests_per_min / 60):
        events.append(_request_event(t, pis, rng.choice(web_clients), rng))

    # 3) Admin logins, with benign typo failures.
    for t in _arrivals(rng, begin, end, schedule, lambda p: p.admin_logins_per_hour / 3600):
        user, role = rng.choice(USERS)
        ok = rng.random() >= schedule.profile_at(t).typo_failure_rate
        events.append(_login_event(t, pis, rng.choice(workstations), user, role, ok, rng))

    # 4) Authorised maintenance writes from the engineering workstation (benign look-alike).
    for t in _arrivals(rng, begin, end, schedule, lambda p: p.maintenance_writes_per_hour / 3600):
        unit_id = rng.randrange(len(controllers))
        events.append(_maintenance_write_event(t, engineering, controllers[unit_id], unit_id + 1, rng))

    # 5) Maintenance SSH sessions to the jump host.
    for t in _arrivals(rng, begin, end, schedule, lambda p: p.ssh_sessions_per_hour / 3600):
        events.append(_ssh_event(t, jump, engineering, rng))

    events.sort(key=lambda e: e["@timestamp"])
    return events

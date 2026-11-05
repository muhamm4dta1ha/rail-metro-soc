"""Shared test data: quiet normal traffic plus four attack bursts with matching ground-truth runs.

pytest runs with --import-mode=importlib, so test modules cannot `import conftest`;
everything they need is exposed through the `h` and `stream` fixtures.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from railsoc_common.events import make_event
from railsoc_common.groundtruth import AttackRun
from railsoc_common.ids import new_run_id

T0 = datetime(2026, 1, 5, 9, 0, 0, tzinfo=UTC)
NORMAL_SOURCES = ("10.60.10.21", "10.60.10.22", "10.60.30.21")
ATTACKER = "10.60.66.10"
VICTIM = "10.60.20.10"
BURST_OFFSETS_S = (200, 500, 800, 1000)  # multiples of the 10 s window: one window per burst


def request(ts, src, status=200):
    ok = status < 400
    return make_event(
        "pis.app",
        "web",
        "request",
        "success" if ok else "failure",
        ts=ts,
        host={"name": "pis-01"},
        source={"ip": src},
        destination={"ip": VICTIM, "port": 8080},
        network={"protocol": "http", "transport": "tcp"},
        http={"request": {"method": "GET"}, "response": {"status_code": status}},
        url={"path": "/api/arrivals"},
    )


def login(ts, src, ok):
    return make_event(
        "pis.app",
        "authentication",
        "login",
        "success" if ok else "failure",
        ts=ts,
        host={"name": "pis-01"},
        source={"ip": src},
        destination={"ip": VICTIM, "port": 8080},
        network={"protocol": "http", "transport": "tcp"},
        user={"name": "ops_admin"},
        http={"request": {"method": "POST"}, "response": {"status_code": 200 if ok else 401}},
        url={"path": "/api/login"},
    )


def normal_events(minutes=20):
    """Regular traffic: every source requests every 3 s; every 20th request of one source is a typo login."""
    events = []
    for i in range(minutes * 20):
        base = T0 + timedelta(seconds=3 * i)
        for n, src in enumerate(NORMAL_SOURCES):
            moment = base + timedelta(milliseconds=100 * n)
            if i % 20 == 7 and n == 0:
                events.append(login(moment, src, ok=False))  # benign look-alike
            else:
                events.append(request(moment, src))
    return events


def attack_burst(offset_s):
    """60 failed logins from the attacker inside 6 seconds."""
    start = T0 + timedelta(seconds=offset_s)
    return [login(start + timedelta(milliseconds=100 * i), ATTACKER, ok=False) for i in range(60)]


def attack_run(offset_s, seq):
    start = T0 + timedelta(seconds=offset_s)
    return AttackRun(
        run_id=new_run_id("A", start, seq),
        scenario_id="A",
        start=start,
        end=start + timedelta(seconds=10),
        attacker_ips=(ATTACKER,),
        victim_ips=(VICTIM,),
        victim_assets=("PIS-01",),
        techniques=("T1110",),
    )


@pytest.fixture(scope="session")
def h():
    """Constants and event builders for the tests."""
    return SimpleNamespace(T0=T0, ATTACKER=ATTACKER, VICTIM=VICTIM, login=login, request=request)


@pytest.fixture(scope="session")
def stream():
    """(events, runs): 20 minutes of normal traffic with four attack bursts."""
    events = normal_events()
    runs = []
    for seq, offset in enumerate(BURST_OFFSETS_S, start=1):
        events += attack_burst(offset)
        runs.append(attack_run(offset, seq))
    events.sort(key=lambda e: e["@timestamp"])
    return events, runs

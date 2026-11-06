"""HC-23: the HTTP driver must make real requests against a real server, not fabricate events."""

import random
import threading
from http.server import ThreadingHTTPServer

import pytest

from railsoc_common.events import validate_event
from railsoc_sim import pis_stub
from railsoc_sim.drivers import http_driver


def test_parse_users():
    assert http_driver.parse_users("a:1, b:2 ,broken, :nopass") == [("a", "1"), ("b", "2")]


def test_run_rejects_empty_user_list():
    with pytest.raises(ValueError, match="username, password"):
        http_driver.run("http://127.0.0.1:1", [], duration_s=1)


@pytest.fixture()
def real_server(monkeypatch):
    """A real pis_stub HTTP server on a random localhost port."""
    events: list[dict] = []
    monkeypatch.setattr(pis_stub.Handler, "_emit", lambda self, event: events.append(event))
    monkeypatch.setattr(pis_stub.Handler, "users", {"ops_admin": "s3cret"})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), pis_stub.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", events
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def test_driver_makes_real_requests_the_server_actually_logs(real_server):
    base_url, events = real_server
    count = http_driver.run(
        base_url,
        [("ops_admin", "s3cret")],
        duration_s=1.0,
        min_delay_s=0.05,
        max_delay_s=0.1,
        typo_rate=0.0,
        rng=random.Random(1),
    )
    assert count > 0
    # Every request the driver made really reached the server and the server really logged it:
    # no event the driver itself invented, and no request that silently went nowhere.
    assert len(events) == count
    for event in events:
        validate_event(event)
    # A real login with the right password really succeeds against the real server.
    logins = [e for e in events if e["event"]["action"] == "login"]
    assert logins and all(e["event"]["outcome"] == "success" for e in logins)


def test_typo_rate_produces_real_failed_logins(real_server):
    base_url, events = real_server
    http_driver.run(
        base_url,
        [("ops_admin", "s3cret")],
        duration_s=1.0,
        min_delay_s=0.01,
        max_delay_s=0.02,
        typo_rate=1.0,  # every login attempt uses a deliberately wrong password
        rng=random.Random(1),
    )
    logins = [e for e in events if e["event"]["action"] == "login"]
    assert logins and all(e["event"]["outcome"] == "failure" for e in logins)

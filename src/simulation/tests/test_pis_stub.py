import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from railsoc_common.events import validate_event
from railsoc_sim import pis_stub


def test_parse_users_and_check_login():
    users = pis_stub.parse_users("ops_admin:s3cret, ops_lead:other ,broken, :nopass")
    assert users == {"ops_admin": "s3cret", "ops_lead": "other"}
    assert pis_stub.check_login(users, "ops_admin", "s3cret")
    assert not pis_stub.check_login(users, "ops_admin", "wrong")
    assert not pis_stub.check_login(users, "nobody", "x")
    assert pis_stub.parse_users("") == {}


def test_events_follow_the_contract():
    failure = pis_stub.login_event("ops_admin", False, "10.60.66.10", 40000, validate=True)
    assert failure["event"]["outcome"] == "failure"
    assert failure["http"]["response"]["status_code"] == 401
    pis_stub.request_event("GET", "/api/arrivals", 200, "10.60.30.21", validate=True)
    long_name = pis_stub.login_event("x" * 500, True, "10.60.10.21", validate=True)
    assert len(long_name["user"]["name"]) == pis_stub.MAX_FIELD


@pytest.fixture()
def server(monkeypatch):
    events: list[dict] = []
    monkeypatch.setattr(pis_stub.Handler, "_emit", lambda self, event: events.append(event))
    monkeypatch.setattr(pis_stub.Handler, "users", {"ops_admin": "s3cret"})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), pis_stub.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1], events
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def _request(port, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def test_login_endpoint_answers_200_or_401_and_logs_contract_events(server):
    port, events = server
    assert _request(port, "/api/login", {"username": "ops_admin", "password": "s3cret"}) == 200
    assert _request(port, "/api/login", {"username": "ops_admin", "password": "nope"}) == 401
    assert [e["event"]["outcome"] for e in events] == ["success", "failure"]
    for event in events:
        validate_event(event)


def test_health_is_silent_and_unknown_paths_are_logged(server):
    port, events = server
    assert _request(port, "/health") == 200
    assert events == []
    assert _request(port, "/api/arrivals") == 200
    assert _request(port, "/nope") == 404
    assert [e["http"]["response"]["status_code"] for e in events] == [200, 404]

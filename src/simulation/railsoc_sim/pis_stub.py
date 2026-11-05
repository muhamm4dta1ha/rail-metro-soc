"""Passenger Information System (PIS) stub - LAB ONLY, synthetic accounts.

Endpoints
  GET  /health        liveness probe (not logged)
  GET  /api/arrivals  synthetic arrival board (JSON)
  POST /api/login     JSON {"username": ..., "password": ...} -> 200 / 401

Every request is logged to stdout as ONE schema event per line (contract v0.1); that is what the
SIEM agent and the ML pipeline consume. Accounts come from the PIS_USERS environment variable
("user:password,user2:password2"). Never commit real credentials.
Module 1 extends this stub (M1-04): config-change and user-create audit events, MQTT feed, portal.
"""

from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from railsoc_common.events import dumps, make_event

HOST_NAME = "pis-01"
ASSET = {"id": "PIS-01", "zone": "dmz_ops", "type": "pis_server"}
SERVER_IP = "10.60.20.10"
PORT = 8080
MAX_BODY = 4096
MAX_FIELD = 64


def parse_users(raw: str) -> dict[str, str]:
    """Parse "user:password,user2:password2" (empty string = no accounts)."""
    users: dict[str, str] = {}
    for item in raw.split(","):
        name, sep, password = item.strip().partition(":")
        if sep and name.strip():
            users[name.strip()] = password
    return users


def check_login(users: dict[str, str], username: str, password: str) -> bool:
    expected = users.get(username)
    if expected is None:
        hmac.compare_digest(password.encode(), b"x")  # keep timing similar for unknown users
        return False
    return hmac.compare_digest(password.encode(), expected.encode())


def login_event(
    username: str,
    success: bool,
    client_ip: str,
    client_port: int | None = None,
    *,
    ts=None,
    validate: bool = False,
) -> dict[str, Any]:
    return make_event(
        "pis.app",
        "authentication",
        "login",
        "success" if success else "failure",
        ts=ts,
        host={"name": HOST_NAME},
        asset=ASSET,
        source={"ip": client_ip, "port": client_port},
        destination={"ip": SERVER_IP, "port": PORT},
        network={"protocol": "http", "transport": "tcp"},
        user={"name": username[:MAX_FIELD]},
        http={"request": {"method": "POST"}, "response": {"status_code": 200 if success else 401}},
        url={"path": "/api/login"},
        message=f"login {'succeeded' if success else 'failed'} for {username[:MAX_FIELD]}",
        validate=validate,
    )


def request_event(
    method: str,
    path: str,
    status: int,
    client_ip: str,
    client_port: int | None = None,
    *,
    ts=None,
    validate: bool = False,
) -> dict[str, Any]:
    return make_event(
        "pis.app",
        "web",
        "request",
        "success" if status < 400 else "failure",
        ts=ts,
        host={"name": HOST_NAME},
        asset=ASSET,
        source={"ip": client_ip, "port": client_port},
        destination={"ip": SERVER_IP, "port": PORT},
        network={"protocol": "http", "transport": "tcp"},
        http={"request": {"method": method}, "response": {"status_code": status}},
        url={"path": path[:200]},
        message=f"{method} {path[:200]}",
        validate=validate,
    )


class Handler(BaseHTTPRequestHandler):
    users: dict[str, str] = {}
    server_version = "PISStub/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the default access log; schema events are emitted instead."""

    def _emit(self, event: dict[str, Any]) -> None:
        print(dumps(event), flush=True)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        ip, port = self.client_address[:2]
        path = self.path.split("?")[0]
        if path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        if path == "/api/arrivals":
            status, payload = 200, {"station": "ST01", "arrivals": [{"line": "L1", "in_min": 3}]}
        else:
            status, payload = 404, {"error": "not found"}
        # Log first, respond second: the event is on disk before the client can react to it.
        self._emit(request_event("GET", path, status, ip, port))
        self._send_json(status, payload)

    def do_POST(self) -> None:
        ip, port = self.client_address[:2]
        path = self.path.split("?")[0]
        if path != "/api/login":
            self._emit(request_event("POST", path, 404, ip, port))
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0")), MAX_BODY)
            payload = json.loads(self.rfile.read(length) or b"{}")
            username = str(payload.get("username", ""))
            password = str(payload.get("password", ""))
        except (ValueError, AttributeError):
            self._emit(request_event("POST", path, 400, ip, port))
            self._send_json(400, {"error": "bad request"})
            return
        ok = check_login(self.users, username, password)
        self._emit(login_event(username, ok, ip, port))
        self._send_json(200 if ok else 401, {"ok": ok})


def main() -> None:
    Handler.users = parse_users(os.environ.get("PIS_USERS", ""))
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()

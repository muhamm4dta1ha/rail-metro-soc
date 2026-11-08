"""Small guarded transports. No redirects, proxies, retries or unbounded concurrency."""

from __future__ import annotations

import http.client
import json
import math
import time

from railsoc_attacks.scenario import RunContext
from railsoc_common.events import make_event, validate_event


def positive(value, name):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise ValueError(f"{name} must be finite and positive")
    return number


def validate_params(params, targets):
    """Reject unsupported assets and credential-bearing parameters before recording."""
    from railsoc_attacks.safety import LabScope

    LabScope().assert_target_allowed(params["attacker_ip"])
    for ip in targets:
        LabScope().assert_target_allowed(ip)
    for key in ("rate_per_s", "duration_s"):
        positive(params[key], key)
    for key in params:
        if any(word in key.lower() for word in ("password", "secret", "token", "credential")):
            raise ValueError("Secrets belong in environment variables, never run parameters")
    if not isinstance(params.get("baseline", False), bool):
        raise ValueError("baseline must be a boolean")
    if params.get("baseline") and params["attacker_ip"] != "10.60.20.20":
        raise ValueError("Baseline must use the approved OCC source 10.60.20.20")
    count = params.get("request_count", 6)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 1000:
        raise ValueError("request_count must be an integer in 1..1000")


class Budget:
    """One total deadline and minimum spacing, including baseline/recovery phases."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.duration = positive(ctx.scope.clamp_duration(ctx.params["duration_s"]), "duration_s")
        self.rate = positive(ctx.scope.clamp_rate(ctx.params["rate_per_s"]), "rate_per_s")
        self.started = time.monotonic()
        self.deadline = self.started + self.duration
        self.next_at = self.started

    def remaining(self):
        return max(0.0, self.deadline - time.monotonic())

    def finish(self, ip):
        """Keep comparison windows equal in duration, without generating extra traffic."""
        while self.remaining():
            self.ctx.guard(ip)
            time.sleep(min(0.05, self.remaining()))

    def slot(self, ip, rate=None, until=None):
        rate = min(self.rate, positive(rate or self.rate, "rate_per_s"))
        end = min(self.deadline, until if until is not None else self.deadline)
        while True:
            self.ctx.guard(ip)
            now = time.monotonic()
            remaining = end - now
            if remaining <= 0:
                return False
            delay = self.next_at - now
            if delay <= 0:
                break
            time.sleep(min(0.05, delay, remaining))
        self.ctx.guard(ip)
        if time.monotonic() >= end:
            return False
        self.next_at = time.monotonic() + 1 / rate
        return True


def emit(ctx, *, target, port, protocol, category, action, outcome, elapsed, **groups):
    event = make_event(
        "scada.poll" if protocol == "modbus" else "pis.client",
        category, action, outcome,
        host={"name": "lab-client"}, source={"ip": ctx.params["attacker_ip"]},
        destination={"ip": target, "port": port},
        network={"protocol": protocol, "transport": "tcp"}, **groups,
    )
    event["event"]["duration_ms"] = elapsed * 1000
    validate_event(event)
    ctx.events.append(event)


def http_request(ctx: RunContext, budget: Budget, path, payload=None):
    """Bind the real source IP; an unavailable source fails instead of inventing attribution."""
    ip = ctx.params["target_ip"]
    method = "POST" if payload is not None else "GET"
    ctx.guard(ip)
    connection = http.client.HTTPConnection(
        ip, 8080, timeout=min(1.0, budget.remaining()),
        source_address=(ctx.params["attacker_ip"], 0),
    )
    started = time.monotonic()
    status = None
    failure = None
    try:
        ctx.guard(ip)
        connection.connect()
        ctx.guard(ip)
        if not budget.remaining():
            raise TimeoutError()
        connection.sock.settimeout(min(1.0, budget.remaining()))
        connection.request(method, path, body=json.dumps(payload) if payload else None,
                           headers={"Content-Type": "application/json"})
        connection.sock.settimeout(max(0.001, min(1.0, budget.remaining())))
        response = connection.getresponse()
        status = response.status
    except (OSError, http.client.HTTPException) as exc:
        # Never include exception text: libraries can echo request bodies/secrets.
        failure = type(exc).__name__
    finally:
        connection.close()
    elapsed = time.monotonic() - started
    response_fields = {"latency_ms": elapsed * 1000}
    if status is not None:
        response_fields["status_code"] = status
    emit(ctx, target=ip, port=8080, protocol="http",
         category="authentication" if payload else "web", action="login" if payload else "request",
         outcome="success" if status == 200 else "failure", elapsed=elapsed,
         http={"request": {"method": method}, "response": response_fields},
         url={"path": path}, message="client observation" if not failure else failure)
    return {"status": status, "latency_ms": elapsed * 1000, "error": failure}


def modbus_read(ctx, budget, address):
    from pymodbus.client import ModbusTcpClient
    from pymodbus.exceptions import ModbusException

    ip = ctx.params["target_ips"][0]
    ctx.guard(ip)
    client = ModbusTcpClient(ip, port=502, source_address=(ctx.params["attacker_ip"], 0),
                            timeout=min(1.0, budget.remaining()), retries=0)
    started = time.monotonic()
    ok = False
    try:
        ctx.guard(ip)
        if client.connect():
            ctx.guard(ip)
            if budget.remaining():
                client.socket.settimeout(min(1.0, budget.remaining()))
                reply = client.read_holding_registers(address, count=1, device_id=1)
                ok = not reply.isError()
    except (OSError, ModbusException):
        pass
    finally:
        client.close()
    elapsed = time.monotonic() - started
    emit(ctx, target=ip, port=502, protocol="modbus", category="telemetry", action="poll",
         outcome="success" if ok else "failure", elapsed=elapsed,
         modbus={"function_code": 3, "unit_id": 1, "address": address})
    return {"success": ok, "latency_ms": elapsed * 1000}

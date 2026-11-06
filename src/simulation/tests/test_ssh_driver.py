"""HC-23: the SSH driver must really authenticate (or really fail to) against a real sshd."""

import json
import random
import socket
import threading

import paramiko
import pytest

from railsoc_common.events import validate_event
from railsoc_sim.assets import Asset
from railsoc_sim.drivers import ssh_driver

CLIENT = Asset("OCC-01", "occ-scada-01", "dmz_ops", "scada_master", "10.60.20.20", ("ssh",))
JUMPHOST = Asset("JH-01", "jumphost-01", "dmz_ops", "jump_host", "127.0.0.1", ("ssh",))
USERNAME = "eng_maint"
PASSWORD = "lab-only-test-pass"  # synthetic, used only inside this test's in-process server


class _AcceptOneUser(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        if username == USERNAME and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED


@pytest.fixture(scope="module")
def host_key():
    return paramiko.RSAKey.generate(2048)


@pytest.fixture()
def real_sshd(host_key):
    """A real, minimal sshd (paramiko server side) on a random localhost port."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    listener.settimeout(1.0)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                client_sock, _ = listener.accept()
            except TimeoutError:
                continue
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(host_key)
            try:
                transport.start_server(server=_AcceptOneUser())
                # start_server() only kicks off negotiation on the transport's own thread; give
                # it a window to actually finish kex + auth before this loop tears it down (the
                # client never opens a channel, so there is nothing else to wait on here).
                transport.accept(5)
            except paramiko.SSHException:
                pass
            finally:
                transport.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield "127.0.0.1", port
    stop.set()
    thread.join(timeout=5)
    listener.close()


def test_connect_once_really_authenticates_with_the_right_password(real_sshd):
    host, port = real_sshd
    events: list[str] = []
    out = type("W", (), {"write": lambda self, s: events.append(s), "flush": lambda self: None})()
    ok = ssh_driver.connect_once(host, port, USERNAME, PASSWORD, CLIENT, JUMPHOST, random.Random(1), out)
    assert ok
    event = json.loads(events[0])
    validate_event(event)
    assert event["event"]["dataset"] == "auth.ssh"
    assert event["event"]["outcome"] == "success"


def test_connect_once_really_fails_with_the_wrong_password(real_sshd):
    host, port = real_sshd
    events: list[str] = []
    out = type("W", (), {"write": lambda self, s: events.append(s), "flush": lambda self: None})()
    ok = ssh_driver.connect_once(host, port, USERNAME, "wrong-password", CLIENT, JUMPHOST, random.Random(1), out)
    assert not ok
    event = json.loads(events[0])
    validate_event(event)
    assert event["event"]["outcome"] == "failure"


def test_run_makes_real_attempts_for_the_whole_duration(real_sshd):
    host, port = real_sshd
    events: list[str] = []
    out = type("W", (), {"write": lambda self, s: events.append(s), "flush": lambda self: None})()
    count = ssh_driver.run(
        host,
        port,
        USERNAME,
        PASSWORD,
        CLIENT,
        JUMPHOST,
        duration_s=1.2,
        interval_s=0.3,
        typo_rate=0.0,
        out=out,
        rng=random.Random(2),
    )
    assert count > 0
    assert len(events) == count
    assert all(json.loads(line)["event"]["outcome"] == "success" for line in events)

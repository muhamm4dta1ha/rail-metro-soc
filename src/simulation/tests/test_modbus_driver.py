"""HC-23: the Modbus driver must read/write real registers over a real Modbus/TCP connection.

Uses a plain real pymodbus TCP server as the "PLC" - a real server of the real protocol, just
not the third-party OpenPLC image the live lab run targets (see plan/DAY1_PLAN.md).
"""

import json
import random
import socket
import threading
import time

import pytest
from pymodbus.client import ModbusTcpClient
from pymodbus.server import ServerStop, StartTcpServer
from pymodbus.simulator import DataType, SimData, SimDevice

from railsoc_common.events import validate_event
from railsoc_sim.assets import Asset
from railsoc_sim.drivers import modbus_driver
from railsoc_sim.protocol_map import ALL_POINTS, SETPOINT_REGISTER, encode_register

POLLER = Asset("OCC-01", "occ-scada-01", "dmz_ops", "scada_master", "10.60.20.20", ("modbus",))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def real_plc():
    """A real pymodbus TCP server holding every monitoring point plus the setpoint."""
    port = _free_port()
    controller = Asset("PLC-01", "station-plc", "dmz_ops", "station_controller", "127.0.0.1", ("modbus",))
    sim_values = [
        SimData(address=address, count=1, values=encode_register(name, nominal), datatype=DataType.REGISTERS)
        for name, _unit, nominal, _spread, address in ALL_POINTS
    ] + [SimData(address=SETPOINT_REGISTER, count=1, values=0, datatype=DataType.REGISTERS)]
    device = SimDevice(id=1, simdata=sim_values)
    thread = threading.Thread(
        target=StartTcpServer, args=(device,), kwargs={"address": ("127.0.0.1", port)}, daemon=True
    )
    thread.start()
    time.sleep(0.5)  # the asyncio server needs a moment to start listening
    yield "127.0.0.1", port, controller
    ServerStop()
    thread.join(timeout=5)


def test_poll_once_reads_real_registers_and_logs_matching_events(real_plc):
    host, port, controller = real_plc
    client = ModbusTcpClient(host, port=port)
    assert client.connect()
    events: list[str] = []
    out = type("W", (), {"write": lambda self, s: events.append(s), "flush": lambda self: None})()
    try:
        ok = modbus_driver.poll_once(client, 1, POLLER, controller, random.Random(1), out, controller_port=port)
    finally:
        client.close()
    assert ok
    assert len(events) == len(ALL_POINTS)
    parsed = [json.loads(line) for line in events]
    for event in parsed:
        validate_event(event)
        assert event["event"]["dataset"] == "scada.poll"
        assert event["event"]["outcome"] == "success"
        assert event["modbus"]["function_code"] == 3
    temp = next(e for e in parsed if e["metric"]["name"] == "station_temp_c")
    assert temp["metric"]["value"] == pytest.approx(22.0)


def test_maintenance_write_once_really_changes_the_register(real_plc):
    host, port, controller = real_plc
    client = ModbusTcpClient(host, port=port)
    assert client.connect()
    events: list[str] = []
    out = type("W", (), {"write": lambda self, s: events.append(s), "flush": lambda self: None})()
    expected_value = random.Random(1).randint(0, 100)  # maintenance_write_once's first draw
    try:
        ok = modbus_driver.maintenance_write_once(
            client, 1, POLLER, controller, random.Random(1), out, controller_port=port
        )
        readback = client.read_holding_registers(address=SETPOINT_REGISTER, count=1, device_id=1)
    finally:
        client.close()
    assert ok
    event = json.loads(events[0])
    validate_event(event)
    assert event["event"]["dataset"] == "scada.command"
    assert event["modbus"]["function_code"] == 6
    # the write really landed on the real server - not just claimed in the log
    assert readback.registers[0] == expected_value


def test_run_polls_and_writes_for_real_over_the_duration(real_plc):
    host, port, controller = real_plc
    events: list[str] = []
    out = type("W", (), {"write": lambda self, s: events.append(s), "flush": lambda self: None})()
    calls = modbus_driver.run(
        host,
        port,
        1,
        POLLER,
        controller,
        duration_s=1.2,
        poll_interval_s=0.3,
        maintenance_write_every_s=0.5,
        out=out,
        rng=random.Random(2),
    )
    assert calls > 0
    assert len(events) == calls


def test_run_raises_if_the_real_connection_cannot_be_made():
    controller = Asset("PLC-01", "station-plc", "dmz_ops", "station_controller", "127.0.0.1", ("modbus",))
    unused_port = _free_port()
    with pytest.raises(ConnectionError):
        modbus_driver.run(
            "127.0.0.1", unused_port, 1, POLLER, controller, duration_s=1.0, poll_interval_s=0.1
        )

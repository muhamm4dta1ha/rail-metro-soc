"""Real Modbus/TCP PLC stand-in (HC-23 fallback) - a plain pymodbus server, not OpenPLC.

OpenPLC (a real, independently-developed PLC runtime) was today's first choice for extra
authenticity, but building it from source took too long for a one-day lab - see
docs/architecture/architecture.md. This is the documented fallback. Every byte on the wire is
still completely real: a genuine pymodbus TCP server, genuine function code 3 (read) and 6
(write) handling - just code this project wrote instead of independent PLC software.

Models a small metro line's non-safety OT points (HC-22, amended 2026-11-06 - see
plan/PLAN.md): traction power (two feeder breakers), ventilation/HVAC (two zones), and
track-circuit occupancy for a mimic panel's train icon. Two background threads play the role of
"the PLC's own sensor input": real Modbus/TCP write calls to itself (loopback, a second real
client) - one drifts the analog points the way real sensors would, the other moves exactly one
track circuit's occupied flag at a time, the way a train would. The maintenance setpoint
register (address 10) is never touched by either thread - only an external client
(railsoc_sim.drivers.modbus_driver) may write it.

  python -m railsoc_sim.services.station_plc --port 502
"""

from __future__ import annotations

import argparse
import logging
import random
import threading

from pymodbus.client import ModbusTcpClient
from pymodbus.server import StartTcpServer
from pymodbus.simulator import DataType, SimData, SimDevice

from railsoc_sim.protocol_map import (
    ALL_POINTS,
    SETPOINT_REGISTER,
    STATE_POINT_NAMES,
    TRACK_CIRCUITS,
    encode_register,
)

LOGGER = logging.getLogger("railsoc_sim.services.station_plc")
UNIT_ID = 1


def build_device() -> SimDevice:
    """One contiguous holding-register block - a real Modbus client reads nearby registers in a
    single batched request (FUXA's own driver buckets reads in groups of 100), and a device with
    gaps in its register map (rather than reserved-but-unused registers) would reject that read
    with "illegal data address" the moment it touches one undefined register."""
    span = max(SETPOINT_REGISTER + 1, 100)
    values = [0] * span
    for name, _unit, nominal, _spread, address in ALL_POINTS:
        values[address] = encode_register(name, nominal)
    # The train starts at Station A's platform (the first track circuit), not nowhere.
    first_tc_name, _unit, _nom, _spread, first_tc_address = TRACK_CIRCUITS[0]
    values[first_tc_address] = encode_register(first_tc_name, 1.0)
    sim_data = SimData(address=0, count=span, values=values, datatype=DataType.REGISTERS)
    return SimDevice(id=UNIT_ID, simdata=[sim_data])


def _write_point(client: ModbusTcpClient, name: str, address: int, value: float) -> None:
    try:
        response = client.write_register(
            address=address, value=encode_register(name, value), device_id=UNIT_ID
        )
        if response.isError():
            LOGGER.warning("sensor-input write to %s failed: %s", name, response)
    except OSError as exc:
        LOGGER.warning("sensor-input write to %s failed: %s", name, exc)
        client.close()


def drift_forever(port: int, interval_s: float, stop: threading.Event, rng: random.Random) -> None:
    """The PLC's own sensor-input loop: real loopback Modbus writes to every analog point, never
    the setpoint register and never a boolean state point (those are driven elsewhere)."""
    client = ModbusTcpClient("127.0.0.1", port=port)
    while not stop.wait(interval_s):
        if not client.connected and not client.connect():
            continue
        for name, _unit, nominal, spread, address in ALL_POINTS:
            if name in STATE_POINT_NAMES:
                continue
            value = nominal + rng.uniform(-spread, spread)
            _write_point(client, name, address, value)
    client.close()


def train_forever(port: int, move_interval_s: float, dwell_interval_s: float, stop: threading.Event) -> None:
    """Moves exactly one track-circuit's occupied flag at a time, shuttling the "train" back and
    forth between Station A (the first circuit) and Station B (the last) - illustrative only,
    for the mimic panel (HC-22 amendment); this never computes or enforces anything safety-related.
    """
    client = ModbusTcpClient("127.0.0.1", port=port)
    last_index = len(TRACK_CIRCUITS) - 1
    forward = list(range(len(TRACK_CIRCUITS)))
    sequence = forward + forward[-2:0:-1]  # 0..last, then last-1..1, then back to 0 - no repeats
    position = 0
    while not stop.wait(dwell_interval_s if sequence[position] in (0, last_index) else move_interval_s):
        if not client.connected and not client.connect():
            continue
        position = (position + 1) % len(sequence)
        occupied_index = sequence[position]
        for i, (name, _unit, _nom, _spread, address) in enumerate(TRACK_CIRCUITS):
            _write_point(client, name, address, 1.0 if i == occupied_index else 0.0)
    client.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--drift-interval", type=float, default=5.0, help="seconds")
    parser.add_argument("--train-move-interval", type=float, default=4.0, help="seconds between track circuits")
    parser.add_argument("--train-dwell-interval", type=float, default=10.0, help="seconds parked at a station")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    stop = threading.Event()
    threads = [
        threading.Thread(
            target=drift_forever,
            args=(args.port, args.drift_interval, stop, random.Random(args.seed)),
            daemon=True,
        ),
        threading.Thread(
            target=train_forever,
            args=(args.port, args.train_move_interval, args.train_dwell_interval, stop),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    LOGGER.info("real Modbus/TCP PLC stand-in listening on 0.0.0.0:%d", args.port)
    try:
        StartTcpServer(build_device(), address=("0.0.0.0", args.port))
    finally:
        stop.set()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

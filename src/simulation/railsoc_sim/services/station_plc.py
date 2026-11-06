"""Real Modbus/TCP PLC stand-in (HC-23 fallback) - a plain pymodbus server, not OpenPLC.

OpenPLC (a real, independently-developed PLC runtime) was today's first choice for extra
authenticity, but building it from source took too long for a one-day lab - see
docs/architecture/architecture.md. This is the documented fallback. Every byte on the wire is
still completely real: a genuine pymodbus TCP server, genuine function code 3 (read) and 6
(write) handling - just code this project wrote instead of independent PLC software.

A background thread plays the role of "the PLC's own sensor input": it makes real Modbus/TCP
write calls to itself (loopback, a second real client) every few seconds, to drift the four
telemetry registers the way a real PLC updates its own holding registers from physical sensors.
The maintenance setpoint register (address 10) is never touched by this thread - only an
external client (railsoc_sim.drivers.modbus_driver) may write it.

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

from railsoc_sim.protocol_map import METRICS, SETPOINT_REGISTER, encode_register

LOGGER = logging.getLogger("railsoc_sim.services.station_plc")
UNIT_ID = 1


def build_device() -> SimDevice:
    """One contiguous holding-register block - a real Modbus client reads nearby registers in a
    single batched request (FUXA's own driver buckets reads in groups of 100), and a device with
    gaps in its register map (rather than reserved-but-unused registers) would reject that read
    with "illegal data address" the moment it touches one undefined register."""
    span = max(SETPOINT_REGISTER + 1, 100)
    values = [0] * span
    for name, _unit, nominal, _spread, address in METRICS:
        values[address] = encode_register(name, nominal)
    sim_data = SimData(address=0, count=span, values=values, datatype=DataType.REGISTERS)
    return SimDevice(id=UNIT_ID, simdata=[sim_data])


def drift_forever(port: int, interval_s: float, stop: threading.Event, rng: random.Random) -> None:
    """The PLC's own sensor-input loop: real loopback Modbus writes, never the setpoint register."""
    client = ModbusTcpClient("127.0.0.1", port=port)
    while not stop.wait(interval_s):
        if not client.connected and not client.connect():
            continue
        for name, _unit, nominal, spread, address in METRICS:
            if name == "lift_available":
                continue  # a boolean status, not a drifting measurement
            value = nominal + rng.uniform(-spread, spread)
            try:
                response = client.write_register(
                    address=address, value=encode_register(name, value), device_id=UNIT_ID
                )
                if response.isError():
                    LOGGER.warning("sensor-input write to %s failed: %s", name, response)
            except OSError as exc:
                LOGGER.warning("sensor-input write to %s failed: %s", name, exc)
                client.close()
    client.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--drift-interval", type=float, default=5.0, help="seconds")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    stop = threading.Event()
    drift = threading.Thread(
        target=drift_forever,
        args=(args.port, args.drift_interval, stop, random.Random(args.seed)),
        daemon=True,
    )
    drift.start()
    LOGGER.info("real Modbus/TCP PLC stand-in listening on 0.0.0.0:%d", args.port)
    try:
        StartTcpServer(build_device(), address=("0.0.0.0", args.port))
    finally:
        stop.set()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

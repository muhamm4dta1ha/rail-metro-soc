"""Real Modbus/TCP driver (HC-23): genuine ``pymodbus`` reads/writes against a real PLC.

The PLC (OpenPLC in the lab; a plain pymodbus test server in unit tests) is real, unmodified
third-party software and does not speak our event schema, so this driver - the component that
actually made the call - writes the matching ``scada.poll`` / ``scada.command`` event right
after each real call returns. Never before, never independent of it.

  python -m railsoc_sim.drivers.modbus_driver --host 10.60.20.22 --port 502 --unit-id 1 \\
      --poller-asset-id OCC-01 --controller-asset-id PLC-01 --duration 1800 \\
      --out /lab/data/raw/modbus_live.jsonl
"""

from __future__ import annotations

import argparse
import logging
import random
import time
from pathlib import Path
from typing import IO, Any

from pymodbus.client import ModbusTcpClient

from railsoc_common.events import dumps, make_event
from railsoc_sim.assets import Asset, load_assets
from railsoc_sim.protocol_map import ALL_POINTS, MODBUS_PORT, SETPOINT_REGISTER, decode_register

LOGGER = logging.getLogger("railsoc_sim.drivers.modbus_driver")


def _ephemeral_port(rng: random.Random) -> int:
    return rng.randint(32768, 60999)


def _asset_fields(asset: Asset) -> dict[str, str]:
    return {"id": asset.asset_id, "zone": asset.zone, "type": asset.type}


def _emit(event: dict[str, Any], out: IO[str] | None) -> None:
    line = dumps(event)
    if out is None:
        print(line, flush=True)
    else:
        out.write(line + "\n")
        out.flush()


def poll_once(
    client: ModbusTcpClient,
    unit_id: int,
    poller: Asset,
    controller: Asset,
    rng: random.Random,
    out: IO[str] | None,
    *,
    controller_port: int = 502,
) -> bool:
    """Read every monitoring point once, for real. Returns True iff every read succeeded."""
    ok_all = True
    for name, unit, _nominal, _spread, address in ALL_POINTS:
        response = client.read_holding_registers(address=address, count=1, device_id=unit_id)
        failed = response.isError()
        ok_all = ok_all and not failed
        value = None if failed else decode_register(name, response.registers[0])
        event = make_event(
            "scada.poll",
            "telemetry",
            "poll",
            "failure" if failed else "success",
            host={"name": poller.hostname},
            asset=_asset_fields(controller),
            source={"ip": poller.ip, "port": _ephemeral_port(rng)},
            destination={"ip": controller.ip, "port": controller_port},
            network={"protocol": "modbus", "transport": "tcp"},
            modbus={"function_code": 3, "unit_id": unit_id, "address": address},
            metric=None if value is None else {"name": name, "value": value, "unit": unit},
            message=f"read {name} from {controller.asset_id}" + (" (failed)" if failed else ""),
        )
        _emit(event, out)
    return ok_all


def maintenance_write_once(
    client: ModbusTcpClient,
    unit_id: int,
    writer: Asset,
    controller: Asset,
    rng: random.Random,
    out: IO[str] | None,
    *,
    controller_port: int = 502,
) -> bool:
    """Write a real value to the setpoint register (an "authorised maintenance" look-alike)."""
    raw_value = rng.randint(0, 100)
    response = client.write_register(address=SETPOINT_REGISTER, value=raw_value, device_id=unit_id)
    failed = response.isError()
    event = make_event(
        "scada.command",
        "configuration",
        "write_register",
        "failure" if failed else "success",
        host={"name": writer.hostname},
        asset=_asset_fields(controller),
        source={"ip": writer.ip, "port": _ephemeral_port(rng)},
        destination={"ip": controller.ip, "port": controller_port},
        network={"protocol": "modbus", "transport": "tcp"},
        user={"name": "eng_maint", "role": "engineer"},
        modbus={"function_code": 6, "unit_id": unit_id, "address": SETPOINT_REGISTER},
        message=f"write single register on {controller.asset_id}" + (" (failed)" if failed else ""),
    )
    _emit(event, out)
    return not failed


def run(
    host: str,
    port: int,
    unit_id: int,
    poller: Asset,
    controller: Asset,
    *,
    duration_s: float,
    poll_interval_s: float = 10.0,
    maintenance_write_every_s: float = 120.0,
    writer: Asset | None = None,
    out: IO[str] | None = None,
    rng: random.Random | None = None,
    sleep=time.sleep,
    now=time.monotonic,
) -> int:
    """Poll (and occasionally write to) a real Modbus/TCP server for ``duration_s`` seconds.

    Returns the number of real Modbus calls made (reads + writes).
    """
    rng = rng or random.Random()
    writer = writer or poller
    client = ModbusTcpClient(host, port=port)
    if not client.connect():
        raise ConnectionError(f"could not open a real Modbus/TCP connection to {host}:{port}")
    try:
        deadline = now() + duration_s
        next_write = now() + maintenance_write_every_s
        calls = 0
        while now() < deadline:
            poll_once(client, unit_id, poller, controller, rng, out, controller_port=port)
            calls += len(ALL_POINTS)
            if now() >= next_write:
                maintenance_write_once(
                    client, unit_id, writer, controller, rng, out, controller_port=port
                )
                calls += 1
                next_write = now() + maintenance_write_every_s
            sleep(poll_interval_s)
        return calls
    finally:
        client.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--unit-id", type=int, default=1)
    parser.add_argument("--poller-asset-id", default="OCC-01")
    parser.add_argument("--controller-asset-id", default="PLC-01")
    parser.add_argument("--writer-asset-id", default=None, help="defaults to --poller-asset-id")
    parser.add_argument("--duration", type=float, default=1800.0, help="seconds")
    parser.add_argument("--poll-interval", type=float, default=10.0, help="seconds")
    parser.add_argument("--maintenance-write-every", type=float, default=120.0, help="seconds")
    parser.add_argument("--out", default=None, help="JSONL path; stdout if omitted")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    assets = {a.asset_id: a for a in load_assets()}
    poller = assets[args.poller_asset_id]
    controller = assets[args.controller_asset_id]
    writer = assets[args.writer_asset_id] if args.writer_asset_id else poller
    host = args.host or controller.ip
    port = args.port or MODBUS_PORT

    out_fh: IO[str] | None = None
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        out_fh = path.open("a", encoding="utf-8", newline="\n")
    try:
        calls = run(
            host,
            port,
            args.unit_id,
            poller,
            controller,
            duration_s=args.duration,
            poll_interval_s=args.poll_interval,
            maintenance_write_every_s=args.maintenance_write_every,
            writer=writer,
            out=out_fh,
            rng=random.Random(args.seed),
        )
    finally:
        if out_fh is not None:
            out_fh.close()
    LOGGER.info("done: %d real Modbus calls", calls)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Start the three real-protocol drivers together for one normal-traffic window (HC-23).

One command gives Furqan/Roshni/Anum a single block of real HTTP + Modbus/TCP + SSH traffic and
the matching JSONL logs, instead of three drivers started by hand in three terminals.

  python -m railsoc_sim.scripts.run_normal_day --duration 1800 --out-dir /lab/data/raw
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

LOGGER = logging.getLogger("railsoc_sim.scripts.run_normal_day")

# (label, module, extra argv)
_DRIVERS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("http", "railsoc_sim.drivers.http_driver", ()),
    ("modbus", "railsoc_sim.drivers.modbus_driver", ()),
    ("ssh", "railsoc_sim.drivers.ssh_driver", ()),
)


def build_argv(label: str, module: str, args: argparse.Namespace, out_dir: Path) -> list[str]:
    out_path = out_dir / f"{label}_live.jsonl"
    argv = [sys.executable, "-m", module, "--duration", str(args.duration)]
    if label == "http":
        # http_driver logs nothing itself - pis_stub (the real server) already does, so it has
        # no --out of its own.
        argv += ["--base-url", args.pis_base_url, "--users", args.pis_users]
    elif label == "modbus":
        argv += ["--out", str(out_path)]
        argv += [
            "--host",
            args.modbus_host,
            "--port",
            str(args.modbus_port),
            "--unit-id",
            str(args.modbus_unit_id),
        ]
    elif label == "ssh":
        argv += ["--out", str(out_path)]
        argv += [
            "--host",
            args.ssh_host,
            "--port",
            str(args.ssh_port),
            "--username",
            args.ssh_username,
        ]
    return argv


def run(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    procs: dict[str, subprocess.Popen] = {}
    for label, module, _extra in _DRIVERS:
        argv = build_argv(label, module, args, out_dir)
        LOGGER.info("starting %s driver: %s", label, " ".join(argv))
        procs[label] = subprocess.Popen(argv)  # noqa: S603 - fixed, internal module names

    deadline = time.monotonic() + args.duration + args.grace
    failures = 0
    while procs and time.monotonic() < deadline:
        for label in list(procs):
            proc = procs[label]
            code = proc.poll()
            if code is not None:
                del procs[label]
                if code != 0:
                    failures += 1
                    LOGGER.warning("%s driver exited with code %s", label, code)
                else:
                    LOGGER.info("%s driver finished", label)
        if procs:
            time.sleep(1.0)

    for label, proc in procs.items():
        LOGGER.warning("%s driver did not finish in time, terminating", label)
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        failures += 1

    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=1800.0, help="seconds, shared by all three")
    parser.add_argument("--grace", type=float, default=60.0, help="extra seconds before giving up")
    parser.add_argument("--out-dir", default="lab/data/raw")
    parser.add_argument("--pis-base-url", default="http://pis:8080")
    parser.add_argument(
        "--pis-users",
        default=os.environ.get(
            "PIS_USERS", "ops_admin:change-me-lab-only,ops_lead:change-me-too-lab-only"
        ),
        help="defaults to $PIS_USERS so this container logs in with the same accounts pis has",
    )
    parser.add_argument("--modbus-host", default="station-plc")
    parser.add_argument("--modbus-port", type=int, default=502)
    parser.add_argument("--modbus-unit-id", type=int, default=1)
    parser.add_argument("--ssh-host", default="jumphost")
    parser.add_argument(
        "--ssh-port", type=int, default=2222, help="linuxserver/openssh-server listens on 2222"
    )
    parser.add_argument("--ssh-username", default="eng_maint")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())

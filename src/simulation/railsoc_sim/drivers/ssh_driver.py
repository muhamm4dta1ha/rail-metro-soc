"""Real SSH driver (HC-23): genuine ``paramiko`` connections against a real ``sshd``.

The jump host is a plain, unmodified ``openssh-server`` and does not speak our event schema, so
this driver - the component that actually attempted the connection - logs the matching
``auth.ssh`` event right after each real connect attempt, from the driver's own connect result.

Host keys are auto-accepted (``AutoAddPolicy``): acceptable for a synthetic, isolated lab network
that is never exposed outside it (HC-18), not for anything real.

  JUMPHOST_PASSWORD=change-me-lab-only python -m railsoc_sim.drivers.ssh_driver \\
      --host 10.60.20.30 --username eng_maint --client-asset-id OCC-01 \\
      --jumphost-asset-id JH-01 --duration 1800
"""

from __future__ import annotations

import argparse
import logging
import os
import random
import time
from pathlib import Path
from typing import IO, Any

import paramiko

from railsoc_common.events import dumps, make_event
from railsoc_sim.assets import Asset, load_assets

LOGGER = logging.getLogger("railsoc_sim.drivers.ssh_driver")


def _ephemeral_port(rng: random.Random) -> int:
    return rng.randint(32768, 60999)


def _emit(event: dict[str, Any], out: IO[str] | None) -> None:
    line = dumps(event)
    if out is None:
        print(line, flush=True)
    else:
        out.write(line + "\n")
        out.flush()


def connect_once(
    host: str,
    port: int,
    username: str,
    password: str,
    client: Asset,
    jumphost: Asset,
    rng: random.Random,
    out: IO[str] | None,
    *,
    timeout: float = 5.0,
) -> bool:
    """Make one real SSH connection attempt. Returns True iff it really authenticated."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    success = False
    try:
        ssh.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        success = True
    except paramiko.AuthenticationException:
        success = False
    except (paramiko.SSHException, OSError) as exc:
        LOGGER.warning("ssh connect error: %s", exc)
        success = False
    finally:
        ssh.close()
    event = make_event(
        "auth.ssh",
        "authentication",
        "login",
        "success" if success else "failure",
        host={"name": jumphost.hostname},
        asset={"id": jumphost.asset_id, "zone": jumphost.zone, "type": jumphost.type},
        source={"ip": client.ip, "port": _ephemeral_port(rng)},
        destination={"ip": jumphost.ip, "port": port},
        network={"protocol": "ssh", "transport": "tcp"},
        user={"name": username, "role": "engineer"},
        message=f"{'accepted' if success else 'failed'} password for {username}",
    )
    _emit(event, out)
    return success


def run(
    host: str,
    port: int,
    username: str,
    password: str,
    client: Asset,
    jumphost: Asset,
    *,
    duration_s: float,
    interval_s: float = 30.0,
    typo_rate: float = 0.1,
    out: IO[str] | None = None,
    rng: random.Random | None = None,
    sleep=time.sleep,
    now=time.monotonic,
) -> int:
    """Connect for real, on an interval, for ``duration_s`` seconds. Returns attempts made."""
    rng = rng or random.Random()
    deadline = now() + duration_s
    count = 0
    while now() < deadline:
        attempt_password = password + "x" if rng.random() < typo_rate else password
        connect_once(host, port, username, attempt_password, client, jumphost, rng, out)
        count += 1
        sleep(interval_s)
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--username", default="eng_maint")
    parser.add_argument(
        "--password-env",
        default="JUMPHOST_PASSWORD",
        help="env var holding the real (lab-only, synthetic) password",
    )
    parser.add_argument("--client-asset-id", default="OCC-01")
    parser.add_argument("--jumphost-asset-id", default="JH-01")
    parser.add_argument("--duration", type=float, default=1800.0, help="seconds")
    parser.add_argument("--interval", type=float, default=30.0, help="seconds")
    parser.add_argument("--typo-rate", type=float, default=0.1)
    parser.add_argument("--out", default=None, help="JSONL path; stdout if omitted")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    password = os.environ.get(args.password_env)
    if not password:
        parser.error(f"${args.password_env} is not set (lab-only synthetic password)")
    assets = {a.asset_id: a for a in load_assets()}
    client = assets[args.client_asset_id]
    jumphost = assets[args.jumphost_asset_id]
    host = args.host or jumphost.ip

    out_fh: IO[str] | None = None
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        out_fh = path.open("a", encoding="utf-8", newline="\n")
    try:
        count = run(
            host,
            args.port,
            args.username,
            password,
            client,
            jumphost,
            duration_s=args.duration,
            interval_s=args.interval,
            typo_rate=args.typo_rate,
            out=out_fh,
            rng=random.Random(args.seed),
        )
    finally:
        if out_fh is not None:
            out_fh.close()
    LOGGER.info("done: %d real SSH attempts", count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

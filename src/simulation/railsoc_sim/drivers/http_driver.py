"""Real HTTP driver (HC-23): genuine ``requests`` calls against the PIS stub.

``pis_stub.py`` already writes a schema event for every request it actually receives, so this
driver's only job is to make the request real; it does not write any events itself.

  python -m railsoc_sim.drivers.http_driver --base-url http://10.60.20.10:8080 \\
      --users ops_admin:change-me-lab-only,ops_lead:change-me-too-lab-only --duration 1800
"""

from __future__ import annotations

import argparse
import logging
import random
import time

import requests

LOGGER = logging.getLogger("railsoc_sim.drivers.http_driver")


def parse_users(raw: str) -> list[tuple[str, str]]:
    """Parse "user:password,user2:password2" into [(user, password), ...]."""
    users: list[tuple[str, str]] = []
    for item in raw.split(","):
        name, sep, password = item.strip().partition(":")
        if sep and name.strip():
            users.append((name.strip(), password))
    return users


def run(
    base_url: str,
    users: list[tuple[str, str]],
    *,
    duration_s: float,
    min_delay_s: float = 1.0,
    max_delay_s: float = 4.0,
    typo_rate: float = 0.1,
    rng: random.Random | None = None,
    session: requests.Session | None = None,
    sleep=time.sleep,
    now=time.monotonic,
) -> int:
    """Make real GET/POST requests against ``base_url`` for ``duration_s`` seconds.

    Returns the number of requests actually sent. A single failed request (timeout, connection
    refused while the lab is still coming up) is logged and the loop keeps going.
    """
    if not users:
        raise ValueError("at least one (username, password) is required")
    rng = rng or random.Random()
    session = session or requests.Session()
    deadline = now() + duration_s
    count = 0
    while now() < deadline:
        try:
            if rng.random() < 0.6:
                resp = session.get(f"{base_url}/api/arrivals", timeout=5)
                LOGGER.info("GET /api/arrivals -> %s", resp.status_code)
            else:
                username, password = rng.choice(users)
                if rng.random() < typo_rate:
                    password = password + "x"  # benign look-alike: a mistyped password
                resp = session.post(
                    f"{base_url}/api/login",
                    json={"username": username, "password": password},
                    timeout=5,
                )
                LOGGER.info("POST /api/login (%s) -> %s", username, resp.status_code)
        except requests.RequestException as exc:
            LOGGER.warning("request failed: %s", exc)
        count += 1
        sleep(rng.uniform(min_delay_s, max_delay_s))
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--users", required=True, help='"user:pass,user2:pass2"')
    parser.add_argument("--duration", type=float, default=1800.0, help="seconds")
    parser.add_argument("--min-delay", type=float, default=1.0)
    parser.add_argument("--max-delay", type=float, default=4.0)
    parser.add_argument("--typo-rate", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    count = run(
        args.base_url,
        parse_users(args.users),
        duration_s=args.duration,
        min_delay_s=args.min_delay,
        max_delay_s=args.max_delay,
        typo_rate=args.typo_rate,
        rng=random.Random(args.seed),
    )
    LOGGER.info("done: %d real requests", count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

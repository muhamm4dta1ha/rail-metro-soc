"""Command line for Module 1.

  python -m railsoc_sim.cli generate --hours 2 --seed 1 --out lab/data/raw/normal_s1.jsonl
  python -m railsoc_sim.cli assets
"""

from __future__ import annotations

import argparse

from railsoc_common.events import parse_ts, write_events
from railsoc_sim.assets import load_assets
from railsoc_sim.generator import generate_normal_events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="railsoc-sim", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="generate synthetic NORMAL events as JSON Lines")
    gen.add_argument("--start", default="2026-01-05T00:00:00Z", help="simulated start (UTC)")
    gen.add_argument("--hours", type=float, default=2.0)
    gen.add_argument("--seed", type=int, default=1)
    gen.add_argument("--out", required=True, help="output .jsonl path (under lab/data/ - not in git)")

    sub.add_parser("assets", help="print the asset inventory")

    args = parser.parse_args(argv)
    if args.cmd == "generate":
        events = generate_normal_events(parse_ts(args.start), args.hours, args.seed)
        count = write_events(args.out, events)
        print(f"wrote {count} events to {args.out}")
        return 0
    for asset in load_assets():
        print(f"{asset.asset_id:9} {asset.zone:14} {asset.type:19} {asset.ip:14} {asset.hostname}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

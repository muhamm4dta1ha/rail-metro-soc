"""Command line for Module 2. The default is a DRY RUN that sends no traffic.

  python -m railsoc_attacks.cli list
  python -m railsoc_attacks.cli run A                      # dry run: manifest only
  python -m railsoc_attacks.cli run A --param rate_per_s=5 # override parameters (clamped by the scope)
  python -m railsoc_attacks.cli run A --live               # real run inside the lab (needs M2-04)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from railsoc_attacks.recorder import DEFAULT_EVIDENCE_DIR, DEFAULT_GROUND_TRUTH, run_scenario
from railsoc_attacks.safety import load_scope
from railsoc_attacks.scenarios import REGISTRY, get_scenario


def _parse_params(items: list[str]) -> dict:
    params: dict = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise SystemExit(f"--param expects KEY=VALUE, got {item!r}")
        try:
            params[key] = json.loads(value)
        except json.JSONDecodeError:
            params[key] = value
    return params


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="railsoc-attacks", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list the scenarios")

    run = sub.add_parser("run", help="run one scenario (dry run unless --live)")
    run.add_argument("scenario", choices=sorted(REGISTRY))
    run.add_argument("--live", action="store_true", help="really execute (default: dry run, no traffic)")
    run.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    run.add_argument("--scope", help="path to a lab scope TOML (default: src/attacks/config/lab_scope.toml)")
    run.add_argument("--evidence-dir", default=str(DEFAULT_EVIDENCE_DIR))
    run.add_argument("--ground-truth", default=str(DEFAULT_GROUND_TRUTH))

    args = parser.parse_args(argv)
    if args.cmd == "list":
        for scenario_id in sorted(REGISTRY):
            scenario = REGISTRY[scenario_id]
            print(f"{scenario_id}  {scenario.title}  [{', '.join(scenario.techniques)}]")
        return 0

    result = run_scenario(
        get_scenario(args.scenario),
        _parse_params(args.param),
        scope=load_scope(args.scope),
        dry_run=not args.live,
        evidence_dir=Path(args.evidence_dir),
        ground_truth_csv=Path(args.ground_truth),
    )
    print(f"{result.status}: {result.run.run_id} -> {result.manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

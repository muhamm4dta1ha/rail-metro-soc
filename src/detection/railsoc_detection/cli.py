"""Command line for Module 3.

  python -m railsoc_detection.cli lint
  python -m railsoc_detection.cli evaluate --wazuh-alerts alerts.json --runs lab/ground_truth/attack_runs.csv --observed-hours 12
  python -m railsoc_detection.cli evaluate --ml-alerts lab/data/processed/ml_alerts.jsonl --runs lab/ground_truth/attack_runs.csv
"""

from __future__ import annotations

import argparse
from pathlib import Path

from railsoc_common.groundtruth import load_runs
from railsoc_detection.evaluate import (
    alerts_from_events,
    alerts_from_wazuh,
    evaluate,
    format_markdown,
)
from railsoc_detection.rule_lint import lint_tree


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="railsoc-detection", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    lint = sub.add_parser("lint", help="lint Wazuh rules and decoders (no Wazuh needed)")
    lint.add_argument("--siem-dir", default="src/detection/siem")

    ev = sub.add_parser("evaluate", help="score alerts against the ground truth")
    ev.add_argument("--wazuh-alerts", action="append", default=[], help="Wazuh alerts.json export")
    ev.add_argument("--ml-alerts", action="append", default=[], help="ML alert events (.jsonl)")
    ev.add_argument("--runs", default="lab/ground_truth/attack_runs.csv")
    ev.add_argument("--observed-hours", type=float)
    ev.add_argument("--grace-s", type=float, default=30.0)
    ev.add_argument("--min-level", type=int, default=0)

    args = parser.parse_args(argv)
    if args.cmd == "lint":
        issues = lint_tree(Path(args.siem_dir))
        for issue in issues:
            print(issue)
        print(f"{len(issues)} issue(s)")
        return 1 if issues else 0

    alerts = [a for p in args.wazuh_alerts for a in alerts_from_wazuh(p)]
    alerts += [a for p in args.ml_alerts for a in alerts_from_events(p)]
    result = evaluate(
        alerts,
        load_runs(args.runs),
        grace_s=args.grace_s,
        observed_hours=args.observed_hours,
        min_level=args.min_level,
    )
    print(format_markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

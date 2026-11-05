"""Command line for Module 4 (data lives under lab/data/, models under src/ml/models/ - both git-ignored).

  python -m railsoc_ml.cli build-dataset --events lab/data/raw/normal_s1.jsonl --events lab/data/raw/campaign.jsonl \\
      --runs lab/ground_truth/attack_runs.csv --assets src/simulation/config/assets.csv --out lab/data/processed/dataset_v1.csv
  python -m railsoc_ml.cli train --dataset lab/data/processed/dataset_v1.csv --out src/ml/models/anomaly.joblib
  python -m railsoc_ml.cli score --events lab/data/raw/live.jsonl --model src/ml/models/anomaly.joblib \\
      --assets src/simulation/config/assets.csv --out lab/data/processed/ml_alerts.jsonl
"""

from __future__ import annotations

import argparse
import json
import tomllib
from pathlib import Path

from railsoc_common.events import read_events
from railsoc_common.groundtruth import load_runs
from railsoc_ml.dataset import (
    build_dataset,
    known_ips_from_assets,
    load_dataset,
    save_dataset,
    split_windows,
)
from railsoc_ml.evaluate import binary_metrics
from railsoc_ml.models import ANOMALY_METHODS, AnomalyDetector
from railsoc_ml.serve import score_file

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "default.toml"


def load_config(path: str | Path | None = None) -> dict:
    return tomllib.loads(Path(path or DEFAULT_CONFIG).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    cfg = load_config()
    parser = argparse.ArgumentParser(prog="railsoc-ml", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    build = sub.add_parser("build-dataset", help="events + ground truth -> labelled windows (CSV)")
    build.add_argument("--events", action="append", required=True, help="JSON Lines file(s)")
    build.add_argument("--runs", default="lab/ground_truth/attack_runs.csv")
    build.add_argument("--assets", help="asset inventory CSV = known-source allow-list")
    build.add_argument("--window-s", type=int, default=cfg["window_s"])
    build.add_argument("--out", required=True)

    train = sub.add_parser("train", help="train + calibrate the anomaly detector, print test metrics")
    train.add_argument("--dataset", required=True)
    train.add_argument("--out", required=True, help="model path, e.g. src/ml/models/anomaly.joblib")
    train.add_argument("--target-fpr", type=float, default=cfg["target_fpr"])
    train.add_argument("--test-fraction", type=float, default=cfg["test_fraction"])
    train.add_argument("--seed", type=int, default=cfg["seed"])
    train.add_argument("--method", choices=ANOMALY_METHODS, default=cfg["anomaly_method"])

    score = sub.add_parser("score", help="score an event file and write ml.alert events")
    score.add_argument("--events", required=True)
    score.add_argument("--model", required=True)
    score.add_argument("--assets")
    score.add_argument("--window-s", type=int, default=cfg["window_s"])
    score.add_argument("--out", required=True)

    args = parser.parse_args(argv)

    if args.cmd == "build-dataset":
        events = (event for path in args.events for event in read_events(path))
        known = known_ips_from_assets(args.assets) if args.assets else None
        dataset = build_dataset(events, load_runs(args.runs), args.window_s, known)
        save_dataset(dataset, args.out)
        print(f"wrote {len(dataset)} windows ({int(dataset['is_attack'].sum())} attack) to {args.out}")
        return 0

    if args.cmd == "train":
        dataset = load_dataset(args.dataset)
        train_set, test_set = split_windows(dataset, args.test_fraction, args.seed)
        normal = train_set[train_set["run_id"] == ""]
        detector = AnomalyDetector(method=args.method, seed=args.seed).fit(normal)
        detector.calibrate(normal, args.target_fpr)  # starter: use a held-out validation split (M4-08)
        detector.save(args.out)
        metrics = binary_metrics(test_set["is_attack"], detector.score(test_set), detector.threshold)
        metrics = {key: (None if value != value else value) for key, value in metrics.items()}  # NaN -> null
        print(json.dumps({"model": detector.name, "threshold": detector.threshold, **metrics}))
        return 0

    detector = AnomalyDetector.load(args.model)
    known = known_ips_from_assets(args.assets) if args.assets else None
    count = score_file(args.events, detector, args.out, window_s=args.window_s, known_ips=known)
    print(f"wrote {count} ml.alert events to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

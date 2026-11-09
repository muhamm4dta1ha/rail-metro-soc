"""Build datasets, train detectors, compare on held-out windows and score event logs."""

from __future__ import annotations

import argparse
import json
import tomllib
from importlib.metadata import version
from pathlib import Path
from platform import python_version

import joblib

from railsoc_common.events import read_events
from railsoc_common.groundtruth import load_runs
from railsoc_detection.evaluate import alerts_from_wazuh
from railsoc_ml.dataset import (
    build_dataset,
    known_ips_from_assets,
    load_dataset,
    normal_windows,
    save_dataset,
    split_windows,
)
from railsoc_ml.evaluate import evaluate_detector, run_metrics, threat_target, write_comparison
from railsoc_ml.features import FEATURES
from railsoc_ml.models import (
    ANOMALY_METHODS,
    AnomalyDetector,
    SupervisedDetector,
    ThresholdBaseline,
)
from railsoc_ml.serve import score_file

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "default.toml"


def load_config(path: str | Path | None = None) -> dict:
    defaults = tomllib.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
    if path is not None:
        custom = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        defaults["paths"].update(custom.pop("paths", {}))
        defaults.update(custom)
    return defaults


def _training_args(parser, cfg):
    parser.add_argument("--dataset", default=cfg["paths"]["dataset"])
    parser.add_argument("--target-fpr", type=float, default=cfg["target_fpr"])
    parser.add_argument("--test-fraction", type=float, default=cfg["test_fraction"])
    parser.add_argument("--validation-fraction", type=float, default=cfg["validation_fraction"])
    parser.add_argument("--seed", type=int, default=cfg["seed"])


def _fit(args, cfg) -> int:
    dataset = load_dataset(args.dataset)
    if not dataset.attrs and dataset["run_id"].ne("").any():
        raise ValueError("rebuild the labeled dataset with its metadata sidecar before training")
    if args.validation_fraction <= 0:
        raise ValueError("training needs a positive validation fraction")
    train, validation, test = split_windows(
        dataset,
        args.test_fraction,
        args.seed,
        validation_fraction=args.validation_fraction,
    )
    normal_train, normal_val = normal_windows(train), normal_windows(validation)
    if normal_train.empty or normal_val.empty:
        raise ValueError("need clean benign windows in both training and validation")
    window_s = dataset.attrs.get("window_s", cfg["window_s"])
    known = dataset.attrs.get("known_ips")
    # The original ten columns are supported for normal-only CSVs from the starter.
    features = FEATURES if dataset.attrs else FEATURES[:10]
    methods = [args.method] if args.cmd == "train" else ANOMALY_METHODS
    detectors = []
    if args.cmd == "compare":
        detectors.append(ThresholdBaseline(cfg["min_failures"]))
    for method in methods:
        model = AnomalyDetector(
            method,
            features=features,
            seed=args.seed,
            nu=cfg["nu"],
            n_estimators=cfg["n_estimators"],
            max_train=cfg["max_train"],
        ).fit(normal_train)
        model.calibrate(normal_val, args.target_fpr)
        detectors.append(model)
    supervised_skip = None
    if args.cmd == "compare":
        target = threat_target(train)
        positive_runs = train.loc[target.eq(1) & train["run_id"].ne(""), "run_id"].nunique()
        if positive_runs >= cfg["min_supervised_train_runs"] and target.nunique() == 2:
            # Train negatives only from clean normal intervals.
            supervised_train = train.loc[train.index.isin(normal_train.index) | target.eq(1)]
            detectors.append(
                SupervisedDetector(
                    features=features, n_estimators=cfg["n_estimators"], seed=args.seed
                ).fit(supervised_train, threat_target(supervised_train))
            )
        else:
            supervised_skip = (
                "Random Forest skipped. Training needs clean benign windows and positive "
                f"windows from at least {cfg['min_supervised_train_runs']} distinct attack runs."
            )

    rows, all_alerts, artifacts = [], {}, {}
    for detector in detectors:
        metrics, alerts = evaluate_detector(detector, test, window_s, grace_s=cfg["run_grace_s"])
        detector.window_s = window_s
        detector.known_ips = known
        output = (
            Path(args.out)
            if args.cmd == "train"
            else Path(args.models_dir) / f"{detector.name}.joblib"
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(detector, output)
        artifacts[detector.name] = str(output)
        if isinstance(detector, AnomalyDetector):
            metrics["validation_fpr"] = float(detector.predict(normal_val).mean())
        rows.append(metrics)
        all_alerts[detector.name] = alerts
    if args.cmd == "train":
        print(json.dumps(rows[0], allow_nan=False))
        return 0

    report = {
        "dataset": str(args.dataset),
        "versions": {
            "python": python_version(),
            **{
                package: version(package)
                for package in ("numpy", "pandas", "scikit-learn", "joblib", "matplotlib")
            },
        },
        "window_s": window_s,
        "seed": args.seed,
        "target_fpr": args.target_fpr,
        "partitions": {
            name: {
                "rows": len(part),
                "clean_normal_rows": len(normal_windows(part)),
                "first_window_start": part["window_start"].min().isoformat(),
                "last_window_start": part["window_start"].max().isoformat(),
                "labels": part["label"].value_counts().to_dict(),
            }
            for name, part in zip(
                ("train", "validation", "test"), (train, validation, test), strict=True
            )
        },
        "models": rows,
        "artifacts": artifacts,
        "supervised_skip": supervised_skip,
    }
    if args.wazuh_alerts:
        # Compare the scenario rules, excluding the ML rule to avoid counting the same alert twice.
        alerts = (
            a
            for a in alerts_from_wazuh(args.wazuh_alerts)
            if a.source.removeprefix("wazuh:").isdigit()
            and 100100 <= int(a.source.removeprefix("wazuh:")) < 100400
        )
        report["wazuh_rules"] = run_metrics(alerts, test, window_s, grace_s=cfg["run_grace_s"])
    write_comparison(Path(args.report_dir), report, all_alerts)
    print(f"wrote held-out comparison to {args.report_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config")
    cfg = load_config(pre.parse_known_args(argv)[0].config)
    paths = cfg["paths"]
    parser = argparse.ArgumentParser(prog="railsoc-ml", description=__doc__, parents=[pre])
    sub = parser.add_subparsers(dest="cmd", required=True)

    build = sub.add_parser(
        "build-dataset", help="build labeled windows from one or more JSONL files"
    )
    build.add_argument("--events", action="append", required=True)
    build.add_argument("--runs", default=paths["runs"])
    build.add_argument("--assets", help="asset inventory CSV for the optional known-source feature")
    build.add_argument("--window-s", type=int, default=cfg["window_s"])
    build.add_argument("--out", default=paths["dataset"])

    train = sub.add_parser("train", help="train and calibrate one anomaly detector")
    _training_args(train, cfg)
    train.add_argument("--out", default=paths["model"])
    train.add_argument("--method", choices=ANOMALY_METHODS, default=cfg["anomaly_method"])

    compare = sub.add_parser(
        "compare", help="fit fixed model candidates and report held-out results"
    )
    _training_args(compare, cfg)
    compare.add_argument("--models-dir", default=paths["models"])
    compare.add_argument("--report-dir", default=paths["reports"])
    compare.add_argument(
        "--wazuh-alerts", help="optional Wazuh alerts.json covering the same test period"
    )

    score = sub.add_parser("score", help="score JSONL input and write validated ml.alert events")
    score.add_argument("--events", required=True)
    score.add_argument("--model", default=paths["model"])
    score.add_argument("--assets")
    score.add_argument("--window-s", type=int)
    score.add_argument("--out", default=paths["alerts"])
    score.add_argument(
        "--stream", action="store_true", help="score timestamp-ordered JSONL incrementally"
    )
    score.add_argument("--max-window-events", type=int, default=cfg["max_window_events"])

    args = parser.parse_args(argv)
    try:
        if args.cmd == "build-dataset":
            if not Path(args.runs).is_file():
                raise ValueError(f"ground-truth file missing: {args.runs}")
            events = (event for path in args.events for event in read_events(path))
            known = known_ips_from_assets(args.assets) if args.assets else None
            dataset = build_dataset(events, load_runs(args.runs), args.window_s, known)
            save_dataset(dataset, args.out)
            print(
                f"wrote {len(dataset)} windows ({int(dataset['is_attack'].sum())} attack) to {args.out}"
            )
            return 0

        if args.cmd in ("train", "compare"):
            return _fit(args, cfg)

        detector = joblib.load(args.model)
        trained_window = getattr(detector, "window_s", None)
        trained_known = getattr(detector, "known_ips", None)
        window_s = args.window_s if args.window_s is not None else trained_window or cfg["window_s"]
        known = known_ips_from_assets(args.assets) if args.assets else set(trained_known or ())
        if trained_window is not None and window_s != trained_window:
            raise ValueError("scoring window size must match the trained model")
        if trained_known is not None and known != set(trained_known):
            raise ValueError("scoring asset inventory must match the trained model")
        count = score_file(
            args.events,
            detector,
            args.out,
            window_s=window_s,
            known_ips=known,
            streaming=args.stream,
            max_window_events=args.max_window_events,
        )
    except (OSError, ValueError) as exc:
        parser.exit(2, f"railsoc-ml: {exc}\n")
    print(f"wrote {count} ml.alert events to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

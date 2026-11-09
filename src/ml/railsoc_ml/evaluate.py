"""Window-level metrics and a run-level comparison using the Module 3 evaluator."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from railsoc_common.events import as_utc, write_events
from railsoc_common.groundtruth import ATTACK, ATTACK_IMPACT, AttackRun
from railsoc_detection.evaluate import Alert, evaluate
from railsoc_ml.serve import window_alerts

SCENARIOS = ("A", "B", "C")


def threat_target(windows: pd.DataFrame) -> pd.Series:
    """Binary SOC target includes directly attributed activity and victim impact."""
    return windows["label"].isin([ATTACK, ATTACK_IMPACT]).astype(int)


def binary_metrics(y_true, scores, threshold: float) -> dict:
    """Window-level metrics for the rule score > threshold."""
    truth = np.asarray(y_true, dtype=bool)
    values = np.asarray(scores, dtype=float)
    if truth.ndim != 1 or truth.shape != values.shape or not np.isfinite(values).all():
        raise ValueError("expected matching vectors of labels and finite scores")
    flagged = values > threshold
    tp = int((flagged & truth).sum())
    fp = int((flagged & ~truth).sum())
    tn = int((~flagged & ~truth).sum())
    fn = int((~flagged & truth).sum())
    has_both = bool(truth.any() and not truth.all())
    unavailable = {}
    if tp + fp == 0:
        unavailable["precision"] = "no flagged windows"
    if tp + fn == 0:
        unavailable["recall"] = "no positive windows"
    if tp + fn == 0:
        unavailable["f1"] = "no positive windows to measure detection"
    if fp + tn == 0:
        unavailable["fpr"] = "no negative windows"
    if not has_both:
        for name in ("roc_auc", "pr_auc"):
            unavailable[name] = "requires both positive and negative windows"
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if tp + fn else None,
        "fpr": fp / (fp + tn) if fp + tn else None,
        "roc_auc": float(roc_auc_score(truth, values)) if has_both else None,
        "pr_auc": float(average_precision_score(truth, values)) if has_both else None,
        "unavailable": unavailable,
    }


def false_alarms_per_hour(false_positives: int, observed_hours: float) -> float:
    """Number of false alarms divided by the stated observation time."""
    if observed_hours <= 0:
        raise ValueError("observed_hours must be > 0")
    return false_positives / observed_hours


def run_metrics(alerts, windows: pd.DataFrame, window_s: int, *, grace_s: float) -> dict:
    """Score held-out run intervals and alert timestamps with the same M3 convention."""
    start = windows["window_start"].min()
    end = windows["window_start"].max() + pd.Timedelta(seconds=window_s)
    runs = [AttackRun.from_row(row) for row in windows.attrs.get("runs", [])]
    held_out = [run for run in runs if start <= run.start and run.end < end]
    hours = windows["window_start"].nunique() * window_s / 3600
    result = evaluate(
        (alert for alert in alerts if start <= alert.ts <= end),
        held_out,
        grace_s=grace_s,
        observed_hours=hours,
    )
    scenarios = {}
    for scenario in SCENARIOS:
        subset = [run for run in result.runs if run.scenario_id == scenario]
        detected = sum(run.detected for run in subset)
        scenarios[scenario] = {
            "runs": len(subset),
            "detected": detected,
            "recall": detected / len(subset) if subset else None,
        }
    return {
        "observed_hours": hours,
        "grace_s": grace_s,
        "detection_rate": result.detection_rate,
        "false_alarms": result.false_alarms,
        "false_alarms_per_hour": result.false_alarms_per_hour,
        "per_scenario": scenarios,
        "runs": [vars(run) for run in result.runs],
        "excluded_partial_run_ids": [
            run.run_id
            for run in runs
            if run.scenario_id != "BASELINE"
            and run.start < end
            and run.end >= start
            and run not in held_out
        ],
        "unavailable": "Run recall requires complete held-out attack runs. "
        "Latency requires a matching alert for a complete run.",
    }


def evaluate_detector(detector, windows: pd.DataFrame, window_s: int, *, grace_s: float = 30):
    scores = detector.score(windows)
    target = threat_target(windows)
    metrics = binary_metrics(target, scores, detector.threshold)
    flagged = scores > detector.threshold
    false_positives = (
        windows.loc[flagged & target.eq(0)]
        .assign(score=scores[flagged & target.eq(0)])
        .sort_values("score", ascending=False, kind="stable")
    )
    alerts = list(window_alerts(windows, detector, window_s=window_s))
    metrics.update(
        model=detector.name,
        threshold=detector.threshold,
        per_scenario_window_recall={
            scenario: (float(flagged[mask].mean()) if mask.any() else None)
            for scenario in SCENARIOS
            for mask in [target.eq(1) & windows["scenario_id"].eq(scenario)]
        },
        false_positives_by_source=false_positives["src_ip"]
        .replace("", "(missing)")
        .value_counts()
        .to_dict(),
        false_positive_examples=[
            {
                "window_start": row["window_start"].isoformat(),
                "source_ip": row["src_ip"] or None,
                "score": row["score"],
                "top_features": detector.explain(row),
            }
            for _, row in false_positives.head(10).iterrows()
        ],
    )
    benign_hours = windows.loc[target.eq(0), "window_start"].nunique() * window_s / 3600
    metrics["benign_window_hours"] = benign_hours
    metrics["false_alarms_per_hour"] = (
        false_alarms_per_hour(metrics["fp"], benign_hours) if benign_hours else None
    )
    metrics["run_metrics"] = run_metrics(
        (
            Alert(
                as_utc(event["@timestamp"]),
                f"ml:{detector.name}",
                src_ip=event.get("source", {}).get("ip"),
            )
            for event in alerts
        ),
        windows,
        window_s,
        grace_s=grace_s,
    )
    return metrics, alerts


def write_comparison(out: Path, report: dict, alerts: dict) -> None:
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(
        json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    keys = (
        "threshold",
        "tn",
        "fp",
        "fn",
        "tp",
        "precision",
        "recall",
        "f1",
        "fpr",
        "roc_auc",
        "pr_auc",
        "false_alarms_per_hour",
    )
    headings = ["Model", *keys]
    test = report["partitions"]["test"]
    lines = [
        "# Held-out comparison",
        "",
        f"First and last test window starts (UTC): {test['first_window_start']} and "
        f"{test['last_window_start']}. Window length: {report['window_s']} seconds.",
        "",
        "| " + " | ".join(headings) + " |",
        "| " + " | ".join(["---"] * len(headings)) + " |",
    ]
    for row in report["models"]:
        values = ["Unavailable" if row[key] is None else f"{row[key]:.6g}" for key in keys]
        lines.append("| " + " | ".join([row["model"], *values]) + " |")
    lines += [
        "",
        "See metrics.json for unavailable metric reasons, per-scenario results, "
        "run latency and false-positive examples.",
    ]
    if report["supervised_skip"]:
        lines += ["", report["supervised_skip"]]
    (out / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    fig = Figure(figsize=(8, 3.8), layout="constrained")
    FigureCanvasAgg(fig)
    axes = fig.subplots()
    rows = report["models"]
    axes.bar([row["model"] for row in rows], [row["fp"] for row in rows], color="#b54c36")
    axes.set(ylabel="False-positive windows", title="Held-out false positives by detector")
    fig.savefig(out / "false_positives.png", dpi=140)
    fig = Figure(figsize=(3 * len(rows), 3.2), layout="constrained")
    FigureCanvasAgg(fig)
    for ax, row in zip(fig.subplots(1, len(rows), squeeze=False)[0], rows, strict=True):
        matrix = [[row["tn"], row["fp"]], [row["fn"], row["tp"]]]
        ax.imshow(matrix, cmap="Blues")
        for y, values in enumerate(matrix):
            for x, value in enumerate(values):
                ax.text(
                    x,
                    y,
                    str(value),
                    ha="center",
                    va="center",
                    color="white" if value > max(map(max, matrix)) / 2 else "black",
                )
        ax.set(title=row["model"], xlabel="Prediction", ylabel="Actual")
        ax.set_xticks([0, 1], ["Benign", "Threat"])
        ax.set_yticks([0, 1], ["Benign", "Threat"])
    fig.savefig(out / "confusion_matrices.png", dpi=140)
    for model, events in alerts.items():
        write_events(out / f"{model}.alerts.jsonl", events)

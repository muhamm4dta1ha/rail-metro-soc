"""Evaluation helpers (task M4-09). Detection latency and rule-vs-ML comparison use
railsoc_detection.evaluate on the ML alert events, so rules and ML are scored the same way.
"""

from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


def binary_metrics(y_true, scores, threshold: float) -> dict[str, float]:
    """Window-level metrics for the rule `score > threshold` (higher score = more suspicious)."""
    truth = np.asarray(y_true).astype(bool)
    values = np.asarray(scores, dtype=float)
    flagged = values > threshold

    tp = int((flagged & truth).sum())
    fp = int((flagged & ~truth).sum())
    tn = int((~flagged & ~truth).sum())
    fn = int((~flagged & truth).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    has_both = truth.any() and not truth.all()
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "roc_auc": float(roc_auc_score(truth, values)) if has_both else float("nan"),
        "pr_auc": float(average_precision_score(truth, values)) if has_both else float("nan"),
    }


def false_alarms_per_hour(false_positives: int, observed_hours: float) -> float:
    """False alarms per hour of NORMAL operation - the number a SOC analyst actually feels."""
    if observed_hours <= 0:
        raise ValueError("observed_hours must be > 0")
    return false_positives / observed_hours

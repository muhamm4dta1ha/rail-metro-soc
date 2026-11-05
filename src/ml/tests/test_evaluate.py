import math

import pytest

from railsoc_ml.evaluate import binary_metrics, false_alarms_per_hour


def test_binary_metrics_counts_and_rates():
    metrics = binary_metrics([1, 1, 0, 0, 0], [0.9, 0.4, 0.6, 0.1, 0.2], threshold=0.5)
    assert (metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]) == (1, 1, 2, 1)
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5
    assert metrics["fpr"] == pytest.approx(1 / 3)
    assert 0.0 <= metrics["roc_auc"] <= 1.0
    assert 0.0 <= metrics["pr_auc"] <= 1.0


def test_a_perfect_detector_scores_one():
    metrics = binary_metrics([1, 1, 0, 0], [0.9, 0.8, 0.1, 0.2], threshold=0.5)
    assert metrics["precision"] == metrics["recall"] == metrics["f1"] == 1.0
    assert metrics["fpr"] == 0.0 and metrics["roc_auc"] == 1.0


def test_a_single_class_does_not_crash_but_has_no_auc():
    metrics = binary_metrics([0, 0, 0], [0.1, 0.2, 0.3], threshold=0.5)
    assert math.isnan(metrics["roc_auc"]) and math.isnan(metrics["pr_auc"])
    assert metrics["recall"] == 0.0


def test_false_alarms_per_hour():
    assert false_alarms_per_hour(3, 1.5) == 2.0
    with pytest.raises(ValueError):
        false_alarms_per_hour(1, 0)

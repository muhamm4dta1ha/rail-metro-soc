"""Models (tasks M4-06 / M4-07 / M4-08). All detectors share one tiny interface:

    .name   .threshold   .score(windows) -> higher = more suspicious
    .predict(windows) -> bool array   .explain(row) -> list of the most telling feature names

Convention: a window is flagged when score > threshold.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from railsoc_ml.dataset import normal_windows
from railsoc_ml.features import FEATURES

ANOMALY_METHODS = ("ocsvm", "isolation_forest")


def _feature_names(features: list[str] | None) -> list[str]:
    names = list(features or FEATURES)
    if set(names) - set(FEATURES):
        raise ValueError("models can use only the feature catalogue columns")
    return names


def _check_normal(windows: pd.DataFrame) -> None:
    if windows.empty:
        raise ValueError("need at least one normal window")
    if "label" in windows and len(normal_windows(windows)) != len(windows):
        raise ValueError("fit and calibration require clean normal windows")
    if "is_attack" in windows and windows["is_attack"].any():
        raise ValueError("fit and calibration require clean normal windows")


class ThresholdBaseline:
    """Rule-style baseline (score = failures in the window). Uses a fixed operating point."""

    name = "threshold_failures"

    def __init__(self, min_failures: int = 5) -> None:
        self.threshold = min_failures - 0.5

    def score(self, windows: pd.DataFrame) -> np.ndarray:
        return windows["n_failures"].to_numpy(dtype=float)

    def predict(self, windows: pd.DataFrame) -> np.ndarray:
        return self.score(windows) > self.threshold

    def explain(self, window_row: pd.Series, top_k: int = 3) -> list[str]:
        return ["n_failures"]


class AnomalyDetector:
    """Unsupervised detector trained on NORMAL windows only.

    ``ocsvm`` (default): One-Class SVM with an RBF kernel on standardised features. It
    extrapolates, so a window far outside anything seen in normal traffic gets the highest score.

    Isolation Forest partitions the observed range of its training features.
    With very repetitive traffic, values far beyond the training extremes can
    land in the same leaves as ordinary values near the extremes.
    """

    def __init__(
        self,
        method: str = "ocsvm",
        features: list[str] | None = None,
        seed: int = 1,
        nu: float = 0.01,
        n_estimators: int = 200,
        max_train: int = 5000,
    ) -> None:
        if method not in ANOMALY_METHODS:
            raise ValueError(f"method must be one of {ANOMALY_METHODS}, got {method!r}")
        self.method = method
        self.name = method
        self.features = _feature_names(features)
        self.seed = seed
        self.nu = nu
        self.n_estimators = n_estimators
        self.max_train = (
            max_train  # the One-Class SVM is O(n^2): subsample very large training sets
        )
        self.scaler = StandardScaler()
        self.model: OneClassSVM | IsolationForest | None = None
        self.threshold: float | None = None

    def _matrix(self, windows: pd.DataFrame) -> np.ndarray:
        return windows[self.features].to_numpy(dtype=float)

    def fit(self, normal_windows: pd.DataFrame) -> AnomalyDetector:
        _check_normal(normal_windows)
        matrix = self._matrix(normal_windows)
        if len(matrix) > self.max_train:
            rows = np.random.default_rng(self.seed).choice(
                len(matrix), self.max_train, replace=False
            )
            matrix = matrix[np.sort(rows)]
        scaled = self.scaler.fit_transform(matrix)
        if self.method == "ocsvm":
            self.model = OneClassSVM(kernel="rbf", gamma="scale", nu=self.nu)
        else:
            self.model = IsolationForest(n_estimators=self.n_estimators, random_state=self.seed)
        self.model.fit(scaled)
        self.threshold = None
        return self

    def score(self, windows: pd.DataFrame) -> np.ndarray:
        """Higher = more anomalous."""
        if self.model is None:
            raise RuntimeError("call fit() before score()")
        if windows.empty:
            return np.empty(0)
        scaled = self.scaler.transform(self._matrix(windows))
        if self.method == "ocsvm":
            return -self.model.decision_function(scaled)
        return -self.model.score_samples(scaled)

    def calibrate(self, normal_windows: pd.DataFrame, target_fpr: float = 0.01) -> float:
        """Choose the threshold so that about `target_fpr` of NORMAL windows would be flagged."""
        _check_normal(normal_windows)
        if not 0 <= target_fpr < 1:
            raise ValueError("target_fpr must be in [0, 1)")
        self.threshold = float(
            np.quantile(self.score(normal_windows), 1.0 - target_fpr, method="higher")
        )
        return self.threshold

    def predict(self, windows: pd.DataFrame) -> np.ndarray:
        if self.threshold is None:
            raise RuntimeError("call calibrate() before predict()")
        return self.score(windows) > self.threshold

    def explain(self, window_row: pd.Series, top_k: int = 3) -> list[str]:
        """Rank score drops from replacing each feature with its normal training mean."""
        values = window_row[self.features].to_numpy(dtype=float)
        deviation = np.abs(self.scaler.transform(values.reshape(1, -1))[0])
        alternatives = np.tile(values, (len(values), 1))
        np.fill_diagonal(alternatives, self.scaler.mean_)
        scores = self.score(pd.DataFrame(np.vstack([values, alternatives]), columns=self.features))
        drops = scores[0] - scores[1:]
        order = np.lexsort((-deviation, -drops))
        supporting = order[(drops[order] > 0) & (deviation[order] > 0)]
        if not len(supporting):
            order = np.argsort(-deviation, kind="stable")
            supporting = order[deviation[order] > 0]
        return [self.features[i] for i in supporting[:top_k]]

    def save(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, target)

    @staticmethod
    def load(path: str | Path) -> AnomalyDetector:
        return joblib.load(path)


class SupervisedDetector:
    """Random forest for KNOWN attack types (needs labelled windows from the campaign)."""

    name = "random_forest"
    threshold = 0.5

    def __init__(
        self, features: list[str] | None = None, n_estimators: int = 200, seed: int = 1
    ) -> None:
        self.features = _feature_names(features)
        self.model = RandomForestClassifier(
            n_estimators=n_estimators, class_weight="balanced", random_state=seed
        )

    def fit(self, windows: pd.DataFrame, y) -> SupervisedDetector:
        labels = np.asarray(y)
        if set(labels) != {0, 1}:
            raise ValueError("supervised training requires both benign and attack examples")
        self.model.fit(windows[self.features].to_numpy(dtype=float), labels.astype(int))
        return self

    def score(self, windows: pd.DataFrame) -> np.ndarray:
        """Probability of the positive class."""
        classes = list(self.model.classes_)
        if windows.empty:
            return np.empty(0)
        proba = self.model.predict_proba(windows[self.features].to_numpy(dtype=float))
        return proba[:, classes.index(1)]

    def predict(self, windows: pd.DataFrame) -> np.ndarray:
        return self.score(windows) > self.threshold

    def explain(self, window_row: pd.Series, top_k: int = 3) -> list[str]:
        """Globally most important features (per-window explanations: M4-09, e.g. SHAP)."""
        order = np.argsort(-self.model.feature_importances_, kind="stable")[:top_k]
        return [self.features[i] for i in order]

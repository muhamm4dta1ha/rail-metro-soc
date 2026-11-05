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

from railsoc_ml.features import FEATURES

ANOMALY_METHODS = ("ocsvm", "isolation_forest")


class ThresholdBaseline:
    """Rule-style baseline (score = failures in the window). ML must beat this and the SIEM rules."""

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

    ``isolation_forest``: kept for comparison. Finding from the starter test data: on very regular,
    OT-like traffic (a handful of distinct normal feature vectors) an Isolation Forest cannot
    extrapolate beyond the training range and scored a 60-failure burst as LESS anomalous than
    normal windows (0.66 vs 0.69), while the One-Class SVM separated them clearly (1.38 vs 0.0002).
    Re-check this on the real campaign data before choosing a model (task M4-08).
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
        self.features = list(features or FEATURES)
        self.seed = seed
        self.nu = nu
        self.n_estimators = n_estimators
        self.max_train = max_train  # the One-Class SVM is O(n^2): subsample very large training sets
        self.scaler = StandardScaler()
        self.model: OneClassSVM | IsolationForest | None = None
        self.threshold: float | None = None

    def _matrix(self, windows: pd.DataFrame) -> np.ndarray:
        return windows[self.features].to_numpy(dtype=float)

    def fit(self, normal_windows: pd.DataFrame) -> AnomalyDetector:
        matrix = self._matrix(normal_windows)
        if len(matrix) > self.max_train:
            rows = np.random.default_rng(self.seed).choice(len(matrix), self.max_train, replace=False)
            matrix = matrix[np.sort(rows)]
        scaled = self.scaler.fit_transform(matrix)
        if self.method == "ocsvm":
            self.model = OneClassSVM(kernel="rbf", gamma="scale", nu=self.nu)
        else:
            self.model = IsolationForest(n_estimators=self.n_estimators, random_state=self.seed)
        self.model.fit(scaled)
        return self

    def score(self, windows: pd.DataFrame) -> np.ndarray:
        """Higher = more anomalous."""
        scaled = self.scaler.transform(self._matrix(windows))
        if self.method == "ocsvm":
            return -self.model.decision_function(scaled)
        return -self.model.score_samples(scaled)

    def calibrate(self, normal_windows: pd.DataFrame, target_fpr: float = 0.01) -> float:
        """Choose the threshold so that about `target_fpr` of NORMAL windows would be flagged."""
        self.threshold = float(np.quantile(self.score(normal_windows), 1.0 - target_fpr))
        return self.threshold

    def predict(self, windows: pd.DataFrame) -> np.ndarray:
        if self.threshold is None:
            raise RuntimeError("call calibrate() before predict()")
        return self.score(windows) > self.threshold

    def explain(self, window_row: pd.Series, top_k: int = 3) -> list[str]:
        """Features that deviate most (in standard deviations) from the normal training data."""
        values = window_row[self.features].to_numpy(dtype=float).reshape(1, -1)
        deviation = np.abs(self.scaler.transform(values)[0])
        return [self.features[i] for i in np.argsort(-deviation)[:top_k]]

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
        self.features = list(features or FEATURES)
        self.model = RandomForestClassifier(
            n_estimators=n_estimators, class_weight="balanced", random_state=seed
        )

    def fit(self, windows: pd.DataFrame, y) -> SupervisedDetector:
        self.model.fit(windows[self.features].to_numpy(dtype=float), np.asarray(y).astype(int))
        return self

    def score(self, windows: pd.DataFrame) -> np.ndarray:
        """Probability of 'attack' (0 if the training data never contained an attack)."""
        classes = list(self.model.classes_)
        if 1 not in classes:
            return np.zeros(len(windows))
        proba = self.model.predict_proba(windows[self.features].to_numpy(dtype=float))
        return proba[:, classes.index(1)]

    def predict(self, windows: pd.DataFrame) -> np.ndarray:
        return self.score(windows) > self.threshold

    def explain(self, window_row: pd.Series, top_k: int = 3) -> list[str]:
        """Globally most important features (per-window explanations: M4-09, e.g. SHAP)."""
        order = np.argsort(-self.model.feature_importances_)[:top_k]
        return [self.features[i] for i in order]

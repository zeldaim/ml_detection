"""Unsupervised detector: Isolation Forest over a feature matrix.

Unsupervised because BOLA labels are scarce. Train on mostly-benign traffic;
score_samples returns higher = more normal, so we negate for an anomaly score.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@dataclass
class AnomalyModel:
    """A trained (scaler + IsolationForest) pair for ONE detector's features."""
    scaler: StandardScaler
    model: IsolationForest
    columns: List[str]

    def anomaly_scores(self, X: Sequence[Sequence[float]]) -> np.ndarray:
        Xs = self.scaler.transform(np.asarray(X, dtype=float))
        return -self.model.score_samples(Xs)   # higher = more anomalous

    def predict_anomaly(self, X: Sequence[Sequence[float]]) -> np.ndarray:
        Xs = self.scaler.transform(np.asarray(X, dtype=float))
        return self.model.predict(Xs) == -1    # True = anomaly


def train_model(
    X: Sequence[Sequence[float]],
    columns: List[str],
    contamination: float = 0.02,
    random_state: int = 42,
) -> AnomalyModel:
    Xa = np.asarray(X, dtype=float)
    scaler = StandardScaler().fit(Xa)
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
    ).fit(scaler.transform(Xa))
    return AnomalyModel(scaler=scaler, model=model, columns=list(columns))


# backward-compatible alias
train_detector = train_model

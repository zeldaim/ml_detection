"""BOLA / IDOR detector — the first sibling.

Object-level authorization abuse: an authenticated user reaching objects they
don't own. Reuses the edge + central feature functions; owns the per-user
baseline history. Needs ownership enrichment for its central features.
"""

from __future__ import annotations

from typing import Dict, List

from ..schema import AccessLog
from ..edge_features import EDGE_FEATURE_NAMES, compute_edge_features
from ..central_features import (
    CENTRAL_FEATURE_NAMES,
    UserHistory,
    compute_central_features,
)
from .base import Detector


class BolaDetector(Detector):
    name = "bola"
    needs_ownership = True

    def __init__(self) -> None:
        self._history = UserHistory()

    @property
    def feature_names(self) -> List[str]:
        return list(EDGE_FEATURE_NAMES) + list(CENTRAL_FEATURE_NAMES)

    def reset(self) -> None:
        self._history = UserHistory()

    def extract(self, window: List[AccessLog], user_id: str, window_seconds: float) -> Dict[str, float]:
        feats = compute_edge_features(window, window_seconds)
        feats.update(compute_central_features(window, user_id, self._history))
        return feats

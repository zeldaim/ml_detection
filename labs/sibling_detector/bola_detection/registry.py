"""Registry: run sibling detectors over ONE shared windowing pass.

This is the piece that reconciles "sibling detectors" with "results attached
simultaneously": logs are windowed once, each detector scores every window, and
each window ends up with every detector's score + a combined score + which
detector it's attributed to. Adding a detector = append it to the list; the log
schema and this runner don't change.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

from .schema import AccessLog
from .ownership import OwnershipSource
from .pipeline import enrich, _window_key
from .model import train_model
from .detectors.base import Detector


@dataclass
class WindowResult:
    user_id: str
    window_start: float
    scores: Dict[str, float] = field(default_factory=dict)   # raw anomaly score per detector
    z: Dict[str, float] = field(default_factory=dict)        # standardized per detector
    combined: float = 0.0                                    # max z across detectors
    top_detector: str = ""                                   # which detector fired hardest


class DetectorRegistry:
    def __init__(
        self,
        detectors: List[Detector],
        window_seconds: float = 300.0,
        ownership: Optional[OwnershipSource] = None,
        contamination: float = 0.02,
    ) -> None:
        self.detectors = detectors
        self.window_seconds = window_seconds
        self.ownership = ownership
        self.contamination = contamination

    def fit_score(self, logs: List[AccessLog]) -> List[WindowResult]:
        # Enrich once if any sibling needs ownership.
        if self.ownership is not None and any(d.needs_ownership for d in self.detectors):
            enrich(logs, self.ownership)

        # Window once, shared by all detectors.
        groups: Dict[tuple, List[AccessLog]] = {}
        for log in logs:
            key = (log.user_id, _window_key(log.timestamp, self.window_seconds))
            groups.setdefault(key, []).append(log)
        keys = sorted(groups, key=lambda k: (k[1], k[0]))   # time order for history

        results = [WindowResult(user_id=k[0], window_start=k[1]) for k in keys]

        # Each detector scores every window independently.
        for det in self.detectors:
            det.reset()
            rows = [det.extract(groups[k], k[0], self.window_seconds) for k in keys]
            X = [[float(r[f]) for f in det.feature_names] for r in rows]
            model = train_model(X, det.feature_names, contamination=self.contamination)
            raw = np.asarray(model.anomaly_scores(X))
            std = raw.std()
            z = (raw - raw.mean()) / std if std > 0 else np.zeros_like(raw)
            for i, res in enumerate(results):
                res.scores[det.name] = float(raw[i])
                res.z[det.name] = float(z[i])

        # Attach combined score + attribution per window (all at once).
        for res in results:
            name, zz = max(res.z.items(), key=lambda kv: kv[1])
            res.combined = zz
            res.top_detector = name
        return results

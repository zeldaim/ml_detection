"""Data-exfiltration detector — a second sibling, to prove the framework.

Catches bulk pull of data (including an insider pulling their OWN data), which
BOLA misses because there's no ownership mismatch. Uses only fields already in
the standardized log (response_size, method) — so adding this detector needs
NO change to the edge log schema.
"""

from __future__ import annotations

from typing import Dict, List

from ..schema import AccessLog
from .base import Detector

EXFIL_FEATURE_NAMES: List[str] = [
    "total_response_bytes",
    "max_response_size",
    "bytes_per_request",
    "read_count",
]


class ExfilDetector(Detector):
    name = "exfil"
    needs_ownership = False

    @property
    def feature_names(self) -> List[str]:
        return list(EXFIL_FEATURE_NAMES)

    def extract(self, window: List[AccessLog], user_id: str, window_seconds: float) -> Dict[str, float]:
        n = len(window)
        total = sum(r.response_size for r in window)
        reads = sum(1 for r in window if r.method == "GET")
        return {
            "total_response_bytes": float(total),
            "max_response_size": float(max((r.response_size for r in window), default=0)),
            "bytes_per_request": (total / n) if n else 0.0,
            "read_count": float(reads),
        }

"""Detector interface shared by every attack family.

Contract: a detector turns one (user, window) slice of AccessLogs into a flat
feature dict. It owns any per-run state (e.g. per-user history) and resets it
via reset(). It does NOT own windowing, enrichment, or the model — the registry
handles those so all detectors stay consistent and run in a single pass.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List

from ..schema import AccessLog


class Detector(ABC):
    #: unique short name, used as the key in combined results
    name: str = "base"
    #: True if this detector reads the ownership-enriched fields (owner_id, ...)
    needs_ownership: bool = False

    @property
    @abstractmethod
    def feature_names(self) -> List[str]:
        """Ordered feature columns this detector produces."""

    def reset(self) -> None:
        """Clear per-run state before a fresh pass. Override if stateful."""

    @abstractmethod
    def extract(
        self,
        window: List[AccessLog],
        user_id: str,
        window_seconds: float,
    ) -> Dict[str, float]:
        """Feature dict for one (user, window) slice. Keys == feature_names."""

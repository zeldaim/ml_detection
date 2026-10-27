"""BOLA detection feature pipeline (hybrid edge/central architecture).

Versions
--------
- v0_edge   : features computable at an edge agent with no central state.
- v1_hybrid : v0 + central-only features (ownership join, global baseline).
"""

from .schema import AccessLog, OwnershipRecord
from .ownership import OwnershipSource, InMemoryOwnershipSource
from .pipeline import build_features, FEATURE_SETS
from .registry import DetectorRegistry, WindowResult
from .detectors import Detector, BolaDetector, ExfilDetector

__all__ = [
    "AccessLog",
    "OwnershipRecord",
    "OwnershipSource",
    "InMemoryOwnershipSource",
    "build_features",
    "FEATURE_SETS",
    "DetectorRegistry",
    "WindowResult",
    "Detector",
    "BolaDetector",
    "ExfilDetector",
]

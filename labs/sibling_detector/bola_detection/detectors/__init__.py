"""Sibling detectors: one per attack family, sharing the same log pipeline.

Each detector declares its own feature columns and extracts them from a
(user, window) slice. The registry runs them over one shared windowing pass
and attaches every detector's score to each window simultaneously.
"""

from .base import Detector
from .bola import BolaDetector
from .exfil import ExfilDetector

__all__ = ["Detector", "BolaDetector", "ExfilDetector"]

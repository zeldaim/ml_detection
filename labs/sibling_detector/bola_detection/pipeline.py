"""Orchestration: enrich -> window -> compute features, by version.

FEATURE_SETS maps a version string to the ordered feature columns it produces.
v0_edge can run at the edge; v1_hybrid adds the central-only columns.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional

from .schema import AccessLog
from .ownership import OwnershipSource
from .edge_features import EDGE_FEATURE_NAMES, compute_edge_features
from .central_features import (
    CENTRAL_FEATURE_NAMES,
    UserHistory,
    compute_central_features,
)

FEATURE_SETS: Dict[str, List[str]] = {
    "v0_edge": list(EDGE_FEATURE_NAMES),
    "v1_hybrid": list(EDGE_FEATURE_NAMES) + list(CENTRAL_FEATURE_NAMES),
}


def enrich(logs: List[AccessLog], ownership: OwnershipSource) -> None:
    """Central step: join each log against the ownership source in place."""
    for log in logs:
        rec = ownership.resolve(log.object_id, log.object_type)
        if rec is not None:
            log.owner_id = rec.owner_id
            log.owner_tenant_id = rec.tenant_id


def _window_key(ts: float, window_seconds: float) -> float:
    return math.floor(ts / window_seconds) * window_seconds


def build_features(
    logs: List[AccessLog],
    version: str = "v1_hybrid",
    window_seconds: float = 300.0,
    ownership: Optional[OwnershipSource] = None,
) -> List[Dict[str, float]]:
    """Return one feature row per (user_id, window), tagged with ids.

    version='v0_edge'   -> edge-only features, ownership ignored.
    version='v1_hybrid' -> edge + central; requires `ownership`.
    """
    if version not in FEATURE_SETS:
        raise ValueError(f"unknown version {version!r}; choose from {list(FEATURE_SETS)}")

    hybrid = version == "v1_hybrid"
    if hybrid:
        if ownership is None:
            raise ValueError("v1_hybrid requires an ownership source")
        enrich(logs, ownership)

    # Group by (user, tumbling window); process in time order for history.
    groups: Dict[tuple, List[AccessLog]] = {}
    for log in logs:
        key = (log.user_id, _window_key(log.timestamp, window_seconds))
        groups.setdefault(key, []).append(log)

    history = UserHistory()
    rows: List[Dict[str, float]] = []
    for (user_id, win_start) in sorted(groups, key=lambda k: (k[1], k[0])):
        window = groups[(user_id, win_start)]
        row: Dict[str, float] = {"user_id": user_id, "window_start": win_start}
        row.update(compute_edge_features(window, window_seconds))
        if hybrid:
            row.update(compute_central_features(window, user_id, history))
        rows.append(row)
    return rows


def feature_matrix(rows: List[Dict[str, float]], version: str):
    """Extract (X, columns) numeric matrix for the given version."""
    cols = FEATURE_SETS[version]
    X = [[float(r[c]) for c in cols] for r in rows]
    return X, cols

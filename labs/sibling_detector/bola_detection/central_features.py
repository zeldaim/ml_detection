"""Central features: require state the edge doesn't have.

Two kinds of state:
  1. Ownership join  -> owner_mismatch_* , distinct_victim_owners, tenant_mismatch
     (this is the near-label signal: authenticated identity vs DB owner)
  2. Per-user history -> new_object_id_rate, deviation_from_baseline

`UserHistory` is updated as windows are consumed in time order, so each row is
scored against only what was known *before* it (no future leakage).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import sqrt
from typing import Dict, List, Set

from .schema import AccessLog

CENTRAL_FEATURE_NAMES: List[str] = [
    "owner_mismatch_rate",
    "mismatch_then_success_count",
    "distinct_victim_owners",
    "tenant_mismatch_rate",
    "new_object_id_rate",
    "deviation_from_baseline",
]


@dataclass
class _UserState:
    seen_object_ids: Set[str] = field(default_factory=set)
    distinct_history: List[int] = field(default_factory=list)   # distinct_ids per past window


@dataclass
class UserHistory:
    """Mutable per-user memory shared across windows (central side)."""
    _states: Dict[str, _UserState] = field(default_factory=dict)

    def _state(self, user_id: str) -> _UserState:
        return self._states.setdefault(user_id, _UserState())

    def new_id_rate(self, user_id: str, ids: Set[str]) -> float:
        seen = self._state(user_id).seen_object_ids
        if not ids:
            return 0.0
        return sum(1 for i in ids if i not in seen) / len(ids)

    def baseline_z(self, user_id: str, value: int) -> float:
        hist = self._state(user_id).distinct_history
        if len(hist) < 2:
            return 0.0
        mean = sum(hist) / len(hist)
        var = sum((h - mean) ** 2 for h in hist) / len(hist)
        std = sqrt(var)
        return (value - mean) / std if std > 0 else 0.0

    def update(self, user_id: str, ids: Set[str], distinct: int) -> None:
        st = self._state(user_id)
        st.seen_object_ids |= ids
        st.distinct_history.append(distinct)


def compute_central_features(
    window: List[AccessLog],
    user_id: str,
    history: UserHistory,
) -> Dict[str, float]:
    """One central feature row. Call windows in time order per user so that
    history reflects only the past. Updates `history` as a side effect."""
    n = len(window)
    if n == 0:
        return {k: 0.0 for k in CENTRAL_FEATURE_NAMES}

    resolved = [r for r in window if r.is_owner_resolved]
    mismatches = [r for r in resolved if r.is_mismatch]

    owner_mismatch_rate = (len(mismatches) / len(resolved)) if resolved else 0.0
    # The real breach: accessed someone else's object AND got 200 back.
    mismatch_then_success = sum(1 for r in mismatches if r.status_code == 200)
    distinct_victim_owners = len({r.owner_id for r in mismatches})

    tenant_pairs = [
        r for r in window
        if r.user_tenant_id is not None and r.owner_tenant_id is not None
    ]
    tenant_mismatch_rate = (
        sum(1 for r in tenant_pairs if r.user_tenant_id != r.owner_tenant_id)
        / len(tenant_pairs)
    ) if tenant_pairs else 0.0

    ids = {r.object_id for r in window}
    distinct = len(ids)
    new_object_id_rate = history.new_id_rate(user_id, ids)
    deviation_from_baseline = history.baseline_z(user_id, distinct)

    history.update(user_id, ids, distinct)

    return {
        "owner_mismatch_rate": owner_mismatch_rate,
        "mismatch_then_success_count": float(mismatch_then_success),
        "distinct_victim_owners": float(distinct_victim_owners),
        "tenant_mismatch_rate": tenant_mismatch_rate,
        "new_object_id_rate": new_object_id_rate,
        "deviation_from_baseline": deviation_from_baseline,
    }

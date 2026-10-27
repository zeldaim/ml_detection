"""Edge features: computable by an edge agent from local traffic only.

No central DB, no cross-node state. These form version v0 and are the fast
first-filter in the hybrid design. Caveat: if the same user is load-balanced
across edge nodes, distinct/velocity features undercount unless you shard by
user_id (consistent hashing) so one node sees that user's full stream.
"""

from __future__ import annotations

from typing import Dict, List

from .schema import AccessLog

EDGE_FEATURE_NAMES: List[str] = [
    "req_count",
    "distinct_object_ids",
    "sequential_id_ratio",
    "status_4xx_ratio",
    "id_access_velocity",
]


def compute_edge_features(window: List[AccessLog], window_seconds: float) -> Dict[str, float]:
    """One feature row for a single (user, time-window) group of requests."""
    n = len(window)
    if n == 0:
        return {k: 0.0 for k in EDGE_FEATURE_NAMES}

    distinct_ids = len({r.object_id for r in window})

    # 403/404 share — authorization failures mixed in = scan signature.
    bad = sum(1 for r in window if r.status_code in (403, 404))
    status_4xx_ratio = bad / n

    # Sequential-ID ratio: adjacent (by time) numeric ids differing by ±1.
    ordered = sorted(window, key=lambda r: r.timestamp)
    nums = [r.numeric_id for r in ordered]
    pairs = adjacent = 0
    for prev, cur in zip(nums, nums[1:]):
        if prev is None or cur is None:
            continue
        pairs += 1
        if abs(cur - prev) == 1:
            adjacent += 1
    sequential_id_ratio = (adjacent / pairs) if pairs else 0.0

    id_access_velocity = distinct_ids / window_seconds if window_seconds else 0.0

    return {
        "req_count": float(n),
        "distinct_object_ids": float(distinct_ids),
        "sequential_id_ratio": sequential_id_ratio,
        "status_4xx_ratio": status_4xx_ratio,
        "id_access_velocity": id_access_velocity,
    }

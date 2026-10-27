"""Unit tests for feature correctness (run: python -m pytest, or python tests/test_features.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bola_detection.schema import AccessLog, OwnershipRecord
from bola_detection.ownership import InMemoryOwnershipSource
from bola_detection.edge_features import compute_edge_features
from bola_detection.pipeline import build_features


def _log(ts, user, oid, status=200, owner=None):
    return AccessLog(
        request_id=f"r{ts}", timestamp=ts, user_id=user, object_type="dataset",
        object_id=oid, endpoint="/d/{id}", method="GET", status_code=status,
        owner_id=owner,
    )


def test_sequential_ratio_detects_enumeration():
    w = [_log(i, "u", f"obj_{1000 + i}") for i in range(5)]  # 1000..1004
    f = compute_edge_features(w, window_seconds=300)
    assert f["sequential_id_ratio"] == 1.0
    assert f["distinct_object_ids"] == 5


def test_sequential_ratio_low_for_normal():
    w = [_log(0, "u", "obj_1000"), _log(1, "u", "obj_1000"), _log(2, "u", "obj_1007")]
    f = compute_edge_features(w, window_seconds=300)
    assert f["sequential_id_ratio"] == 0.0


def test_status_4xx_ratio():
    w = [_log(0, "u", "obj_1", 200), _log(1, "u", "obj_2", 403), _log(2, "u", "obj_3", 404)]
    f = compute_edge_features(w, window_seconds=300)
    assert abs(f["status_4xx_ratio"] - 2 / 3) < 1e-9


def test_owner_mismatch_and_leak():
    owners = InMemoryOwnershipSource([
        OwnershipRecord("obj_1", "victim"),
        OwnershipRecord("obj_2", "attacker"),
    ])
    logs = [
        _log(0, "attacker", "obj_1", status=200),   # accessed victim's obj, leaked
        _log(1, "attacker", "obj_2", status=200),   # own obj, fine
    ]
    rows = build_features(logs, version="v1_hybrid", ownership=owners, window_seconds=300)
    row = rows[0]
    assert row["owner_mismatch_rate"] == 0.5
    assert row["mismatch_then_success_count"] == 1
    assert row["distinct_victim_owners"] == 1


def test_v0_has_no_central_columns():
    logs = [_log(0, "u", "obj_1000")]
    rows = build_features(logs, version="v0_edge", window_seconds=300)
    assert "owner_mismatch_rate" not in rows[0]
    assert "distinct_object_ids" in rows[0]


def test_registry_runs_siblings_and_attributes():
    from bola_detection.registry import DetectorRegistry
    from bola_detection.detectors import BolaDetector, ExfilDetector

    owners = InMemoryOwnershipSource([
        OwnershipRecord("obj_1", "victim"),
        OwnershipRecord("obj_2", "attacker"),
    ])
    logs = [_log(0, "attacker", "obj_1", status=200), _log(1, "attacker", "obj_2", status=200)]
    reg = DetectorRegistry([BolaDetector(), ExfilDetector()], ownership=owners, window_seconds=300)
    results = reg.fit_score(logs)
    # every window carries every detector's score + an attribution
    assert len(results) == 1
    assert set(results[0].scores) == {"bola", "exfil"}
    assert results[0].top_detector in {"bola", "exfil"}


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")

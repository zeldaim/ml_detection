"""Synthetic traffic so the pipeline runs before real logs/DB exist.

Produces (logs, ownership_source, attacker_ids):
  - normal users: access mostly their OWN small object pool, status 200.
  - attackers:    enumerate IDs across the global space (sequential, fast),
                  hitting objects owned by others -> owner_mismatch, 403/404 mix.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path
from typing import List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bola_detection.schema import AccessLog, OwnershipRecord
from bola_detection.ownership import InMemoryOwnershipSource

OBJ_BASE = 1000
OBJS_PER_USER = 20


def _oid(n: int) -> str:
    return f"obj_{n}"


def generate(
    n_normal: int = 40,
    n_attackers: int = 3,
    seed: int = 7,
) -> Tuple[List[AccessLog], InMemoryOwnershipSource, Set[str]]:
    rng = random.Random(seed)

    users = [f"u{idx:03d}" for idx in range(n_normal)]
    tenants = {u: f"t{idx % 4}" for idx, u in enumerate(users)}

    # Ownership: contiguous id ranges per user (so enumeration crosses owners).
    owners = InMemoryOwnershipSource()
    owner_of = {}
    for ui, u in enumerate(users):
        for k in range(OBJS_PER_USER):
            oid = _oid(OBJ_BASE + ui * OBJS_PER_USER + k)
            owner_of[oid] = u
            owners.put(OwnershipRecord(oid, owner_id=u, tenant_id=tenants[u]))

    total_objs = n_normal * OBJS_PER_USER
    logs: List[AccessLog] = []
    rid = 0

    def add(ts, user, oid, status):
        nonlocal rid
        rid += 1
        logs.append(AccessLog(
            request_id=f"r{rid}", timestamp=ts, user_id=user,
            object_type="dataset", object_id=oid, endpoint="/datasets/{id}",
            method="GET", status_code=status,
            response_size=rng.randint(200, 5000),
            user_tenant_id=tenants.get(user),
        ))

    # Normal traffic: ~60 reqs/user over an hour, own pool, mostly 200.
    for ui, u in enumerate(users):
        own = [_oid(OBJ_BASE + ui * OBJS_PER_USER + k) for k in range(OBJS_PER_USER)]
        for _ in range(rng.randint(45, 75)):
            ts = rng.uniform(0, 3600)
            oid = rng.choice(own)
            status = 200 if rng.random() > 0.03 else 404  # rare typo
            add(ts, u, oid, status)

    # Attack traffic: sequential enumeration burst in a short window.
    attacker_ids: Set[str] = set()
    for a in range(n_attackers):
        atk = f"atk{a:02d}"
        attacker_ids.add(atk)
        atk_tenant = f"t{a % 4}"
        tenants[atk] = atk_tenant
        start_obj = rng.randint(OBJ_BASE, OBJ_BASE + total_objs - 120)
        t0 = rng.uniform(0, 3000)
        for j in range(rng.randint(80, 160)):
            ts = t0 + j * rng.uniform(0.3, 1.2)        # fast, bursty
            oid = _oid(start_obj + j)                   # sequential scan
            owner = owner_of.get(oid)
            if owner == atk:
                status = 200
            else:
                # server sometimes blocks (403), sometimes leaks (200), 404 miss
                status = rng.choices([200, 403, 404], weights=[0.35, 0.45, 0.20])[0]
            add(ts, atk, oid, status)

    return logs, owners, attacker_ids

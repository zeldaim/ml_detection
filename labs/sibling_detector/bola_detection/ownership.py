"""Ownership source abstraction (the 'DB' side of the join).

The central pipeline only needs `resolve(object_id, object_type)` -> owner info.
Swap InMemoryOwnershipSource for an adapter over your real DB model.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Iterable, Optional, Tuple

from .schema import OwnershipRecord


class OwnershipSource(ABC):
    """Resolve the ground-truth owner of an object at request time."""

    @abstractmethod
    def resolve(self, object_id: str, object_type: str) -> Optional[OwnershipRecord]:
        ...


class InMemoryOwnershipSource(OwnershipSource):
    """Dict-backed source for tests / synthetic data / edge cache replica."""

    def __init__(self, records: Iterable[OwnershipRecord] = ()):
        self._by_id: Dict[Tuple[str, str], OwnershipRecord] = {}
        for r in records:
            self.put(r)

    def put(self, record: OwnershipRecord, object_type: str = "*") -> None:
        self._by_id[(object_type, record.object_id)] = record

    def resolve(self, object_id: str, object_type: str) -> Optional[OwnershipRecord]:
        return (
            self._by_id.get((object_type, object_id))
            or self._by_id.get(("*", object_id))
        )


# --- Plug your real DB here --------------------------------------------------
# class SqlOwnershipSource(OwnershipSource):
#     """Adapter over the ownership model you've already built and tested.
#
#     IMPORTANT (temporal correctness): if ownership can change (sharing,
#     transfer), resolve the owner *as of the request timestamp*, not 'now',
#     or you'll get false positives right after a legit transfer.
#     """
#     def __init__(self, session_factory):
#         self._session_factory = session_factory
#
#     def resolve(self, object_id, object_type):
#         with self._session_factory() as s:
#             row = s.query(YourObjectModel.owner_id, YourObjectModel.tenant_id) \
#                    .filter_by(id=object_id, type=object_type).one_or_none()
#             if row is None:
#                 return None
#             return OwnershipRecord(object_id, row.owner_id, row.tenant_id)

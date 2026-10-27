"""Data contracts for the pipeline.

AccessLog is what an edge agent emits per request. Only the top block is
available at the edge; the ownership block is filled by the central side
(by joining against OwnershipSource) and stays None at the edge.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_TRAILING_INT = re.compile(r"(\d+)\s*$")


@dataclass
class AccessLog:
    # --- emitted by the edge agent (gateway authentication context) ---
    request_id: str
    timestamp: float            # epoch seconds
    user_id: str                # authenticated identity from the gateway
    object_type: str            # "dataset" | "model" | "prediction" | ...
    object_id: str              # object referenced in the URL/payload
    endpoint: str
    method: str
    status_code: int
    response_size: int = 0
    user_tenant_id: Optional[str] = None   # may come from a JWT claim (case B)

    # --- filled on the central side by joining OwnershipSource (case D) ---
    owner_id: Optional[str] = None
    owner_tenant_id: Optional[str] = None

    @property
    def numeric_id(self) -> Optional[int]:
        """Trailing integer of object_id, e.g. 'obj_1042' -> 1042."""
        m = _TRAILING_INT.search(self.object_id)
        return int(m.group(1)) if m else None

    @property
    def is_owner_resolved(self) -> bool:
        return self.owner_id is not None

    @property
    def is_mismatch(self) -> bool:
        """Requester is not the object's owner (requires central enrichment)."""
        return self.owner_id is not None and self.user_id != self.owner_id


@dataclass
class OwnershipRecord:
    object_id: str
    owner_id: str
    tenant_id: Optional[str] = None

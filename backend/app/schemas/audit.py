"""Pydantic schemas for the Audit Log API."""

from datetime import datetime
from typing import Any, Optional
import uuid
from pydantic import BaseModel, ConfigDict


class AuditLogResponse(BaseModel):
    """Public representation of an immutable audit record."""

    id: uuid.UUID
    event_type: str
    actor_id: Optional[uuid.UUID] = None
    actor_role: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    decision: Optional[str] = None
    event_data: dict[str, Any]
    previous_hash: str
    event_hash: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogListResponse(BaseModel):
    """Paginated list envelope for audit log queries."""

    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


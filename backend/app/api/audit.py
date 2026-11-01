"""Audit history API endpoints providing tamper-evident log inspection for administrators."""

from datetime import datetime
import math
from typing import Optional
import uuid
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.permissions import require_admin
from app.database.session import get_db
from app.models.user import User
from app.schemas.audit import AuditLogListResponse, AuditLogResponse
from app.services.audit_service import get_audit_logs

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get(
    "",
    response_model=AuditLogListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Audit Logs",
    description="Retrieves a paginated list of cryptographically chained audit events. Restricted to administrators.",
)
async def list_audit_history(
    page: int = Query(1, ge=1, description="Page number starting at 1"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page (max 100)"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    actor_id: Optional[uuid.UUID] = Query(None, description="Filter by actor UUID"),
    start_date: Optional[datetime] = Query(None, description="Filter from timestamp"),
    end_date: Optional[datetime] = Query(None, description="Filter until timestamp"),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> AuditLogListResponse:
    """Returns tamper-evident audit history. Strictly read-only; no modification/deletion supported."""
    items, total = await get_audit_logs(
        session=db,
        page=page,
        page_size=page_size,
        event_type=event_type,
        actor_id=actor_id,
        start_date=start_date,
        end_date=end_date,
    )

    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


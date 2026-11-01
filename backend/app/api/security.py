"""Security policy check API endpoints for pre-flight authorization checks."""

import logging
from fastapi import APIRouter, Depends, status
from app.core.permissions import get_current_user
from app.models.user import User
from app.security.gateway import authorize_action
from app.security.schemas import AuthorizationDecision, SecurityCheckRequest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/security", tags=["Security Gateway"])


@router.post(
    "/check",
    response_model=AuthorizationDecision,
    status_code=status.HTTP_200_OK,
    summary="Evaluate Operational Authorization",
    description="Evaluates whether an authenticated user is permitted to perform a security action via OPA.",
)
async def check_security_authorization(
    payload: SecurityCheckRequest,
    current_user: User = Depends(get_current_user),
) -> AuthorizationDecision:
    """Pre-flight authorization check. Does not execute the action."""
    return await authorize_action(
        user=current_user,
        operation=payload.operation,
        capability=payload.capability,
        resource_type=payload.resource_type,
        resource_id=payload.resource_id,
        environment=payload.environment,
        risk_level=payload.risk_level,
        approval_status=payload.approval_status,
    )


"""FastAPI router for Email Gateway integration endpoints.

Enforces OPA attribute-based authorization, strict Pydantic payload validation,
test-mode recipient allowlisting, and cryptographic SHA-256 audit tracking.
"""

import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.permissions import get_current_user
from app.database.session import get_db
from app.integrations.email.schemas import (
    EmailDeliveryRequest,
    EmailDeliveryResponse,
    EmailStatusResponse,
    EmailTemplateInfo,
)
from app.integrations.email.service import email_service
from app.models.user import User
from app.security.gateway import authorize_action

logger = logging.getLogger("aegismesh.api.integrations_email")

router = APIRouter(prefix="/integrations/email", tags=["Integrations - Email"])


@router.get(
    "/templates",
    response_model=List[EmailTemplateInfo],
    summary="List Approved Email Templates",
    description="Returns catalog of strictly approved transactional security email templates.",
)
async def list_templates(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> List[EmailTemplateInfo]:
    """Retrieves catalog of approved transactional email templates."""
    decision = await authorize_action(
        user=current_user,
        operation="email.template_list",
        capability="read",
        resource_type="email_template",
        resource_id="catalog",
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    return email_service.list_approved_templates()


@router.get(
    "/status",
    response_model=EmailStatusResponse,
    summary="Email Gateway Health & Configuration Status",
    description="Returns provider status, active mode, and allowlisted recipient count. Secrets are never exposed.",
)
async def get_gateway_status(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> EmailStatusResponse:
    """Returns the operational status of the transactional email gateway."""
    decision = await authorize_action(
        user=current_user,
        operation="email.delivery_read",
        capability="read",
        resource_type="email_gateway",
        resource_id="status",
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    return await email_service.get_gateway_status()


@router.post(
    "/test",
    response_model=EmailDeliveryResponse,
    status_code=status.HTTP_200_OK,
    summary="Test Email Delivery Probe",
    description=(
        "Validates authorization, approved template schema, configured sender, and allowlisted recipient. "
        "Under Step 10.1 test mode, records simulated delivery acceptance without contacting external provider."
    ),
)
async def test_email_delivery(
    request: EmailDeliveryRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> EmailDeliveryResponse:
    """Validates and simulates test email delivery within the Step 10.1 security boundary."""
    # 1. Evaluate OPA policy
    decision = await authorize_action(
        user=current_user,
        operation="email.delivery_request",
        capability="execute",
        resource_type="email_gateway",
        resource_id="test_delivery",
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    # 2. Process delivery request through email integration service
    return await email_service.process_delivery_request(
        request=request,
        user=current_user,
        session=session,
    )

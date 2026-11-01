"""API endpoints for managing and inspecting Sandbox environments."""

import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import get_current_user, require_roles
from app.database.session import get_db
from app.models.user import User, UserRole
from app.schemas.sandbox import (
    SandboxDetailResponse,
    SandboxResponse,
    SandboxSeedResponse,
    SyntheticAssetResponse,
)
from app.services.sandbox_service import (
    get_sandbox_by_id,
    list_assets_in_sandbox,
    list_sandboxes,
    verify_sandbox_access,
)
from app.services.synthetic_generator import DEMO_ASSET_DEFINITIONS, initialize_demo_sandbox

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/sandboxes", tags=["Sandbox Environments"])


@router.get(
    "",
    response_model=list[SandboxResponse],
    status_code=status.HTTP_200_OK,
    summary="List Sandbox Environments",
    include_in_schema=False,
)
@router.get(
    "/",
    response_model=list[SandboxResponse],
    status_code=status.HTTP_200_OK,
    summary="List Sandbox Environments",
    description="Retrieves a paginated list of registered sandbox environments.",
)
async def get_sandboxes(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[SandboxResponse]:
    """Lists available sandbox environments filtered by caller authorization."""
    sandboxes = await list_sandboxes(session=db, skip=skip, limit=limit, user=current_user)
    return [SandboxResponse.model_validate(s) for s in sandboxes]


@router.get(
    "/{sandbox_id}",
    response_model=SandboxDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Sandbox Environment Details",
    description="Retrieves configuration and asset count for a specific sandbox environment.",
)
async def get_sandbox(
    sandbox_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SandboxDetailResponse:
    """Retrieves detailed sandbox metadata and synthetic asset count with authorization check."""
    sandbox = await get_sandbox_by_id(session=db, sandbox_id=sandbox_id)
    if not sandbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sandbox '{sandbox_id}' not found.",
        )

    if not verify_sandbox_access(sandbox, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: You do not have permission to access sandbox '{sandbox_id}'.",
        )

    assets = await list_assets_in_sandbox(session=db, sandbox_id=sandbox.id, limit=100)
    response_data = SandboxDetailResponse.model_validate(sandbox)
    response_data.asset_count = len(assets)
    return response_data


@router.get(
    "/{sandbox_id}/assets",
    response_model=list[SyntheticAssetResponse],
    status_code=status.HTTP_200_OK,
    summary="List Assets in Sandbox",
    description="Retrieves synthetic assets residing in a specific sandbox environment.",
)
async def get_sandbox_assets(
    sandbox_id: uuid.UUID,
    asset_type: Optional[str] = None,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[SyntheticAssetResponse]:
    """Retrieves all synthetic assets registered in a sandbox."""
    sandbox = await get_sandbox_by_id(session=db, sandbox_id=sandbox_id)
    if not sandbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sandbox '{sandbox_id}' not found.",
        )

    if not verify_sandbox_access(sandbox, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: You do not have permission to access sandbox '{sandbox_id}'.",
        )

    assets = await list_assets_in_sandbox(
        session=db,
        sandbox_id=sandbox.id,
        asset_type=asset_type,
        skip=skip,
        limit=limit,
    )
    return [SyntheticAssetResponse.model_validate(a) for a in assets]



@router.post(
    "/seed",
    response_model=SandboxSeedResponse,
    status_code=status.HTTP_200_OK,
    summary="Initialize Demo Synthetic Sandbox Assets",
    description="Idempotently populates the demo enterprise sandbox with 10 synthetic assets.",
)
async def seed_demo_sandbox(
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.SECURITY_OPERATOR)),
    db: AsyncSession = Depends(get_db),
) -> SandboxSeedResponse:
    """Idempotently seeds the demo enterprise environment."""
    sandbox = await initialize_demo_sandbox(session=db)
    return SandboxSeedResponse(
        sandbox_id=sandbox.id,
        name=sandbox.name,
        status=sandbox.status,
        seeded_assets_count=len(DEMO_ASSET_DEFINITIONS),
        message="Demo synthetic sandbox assets initialized successfully.",
    )

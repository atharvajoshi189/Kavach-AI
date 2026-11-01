"""Target Agent Service for AegisMesh 2.0.

Provides controlled, read-only inspection of synthetic assets inside an assigned
sandbox environment. Strictly enforces sandbox isolation boundaries, rejecting any
cross-sandbox or unauthorized asset access.
"""

import logging
from typing import Any, Optional
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.services.sandbox_service import (
    get_asset_in_sandbox,
    get_sandbox_by_id,
    list_assets_in_sandbox,
    verify_sandbox_access,
)

logger = logging.getLogger("aegismesh.services.target_agent")


async def discover_sandbox_assets(
    session: AsyncSession,
    sandbox_id: uuid.UUID,
    asset_type: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    user: Optional[User] = None,
) -> dict[str, Any]:
    """Discovers synthetic assets registered within the target agent's assigned sandbox.

    Enforces:
    - Sandbox existence verification.
    - Caller authorization and assignment verification.
    - Rejection of archived sandbox environments.
    """
    sandbox = await get_sandbox_by_id(session, sandbox_id)
    if not sandbox:
        return {
            "found": False,
            "error": "Assigned sandbox environment not found.",
            "sandbox_id": str(sandbox_id),
            "assets": [],
            "count": 0,
        }

    if user is not None and not verify_sandbox_access(sandbox, user):
        logger.warning(
            "Unauthorized sandbox discovery attempt by user '%s' (%s) on sandbox '%s'",
            user.username,
            user.id,
            sandbox.id,
        )
        return {
            "found": False,
            "error": "Access denied: caller is not authorized to access this sandbox.",
            "sandbox_id": str(sandbox_id),
            "assets": [],
            "count": 0,
        }

    if sandbox.status == "archived":
        return {
            "found": False,
            "error": "Sandbox environment is archived. Target operations cannot be performed on archived environments.",
            "sandbox_id": str(sandbox_id),
            "assets": [],
            "count": 0,
        }

    assets = await list_assets_in_sandbox(
        session=session,
        sandbox_id=sandbox_id,
        asset_type=asset_type,
        skip=skip,
        limit=limit,
    )

    return {
        "found": True,
        "sandbox_id": str(sandbox.id),
        "sandbox_name": sandbox.name,
        "isolation_mode": sandbox.isolation_mode,
        "count": len(assets),
        "assets": [
            {
                "id": str(a.id),
                "name": a.name,
                "asset_type": a.asset_type,
                "status": a.status,
                "hostname": a.hostname,
                "ip_address": a.ip_address,
                "risk_level": a.risk_level,
                "environment": a.environment,
                "sandbox_id": str(a.sandbox_id),
            }
            for a in assets
        ],
    }


async def inspect_synthetic_asset(
    session: AsyncSession,
    sandbox_id: uuid.UUID,
    asset_id: uuid.UUID,
    user: Optional[User] = None,
) -> dict[str, Any]:
    """Inspects metadata, services, and connections for an asset within its assigned sandbox.

    Enforces:
    - Sandbox existence verification.
    - Caller authorization and assignment verification.
    - Rejection of archived sandbox environments.
    - Strict cross-sandbox boundary validation.
    """
    sandbox = await get_sandbox_by_id(session, sandbox_id)
    if not sandbox:
        return {
            "found": False,
            "error": "Assigned sandbox environment not found.",
            "sandbox_id": str(sandbox_id),
            "asset_id": str(asset_id),
        }

    if user is not None and not verify_sandbox_access(sandbox, user):
        logger.warning(
            "Unauthorized asset inspection attempt by user '%s' (%s) on sandbox '%s'",
            user.username,
            user.id,
            sandbox.id,
        )
        return {
            "found": False,
            "error": "Access denied: caller is not authorized to access this sandbox.",
            "sandbox_id": str(sandbox_id),
            "asset_id": str(asset_id),
        }

    if sandbox.status == "archived":
        return {
            "found": False,
            "error": "Sandbox environment is archived. Target operations cannot be performed on archived environments.",
            "sandbox_id": str(sandbox_id),
            "asset_id": str(asset_id),
        }

    asset = await get_asset_in_sandbox(session, sandbox_id=sandbox_id, asset_id=asset_id)
    if not asset:
        return {
            "found": False,
            "error": "Asset not found in the specified sandbox environment.",
            "sandbox_id": str(sandbox_id),
            "asset_id": str(asset_id),
        }

    return {
        "found": True,
        "asset": {
            "id": str(asset.id),
            "sandbox_id": str(asset.sandbox_id),
            "name": asset.name,
            "asset_type": asset.asset_type,
            "description": asset.description,
            "environment": asset.environment,
            "status": asset.status,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "os_metadata": asset.os_metadata,
            "service_metadata": asset.service_metadata,
            "configuration": asset.configuration,
            "risk_level": asset.risk_level,
            "connected_asset_ids": asset.connected_asset_ids,
            "simulated_findings_count": len(asset.simulated_vulnerabilities),
            "created_at": asset.created_at.isoformat(),
            "updated_at": asset.updated_at.isoformat(),
        },
    }


async def get_simulated_findings(
    session: AsyncSession,
    sandbox_id: uuid.UUID,
    asset_id: uuid.UUID,
    severity: Optional[str] = None,
    user: Optional[User] = None,
) -> dict[str, Any]:
    """Retrieves simulated vulnerability findings for a synthetic asset.

    Enforces:
    - Sandbox existence verification.
    - Caller authorization and assignment verification.
    - Rejection of archived sandbox environments.
    - Strict cross-sandbox boundary validation.
    """
    sandbox = await get_sandbox_by_id(session, sandbox_id)
    if not sandbox:
        return {
            "found": False,
            "error": "Assigned sandbox environment not found.",
            "sandbox_id": str(sandbox_id),
            "asset_id": str(asset_id),
            "findings": [],
            "count": 0,
        }

    if user is not None and not verify_sandbox_access(sandbox, user):
        logger.warning(
            "Unauthorized findings access attempt by user '%s' (%s) on sandbox '%s'",
            user.username,
            user.id,
            sandbox.id,
        )
        return {
            "found": False,
            "error": "Access denied: caller is not authorized to access this sandbox.",
            "sandbox_id": str(sandbox_id),
            "asset_id": str(asset_id),
            "findings": [],
            "count": 0,
        }

    if sandbox.status == "archived":
        return {
            "found": False,
            "error": "Sandbox environment is archived. Target operations cannot be performed on archived environments.",
            "sandbox_id": str(sandbox_id),
            "asset_id": str(asset_id),
            "findings": [],
            "count": 0,
        }

    asset = await get_asset_in_sandbox(session, sandbox_id=sandbox_id, asset_id=asset_id)
    if not asset:
        return {
            "found": False,
            "error": "Asset not found in the specified sandbox environment.",
            "sandbox_id": str(sandbox_id),
            "asset_id": str(asset_id),
            "findings": [],
            "count": 0,
        }

    findings = list(asset.simulated_vulnerabilities)
    if severity:
        target_sev = severity.strip().lower()
        findings = [f for f in findings if f.get("severity", "").lower() == target_sev]

    return {
        "found": True,
        "asset_id": str(asset.id),
        "asset_name": asset.name,
        "sandbox_id": str(asset.sandbox_id),
        "is_simulated_environment": True,
        "count": len(findings),
        "findings": findings,
    }


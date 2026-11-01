"""Target Agent synthetic asset inspection MCP tools."""

import logging
from typing import Any, Optional
import uuid

from mcp.server.mcpserver import Context

from app.mcp.context import mcp_security_context
from app.services.target_agent_service import (
    discover_sandbox_assets,
    get_simulated_findings,
    inspect_synthetic_asset,
)

logger = logging.getLogger("aegismesh.mcp.tools.target")


async def target_list_assets(
    ctx: Context,
    sandbox_id: str,
    asset_type: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """Lists synthetic target assets within an assigned sandbox environment.

    Supports optional asset_type filtering (server, database, web_application, api, network_device).
    Guarantees zero access to host machine or real networks.
    """
    safe_page = max(1, page)
    safe_page_size = max(1, min(page_size, 100))
    skip = (safe_page - 1) * safe_page_size

    try:
        sb_uuid = uuid.UUID(str(sandbox_id).strip())
    except ValueError:
        return {
            "found": False,
            "error": "Malformed sandbox UUID.",
            "sandbox_id": str(sandbox_id),
            "assets": [],
            "count": 0,
        }

    async with mcp_security_context(
        tool_name="target_list_assets",
        resource_type="synthetic_asset",
        resource_id=str(sb_uuid),
        mcp_ctx=ctx,
        input_metadata={"sandbox_id": str(sb_uuid), "asset_type": asset_type, "page": safe_page, "page_size": safe_page_size},
    ) as sec_ctx:
        return await discover_sandbox_assets(
            session=sec_ctx.session,
            sandbox_id=sb_uuid,
            asset_type=asset_type,
            skip=skip,
            limit=safe_page_size,
            user=sec_ctx.user,
        )


async def target_inspect_asset(
    ctx: Context,
    sandbox_id: str,
    asset_id: str,
) -> dict[str, Any]:
    """Inspects detailed metadata, OS details, services, and connections for a synthetic asset.

    Strictly denies cross-sandbox access if the asset belongs to a different sandbox.
    """
    try:
        sb_uuid = uuid.UUID(str(sandbox_id).strip())
    except ValueError:
        return {
            "found": False,
            "error": "Malformed sandbox UUID.",
            "sandbox_id": str(sandbox_id),
            "asset_id": str(asset_id),
        }

    try:
        asset_uuid = uuid.UUID(str(asset_id).strip())
    except ValueError:
        return {
            "found": False,
            "error": "Malformed asset UUID.",
            "sandbox_id": str(sandbox_id),
            "asset_id": str(asset_id),
        }

    async with mcp_security_context(
        tool_name="target_inspect_asset",
        resource_type="synthetic_asset",
        resource_id=str(asset_uuid),
        mcp_ctx=ctx,
        input_metadata={"sandbox_id": str(sb_uuid), "asset_id": str(asset_uuid)},
    ) as sec_ctx:
        return await inspect_synthetic_asset(
            session=sec_ctx.session,
            sandbox_id=sb_uuid,
            asset_id=asset_uuid,
            user=sec_ctx.user,
        )


async def target_get_simulated_findings(
    ctx: Context,
    sandbox_id: str,
    asset_id: str,
    severity: Optional[str] = None,
) -> dict[str, Any]:
    """Retrieves simulated vulnerability findings for a synthetic asset within its assigned sandbox.

    Findings are fictional and explicitly flagged as simulated. No real scans or exploits exist.
    """
    try:
        sb_uuid = uuid.UUID(str(sandbox_id).strip())
    except ValueError:
        return {
            "found": False,
            "error": "Malformed sandbox UUID.",
            "sandbox_id": str(sandbox_id),
            "asset_id": str(asset_id),
            "findings": [],
            "count": 0,
        }

    try:
        asset_uuid = uuid.UUID(str(asset_id).strip())
    except ValueError:
        return {
            "found": False,
            "error": "Malformed asset UUID.",
            "sandbox_id": str(sandbox_id),
            "asset_id": str(asset_id),
            "findings": [],
            "count": 0,
        }

    async with mcp_security_context(
        tool_name="target_get_simulated_findings",
        resource_type="synthetic_asset",
        resource_id=str(asset_uuid),
        mcp_ctx=ctx,
        input_metadata={"sandbox_id": str(sb_uuid), "asset_id": str(asset_uuid), "severity": severity},
    ) as sec_ctx:
        return await get_simulated_findings(
            session=sec_ctx.session,
            sandbox_id=sb_uuid,
            asset_id=asset_uuid,
            severity=severity,
            user=sec_ctx.user,
        )


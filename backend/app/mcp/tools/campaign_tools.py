"""Campaign inspection and status MCP tools."""

import logging
from typing import Any, Optional
import uuid

from mcp.server.mcpserver import Context

from app.mcp.context import mcp_security_context
from app.services.campaign_service import get_campaign_by_id, list_campaigns as svc_list_campaigns

logger = logging.getLogger("aegismesh.mcp.tools.campaigns")


async def list_campaigns(
    ctx: Context,
    page: int = 1,
    page_size: int = 50,
    environment: Optional[str] = None,
    status: Optional[str] = None,
) -> dict[str, Any]:
    """Retrieves a paginated list of security campaigns.

    Supports optional filtering by operational environment and execution status. Read-only.
    """
    safe_page = max(1, page)
    safe_page_size = max(1, min(page_size, 100))
    skip = (safe_page - 1) * safe_page_size

    async with mcp_security_context(
        tool_name="list_campaigns",
        resource_type="campaign",
        mcp_ctx=ctx,
        input_metadata={"page": safe_page, "page_size": safe_page_size, "environment": environment, "status": status},
    ) as sec_ctx:
        campaigns = await svc_list_campaigns(
            session=sec_ctx.session,
            environment=environment,
            status=status,
            skip=skip,
            limit=safe_page_size,
        )

        return {
            "page": safe_page,
            "page_size": safe_page_size,
            "count": len(campaigns),
            "campaigns": [
                {
                    "id": str(c.id),
                    "name": c.name,
                    "agent_id": str(c.agent_id) if c.agent_id else None,
                    "trigger_type": c.trigger_type,
                    "status": c.status,
                    "environment": c.environment,
                    "started_at": c.started_at.isoformat() if c.started_at else None,
                    "completed_at": c.completed_at.isoformat() if c.completed_at else None,
                    "created_at": c.created_at.isoformat(),
                }
                for c in campaigns
            ],
        }


async def get_campaign(
    ctx: Context,
    campaign_id: str,
) -> dict[str, Any]:
    """Retrieves operational details for a specific campaign by UUID.

    Returns structured not-found response if the campaign does not exist. Read-only.
    """
    try:
        camp_uuid = uuid.UUID(str(campaign_id).strip())
    except ValueError:
        return {
            "found": False,
            "error": "Malformed campaign UUID.",
            "campaign_id": str(campaign_id),
        }

    async with mcp_security_context(
        tool_name="get_campaign",
        resource_type="campaign",
        mcp_ctx=ctx,
        resource_id=str(camp_uuid),
    ) as sec_ctx:
        campaign = await get_campaign_by_id(session=sec_ctx.session, campaign_id=camp_uuid)

        if not campaign:
            return {
                "found": False,
                "error": "Campaign not found.",
                "campaign_id": str(camp_uuid),
            }

        return {
            "found": True,
            "campaign": {
                "id": str(campaign.id),
                "name": campaign.name,
                "agent_id": str(campaign.agent_id) if campaign.agent_id else None,
                "trigger_type": campaign.trigger_type,
                "status": campaign.status,
                "environment": campaign.environment,
                "configuration": campaign.configuration,
                "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
                "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
                "created_at": campaign.created_at.isoformat(),
            },
        }

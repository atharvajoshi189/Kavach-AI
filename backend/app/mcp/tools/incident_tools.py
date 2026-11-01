"""Security incident inspection MCP tools."""

import logging
from typing import Any, Optional
import uuid

from mcp.server.mcpserver import Context

from app.mcp.context import mcp_security_context
from app.services.incident_service import get_incident_by_id, list_incidents as svc_list_incidents

logger = logging.getLogger("aegismesh.mcp.tools.incidents")


async def list_incidents(
    ctx: Context,
    page: int = 1,
    page_size: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
) -> dict[str, Any]:
    """Retrieves a paginated list of security incidents.

    Supports optional severity and status filters. Read-only.
    """
    safe_page = max(1, page)
    safe_page_size = max(1, min(page_size, 100))
    skip = (safe_page - 1) * safe_page_size

    async with mcp_security_context(
        tool_name="list_incidents",
        resource_type="incident",
        mcp_ctx=ctx,
        input_metadata={"page": safe_page, "page_size": safe_page_size, "severity": severity, "status": status},
    ) as sec_ctx:
        incidents = await svc_list_incidents(
            session=sec_ctx.session,
            severity=severity,
            status=status,
            skip=skip,
            limit=safe_page_size,
        )

        return {
            "page": safe_page,
            "page_size": safe_page_size,
            "count": len(incidents),
            "incidents": [
                {
                    "id": str(inc.id),
                    "title": inc.title,
                    "severity": inc.severity,
                    "status": inc.status,
                    "source": inc.source,
                    "campaign_id": str(inc.campaign_id) if inc.campaign_id else None,
                    "created_at": inc.created_at.isoformat(),
                    "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
                }
                for inc in incidents
            ],
        }


async def get_incident(
    ctx: Context,
    incident_id: str,
) -> dict[str, Any]:
    """Retrieves detailed information for a specific security incident by UUID.

    Returns structured not-found response if the incident does not exist. Read-only.
    """
    try:
        inc_uuid = uuid.UUID(str(incident_id).strip())
    except ValueError:
        return {
            "found": False,
            "error": "Malformed incident UUID.",
            "incident_id": str(incident_id),
        }

    async with mcp_security_context(
        tool_name="get_incident",
        resource_type="incident",
        mcp_ctx=ctx,
        resource_id=str(inc_uuid),
    ) as sec_ctx:
        incident = await get_incident_by_id(session=sec_ctx.session, incident_id=inc_uuid)

        if not incident:
            return {
                "found": False,
                "error": "Incident not found.",
                "incident_id": str(inc_uuid),
            }

        return {
            "found": True,
            "incident": {
                "id": str(incident.id),
                "title": incident.title,
                "description": incident.description,
                "severity": incident.severity,
                "status": incident.status,
                "source": incident.source,
                "campaign_id": str(incident.campaign_id) if incident.campaign_id else None,
                "created_at": incident.created_at.isoformat(),
                "updated_at": incident.updated_at.isoformat(),
                "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            },
        }

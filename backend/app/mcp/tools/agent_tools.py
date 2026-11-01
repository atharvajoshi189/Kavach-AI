"""Autonomous Agent inspection MCP tools."""

import logging
from typing import Any, Optional
import uuid

from mcp.server.mcpserver import Context

from app.mcp.context import mcp_security_context
from app.services.agent_service import get_agent_by_id, list_agents as svc_list_agents

logger = logging.getLogger("aegismesh.mcp.tools.agents")


async def list_agents(
    ctx: Context,
    page: int = 1,
    page_size: int = 50,
    environment: Optional[str] = None,
    status: Optional[str] = None,
) -> dict[str, Any]:
    """Retrieves a paginated list of registered autonomous agents.

    Supports optional environment and status filtering. Read-only.
    """
    safe_page = max(1, page)
    safe_page_size = max(1, min(page_size, 100))
    skip = (safe_page - 1) * safe_page_size

    async with mcp_security_context(
        tool_name="list_agents",
        resource_type="agent",
        mcp_ctx=ctx,
        input_metadata={"page": safe_page, "page_size": safe_page_size, "environment": environment, "status": status},
    ) as sec_ctx:
        agents = await svc_list_agents(
            session=sec_ctx.session,
            environment=environment,
            status=status,
            skip=skip,
            limit=safe_page_size,
        )

        return {
            "page": safe_page,
            "page_size": safe_page_size,
            "count": len(agents),
            "agents": [
                {
                    "id": str(a.id),
                    "name": a.name,
                    "agent_type": a.agent_type,
                    "description": a.description,
                    "status": a.status,
                    "environment": a.environment,
                    "created_at": a.created_at.isoformat(),
                }
                for a in agents
            ],
        }


async def get_agent(
    ctx: Context,
    agent_id: str,
) -> dict[str, Any]:
    """Retrieves details of a specific agent by UUID.

    Returns structured not-found response if the agent does not exist. Read-only.
    """
    try:
        agent_uuid = uuid.UUID(str(agent_id).strip())
    except ValueError:
        return {
            "found": False,
            "error": "Malformed agent UUID.",
            "agent_id": str(agent_id),
        }

    async with mcp_security_context(
        tool_name="get_agent",
        resource_type="agent",
        mcp_ctx=ctx,
        resource_id=str(agent_uuid),
    ) as sec_ctx:
        agent = await get_agent_by_id(session=sec_ctx.session, agent_id=agent_uuid)

        if not agent:
            return {
                "found": False,
                "error": "Agent not found.",
                "agent_id": str(agent_uuid),
            }

        return {
            "found": True,
            "agent": {
                "id": str(agent.id),
                "name": agent.name,
                "agent_type": agent.agent_type,
                "description": agent.description,
                "capabilities": agent.capabilities,
                "status": agent.status,
                "environment": agent.environment,
                "created_at": agent.created_at.isoformat(),
                "updated_at": agent.updated_at.isoformat(),
            },
        }

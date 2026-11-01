"""System health and diagnostic MCP tools."""

from datetime import datetime, timezone
import logging
from typing import Any

import httpx
from mcp.server.mcpserver import Context
from sqlalchemy import text

from app.core.config import settings
from app.core.redis import redis_client
from app.mcp.context import mcp_security_context

logger = logging.getLogger("aegismesh.mcp.tools.system")


async def system_health(ctx: Context) -> dict[str, Any]:
    """Inspects backend service connectivity and operational readiness.

    Verifies PostgreSQL, Redis, and OPA connectivity without disclosing credentials,
    hostnames, or internal connection strings. Requires valid HTTP Bearer authorization.
    """
    async with mcp_security_context(
        tool_name="system_health",
        resource_type="system",
        mcp_ctx=ctx,
    ) as sec_ctx:
        db_status = "down"
        redis_status = "down"
        opa_status = "down"

        # 1. Database ping
        try:
            await sec_ctx.session.execute(text("SELECT 1;"))
            db_status = "up"
        except Exception as e:
            logger.error("System health check database error: %s", e)

        # 2. Redis ping
        try:
            if await redis_client.ping():
                redis_status = "up"
        except Exception as e:
            logger.error("System health check Redis error: %s", e)

        # 3. OPA ping
        try:
            async with httpx.AsyncClient(timeout=2.0) as http_client:
                resp = await http_client.get(f"{settings.OPA_URL}/health")
                if resp.status_code == 200:
                    opa_status = "up"
        except Exception as e:
            logger.error("System health check OPA error: %s", e)

        overall = "healthy" if db_status == "up" and redis_status == "up" and opa_status == "up" else "degraded"

        return {
            "status": overall,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "services": {
                "database": db_status,
                "redis": redis_status,
                "policy_engine": opa_status,
            },
        }

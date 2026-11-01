"""Authorization layer for AegisMesh MCP server integrating with the Security Gateway."""

import logging
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import User
from app.security.gateway import authorize_action
from app.security.schemas import AuthorizationDecision

logger = logging.getLogger("aegismesh.mcp.authz")


class MCPAuthorizationError(Exception):
    """Raised when an action is denied by OPA policy or the Security Gateway."""
    pass


async def authorize_mcp_action(
    user: User,
    tool_name: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    environment: str = "sandbox",
    session: Optional[AsyncSession] = None,
) -> AuthorizationDecision:
    """Enforces policy evaluation via OPA Security Gateway and persists audit records.

    Fails closed if OPA evaluates to deny, if OPA is unreachable, or if audit persistence fails.
    """
    operation_name = f"mcp.{tool_name}"

    try:
        decision = await authorize_action(
            user=user,
            operation=operation_name,
            capability="read",
            resource_type=resource_type,
            resource_id=resource_id or "all",
            environment=environment,
            session=session,
        )
    except Exception as e:
        logger.warning("Security Gateway evaluation error for MCP tool '%s': %s", tool_name, e)
        raise MCPAuthorizationError(f"Authorization check failed: {e}") from e

    if not decision.allowed:
        logger.warning(
            "Access denied by policy for user '%s' on tool '%s': %s",
            user.username,
            tool_name,
            decision.reason,
        )
        raise MCPAuthorizationError(f"Permission denied: {decision.reason}")

    return decision


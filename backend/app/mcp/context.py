"""Context manager for executing authenticated and authorized MCP tool requests."""

from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
import logging
from typing import Any, Optional

from mcp.server.mcpserver import Context
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import AsyncSessionLocal
from app.mcp.security.authentication import (
    AegisMeshAuthenticatedUser,
    authenticate_token,
    extract_bearer_token,
)
from app.mcp.security.authorization import authorize_mcp_action
from app.models.user import User
from app.services.audit_service import record_audit_log

logger = logging.getLogger("aegismesh.mcp.context")


class MCPExecutionContext:
    """Carries trusted caller identity and active database session throughout tool execution."""

    def __init__(
        self,
        user: User,
        session: AsyncSession,
        tool_name: str,
        resource_type: str,
    ):
        self.user = user
        self.session = session
        self.tool_name = tool_name
        self.resource_type = resource_type


def _extract_request_headers(
    mcp_ctx: Optional[Context] = None,
    headers: Optional[Mapping[str, str]] = None,
) -> Optional[Mapping[str, str]]:
    """Extracts HTTP headers from either an MCP Context or an explicit headers mapping."""
    if headers is not None:
        return headers
    if mcp_ctx is not None:
        if hasattr(mcp_ctx, "headers") and mcp_ctx.headers:
            return mcp_ctx.headers
        if (
            hasattr(mcp_ctx, "request_context")
            and mcp_ctx.request_context is not None
            and hasattr(mcp_ctx.request_context, "request")
            and hasattr(mcp_ctx.request_context.request, "headers")
        ):
            return mcp_ctx.request_context.request.headers
    return None


@asynccontextmanager
async def mcp_security_context(
    tool_name: str,
    resource_type: str,
    mcp_ctx: Optional[Context] = None,
    headers: Optional[Mapping[str, str]] = None,
    resource_id: Optional[str] = None,
    environment: str = "sandbox",
    session: Optional[AsyncSession] = None,
    input_metadata: Optional[dict[str, Any]] = None,
) -> AsyncGenerator[MCPExecutionContext, None]:
    """Establishes security envelope: authenticates caller via HTTP header, authorizes via OPA, and audits.

    Sequence:
    1. Resolve verified identity from transport authentication state (or verify Bearer token without duplication).
    2. Authorize action against OPA Security Gateway.
    3. Yield execution context to the tool handler.
    4. Persist tamper-evident audit record in PostgreSQL with SHA-256 hash chaining.

    Fails closed if authentication, authorization, or audit persistence fails.
    """
    owns_session = session is None
    db_session = session if session is not None else AsyncSessionLocal()

    try:
        # 1. Resolve verified identity from transport layer (avoiding duplicate JWT decode/Redis/DB queries)
        trusted_user: Optional[User] = None
        if mcp_ctx is not None and mcp_ctx.request_context is not None:
            req = getattr(mcp_ctx.request_context, "request", None)
            auth_user = getattr(req, "user", None)
            if (
                isinstance(auth_user, AegisMeshAuthenticatedUser)
                and auth_user.is_authenticated
                and auth_user.db_user is not None
            ):
                trusted_user = auth_user.db_user

        if trusted_user is None:
            # Fallback or explicit verification (when called directly in unit tests or when middleware unverified)
            req_headers = _extract_request_headers(mcp_ctx=mcp_ctx, headers=headers)
            token = extract_bearer_token(req_headers)
            trusted_user = await authenticate_token(token, db_session)

        user = trusted_user

        # 2. Authorize action against OPA Security Gateway and persist gateway decision audit
        await authorize_mcp_action(
            user=user,
            tool_name=tool_name,
            resource_type=resource_type,
            resource_id=resource_id,
            environment=environment,
            session=db_session,
        )

        ctx = MCPExecutionContext(
            user=user,
            session=db_session,
            tool_name=tool_name,
            resource_type=resource_type,
        )

        yield ctx

        # 3. Record tool execution audit log in PostgreSQL with SHA-256 cryptographic hash chaining
        safe_metadata = input_metadata.copy() if input_metadata else {}
        for sensitive_key in ["authorization", "auth_token", "token", "password", "secret"]:
            safe_metadata.pop(sensitive_key, None)

        await record_audit_log(
            session=db_session,
            event_type="MCP_TOOL_EXECUTION",
            action=f"mcp.{tool_name}",
            resource_type=resource_type,
            actor_id=user.id,
            actor_role=user.role.value if hasattr(user.role, "value") else str(user.role),
            resource_id=resource_id,
            decision="success",
            event_data={
                "tool": tool_name,
                "resource_id": resource_id,
                "metadata": safe_metadata,
            },
        )
        if owns_session:
            await db_session.commit()

    except Exception:
        if owns_session:
            await db_session.rollback()
        raise
    finally:
        if owns_session:
            await db_session.close()

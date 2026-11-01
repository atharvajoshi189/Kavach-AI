"""Authentication boundary for the AegisMesh MCP server.

Guarantees that tool callers cannot forge identity, roles, or permissions. All identity
is derived server-side from verified, unrevoked JWT access tokens transmitted via HTTP
Authorization headers.
"""

from collections.abc import Mapping
import logging
from typing import Optional
import uuid

import jwt
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser, BearerAuthBackend
from mcp.server.auth.provider import AccessToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_token, is_token_revoked
from app.database.session import AsyncSessionLocal
from app.models.user import User

logger = logging.getLogger("aegismesh.mcp.auth")


class MCPAuthenticationError(Exception):
    """Raised when an MCP caller provides invalid, expired, revoked, or missing credentials."""
    pass


class AegisMeshAuthenticatedUser(AuthenticatedUser):
    """Authenticated user carrying the trusted PostgreSQL User entity and verified token claims."""

    def __init__(self, auth_info: AccessToken, db_user: Optional[User] = None):
        super().__init__(auth_info)
        self.db_user = db_user


class AegisMeshBearerAuthBackend(BearerAuthBackend):
    """Bearer authentication backend integrating AegisMeshTokenVerifier with Starlette.

    Eliminates duplicate verification by propagating the verified PostgreSQL User entity
    to the ASGI request scope.
    """

    async def authenticate(self, conn):
        res = await super().authenticate(conn)
        if res is not None:
            creds, auth_user = res
            db_user = getattr(auth_user.access_token, "_db_user", None)
            return creds, AegisMeshAuthenticatedUser(auth_user.access_token, db_user=db_user)
        return None


def extract_bearer_token(headers: Optional[Mapping[str, str]]) -> str:
    """Extracts and validates the Bearer token from HTTP request headers."""
    if not headers:
        raise MCPAuthenticationError("Authentication required: Missing Authorization header.")

    auth_header = next(
        (headers.get(key) for key in headers if key.lower() == "authorization"),
        None,
    )
    if not auth_header:
        raise MCPAuthenticationError("Authentication required: Missing Authorization header.")

    cleaned = auth_header.strip()
    if not cleaned.lower().startswith("bearer "):
        raise MCPAuthenticationError("Invalid Authorization header format. Expected 'Bearer <token>'.")

    token = cleaned[7:].strip()
    if not token:
        raise MCPAuthenticationError("Authentication token is required.")

    return token


async def authenticate_token(token: str, session: AsyncSession) -> User:
    """Validates an incoming bearer JWT, checks revocation in Redis, and loads active User.

    Fails closed on any signature, expiration, revocation, or inactive account issue.
    """
    if not token or not isinstance(token, str):
        raise MCPAuthenticationError("Authentication token is required.")

    cleaned_token = token.strip()
    if cleaned_token.lower().startswith("bearer "):
        cleaned_token = cleaned_token[7:].strip()

    try:
        payload = decode_token(cleaned_token)
    except jwt.ExpiredSignatureError:
        raise MCPAuthenticationError("Authentication token has expired.") from None
    except jwt.PyJWTError:
        raise MCPAuthenticationError("Invalid authentication token.") from None

    if payload.get("type") != "access":
        raise MCPAuthenticationError("Invalid token type: access token required.")

    jti = payload.get("jti")
    if not jti or await is_token_revoked(jti):
        raise MCPAuthenticationError("Authentication token has been revoked.")

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise MCPAuthenticationError("Invalid token payload: missing subject.")

    try:
        user_uuid = uuid.UUID(user_id_str)
    except ValueError:
        raise MCPAuthenticationError("Invalid token subject: malformed UUID.") from None

    query = select(User).where(User.id == user_uuid)
    result = await session.execute(query)
    user = result.scalar_one_or_none()

    if user is None:
        raise MCPAuthenticationError("User identity not found.")

    if not user.is_active:
        raise MCPAuthenticationError("User account is deactivated.")

    return user


class AegisMeshTokenVerifier:
    """TokenVerifier implementation integrating AegisMesh authentication with the MCP SDK."""

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """Verifies token against AegisMesh JWT decoder, Redis revocation, and PostgreSQL."""
        try:
            async with AsyncSessionLocal() as session:
                user = await authenticate_token(token, session)
                role_val = user.role.value if hasattr(user.role, "value") else str(user.role)
                token_info = AccessToken(
                    token=token,
                    client_id=str(user.id),
                    scopes=[role_val],
                    subject=str(user.id),
                    claims={"role": role_val, "username": user.username},
                )
                # Cache verified database user to prevent duplicate queries downstream
                token_info._db_user = user
                return token_info
        except Exception as exc:
            logger.debug("AegisMeshTokenVerifier rejected token: %s", exc)
            return None

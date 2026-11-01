"""Role-Based Access Control (RBAC) and authentication dependencies."""

from collections.abc import Callable
from datetime import datetime, timezone
import logging
import uuid
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.audit import AuditEvent, log_audit_event
from app.core.security import decode_token, is_token_revoked
from app.database.session import get_db
from app.models.user import User, UserRole
from app.services.audit_service import record_audit_log

logger = logging.getLogger(__name__)

# HTTP Bearer scheme for token extraction
bearer_scheme = HTTPBearer(auto_error=True)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Authenticates the request bearer token and retrieves active user."""
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except jwt.PyJWTError:
        raise credentials_exception from None

    # Enforce access token type
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check token revocation via Redis
    jti = payload.get("jti")
    if not jti or await is_token_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Fetch user from database
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise credentials_exception

    try:
        user_uuid = uuid.UUID(user_id_str)
    except ValueError:
        raise credentials_exception from None

    query = select(User).where(User.id == user_uuid)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    return user


def require_roles(*allowed_roles: UserRole) -> Callable:
    """Factory creating a FastAPI dependency enforcing user role constraints."""

    async def role_checker(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        if current_user.role not in allowed_roles:
            log_audit_event(
                event=AuditEvent.PERMISSION_DENIED,
                user_id=str(current_user.id),
                username=current_user.username,
                status="DENIED",
                details={
                    "user_role": current_user.role.value,
                    "required_roles": [r.value for r in allowed_roles],
                },
            )
            try:
                await record_audit_log(
                    session=db,
                    event_type=AuditEvent.PERMISSION_DENIED.value,
                    action="role_authorization",
                    resource_type="endpoint",
                    actor_id=current_user.id,
                    actor_role=current_user.role.value,
                    decision="denied",
                    event_data={
                        "user_role": current_user.role.value,
                        "required_roles": [r.value for r in allowed_roles],
                    },
                )
                await db.commit()
            except Exception as audit_err:
                logger.error("Failed to persist permission denied audit event: %s", audit_err)

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: insufficient role permissions",
            )
        return current_user

    return role_checker


# Role-specific convenience dependencies following least privilege hierarchy
require_admin = require_roles(UserRole.ADMIN)
require_security_operator = require_roles(UserRole.ADMIN, UserRole.SECURITY_OPERATOR)
require_security_analyst = require_roles(
    UserRole.ADMIN, UserRole.SECURITY_OPERATOR, UserRole.SECURITY_ANALYST
)


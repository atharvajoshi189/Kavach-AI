"""Authentication API endpoints covering registration, login, token refresh, profile, and logout."""

from datetime import datetime, timezone
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.audit import AuditEvent, log_audit_event
from app.core.config import settings
from app.core.permissions import bearer_scheme, get_current_user
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    is_token_revoked,
    revoke_token,
    validate_password_strength,
    verify_password,
)
from app.database.session import get_db
from app.models.user import User, UserRole
from app.schemas.auth import (
    LogoutRequest,
    TokenRefreshRequest,
    TokenResponse,
    UserLoginRequest,
    UserPublicResponse,
    UserRegisterRequest,
)
from app.services.audit_service import record_audit_log

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserPublicResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register New User",
    description="Registers a new user account with default viewer permissions.",
)
async def register(
    request: Request,
    payload: UserRegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> UserPublicResponse:
    """Handles public user self-registration."""
    client_ip = request.client.host if request.client else None

    # Verify registration is allowed by policy
    if not settings.PUBLIC_REGISTRATION_ENABLED:
        log_audit_event(
            AuditEvent.REGISTER_FAILURE,
            username=payload.username,
            client_ip=client_ip,
            status="FORBIDDEN",
            details={"reason": "Public registration is disabled"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public registration is currently disabled.",
        )

    # Validate password complexity
    try:
        validate_password_strength(payload.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        ) from None

    # Check for duplicate email or username
    existing_user_query = select(User).where(
        or_(
            User.email == payload.email.lower(),
            User.username == payload.username.lower(),
        )
    )
    result = await db.execute(existing_user_query)
    existing_user = result.scalar_one_or_none()

    if existing_user:
        log_audit_event(
            AuditEvent.REGISTER_FAILURE,
            username=payload.username,
            client_ip=client_ip,
            status="CONFLICT",
            details={"reason": "Duplicate username or email"},
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email address or username is already registered.",
        )

    # Create user entity strictly defaulting to VIEWER role
    new_user = User(
        email=payload.email.lower(),
        username=payload.username.lower(),
        hashed_password=hash_password(payload.password),
        role=UserRole.VIEWER,
        is_active=True,
        is_verified=False,
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    log_audit_event(
        AuditEvent.REGISTER_SUCCESS,
        user_id=str(new_user.id),
        username=new_user.username,
        client_ip=client_ip,
        details={"assigned_role": new_user.role.value},
    )

    try:
        await record_audit_log(
            session=db,
            event_type=AuditEvent.REGISTER_SUCCESS.value,
            action="register",
            resource_type="user",
            actor_id=new_user.id,
            actor_role=new_user.role.value,
            resource_id=str(new_user.id),
            decision="success",
            event_data={"username": new_user.username, "client_ip": client_ip},
        )
        await db.commit()
    except Exception as audit_err:
        await db.rollback()
        logger.critical("MANDATORY AUDIT PERSISTENCE FAILED for user registration: %s", audit_err)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security audit persistence failed; operation aborted.",
        ) from audit_err

    return UserPublicResponse.model_validate(new_user)


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate User",
    description="Authenticates credentials and returns a pair of JWT access and refresh tokens.",
)
async def login(
    request: Request,
    payload: UserLoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticates username/email and password, issuing access & refresh tokens."""
    client_ip = request.client.host if request.client else None
    identifier = payload.username_or_email.lower().strip()

    # Query user by email or username
    query = select(User).where(
        or_(
            User.email == identifier,
            User.username == identifier,
        )
    )
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    # Generic error message to prevent account enumeration
    invalid_creds_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username/email or password.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not user:
        log_audit_event(
            AuditEvent.LOGIN_FAILURE,
            username=identifier,
            client_ip=client_ip,
            status="FAILED",
            details={"reason": "User not found"},
        )
        raise invalid_creds_exception

    if not verify_password(payload.password, user.hashed_password):
        log_audit_event(
            AuditEvent.LOGIN_FAILURE,
            user_id=str(user.id),
            username=user.username,
            client_ip=client_ip,
            status="FAILED",
            details={"reason": "Incorrect password"},
        )
        raise invalid_creds_exception

    if not user.is_active:
        log_audit_event(
            AuditEvent.LOGIN_FAILURE,
            user_id=str(user.id),
            username=user.username,
            client_ip=client_ip,
            status="FORBIDDEN",
            details={"reason": "Account deactivated"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact an administrator.",
        )

    # Update last login timestamp
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    # Issue token pair
    access_token = create_access_token(subject=user.id, role=user.role.value)
    refresh_token = create_refresh_token(subject=user.id)
    expires_in = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60

    log_audit_event(
        AuditEvent.LOGIN_SUCCESS,
        user_id=str(user.id),
        username=user.username,
        client_ip=client_ip,
        details={"role": user.role.value},
    )

    try:
        await record_audit_log(
            session=db,
            event_type=AuditEvent.LOGIN_SUCCESS.value,
            action="login",
            resource_type="user",
            actor_id=user.id,
            actor_role=user.role.value,
            resource_id=str(user.id),
            decision="success",
            event_data={"username": user.username, "client_ip": client_ip},
        )
        await db.commit()
    except Exception as audit_err:
        await db.rollback()
        logger.critical("MANDATORY AUDIT PERSISTENCE FAILED for user login: %s", audit_err)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security audit persistence failed; authentication aborted.",
        ) from audit_err

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh Access Token",
    description="Rotates refresh tokens and issues a new access token.",
)
async def refresh_tokens(
    payload: TokenRefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Validates refresh token, invalidates old token, and issues a fresh pair."""
    invalid_token_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        decoded = decode_token(payload.refresh_token)
    except jwt.PyJWTError:
        log_audit_event(AuditEvent.TOKEN_REFRESH_FAILURE, details={"reason": "Malformed or expired JWT"})
        raise invalid_token_exception from None

    # Enforce refresh token type
    if decoded.get("type") != "refresh":
        log_audit_event(AuditEvent.TOKEN_REFRESH_FAILURE, details={"reason": "Wrong token type"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token type must be 'refresh'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check revocation status
    jti = decoded.get("jti")
    if not jti or await is_token_revoked(jti):
        log_audit_event(AuditEvent.TOKEN_REFRESH_FAILURE, details={"reason": "Revoked token reused"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify user existence and active status
    user_id_str = decoded.get("sub")
    query = select(User).where(User.id == user_id_str)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise invalid_token_exception

    # Revoke old refresh token (Token Rotation)
    exp = decoded.get("exp", 0)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    remaining_ttl = max(1, exp - now_ts)
    await revoke_token(jti, remaining_ttl)

    # Issue new token pair
    new_access_token = create_access_token(subject=user.id, role=user.role.value)
    new_refresh_token = create_refresh_token(subject=user.id)
    expires_in = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60

    log_audit_event(
        AuditEvent.TOKEN_REFRESH_SUCCESS,
        user_id=str(user.id),
        username=user.username,
    )

    try:
        await record_audit_log(
            session=db,
            event_type=AuditEvent.TOKEN_REFRESH_SUCCESS.value,
            action="refresh_token",
            resource_type="auth_token",
            actor_id=user.id,
            actor_role=user.role.value,
            resource_id=str(user.id),
            decision="success",
            event_data={"username": user.username},
        )
        await db.commit()
    except Exception as audit_err:
        await db.rollback()
        logger.critical("MANDATORY AUDIT PERSISTENCE FAILED for token refresh: %s", audit_err)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security audit persistence failed; token refresh aborted.",
        ) from audit_err

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_in=expires_in,
    )


@router.get(
    "/me",
    response_model=UserPublicResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Current User Profile",
    description="Retrieves the public profile for the authenticated caller.",
)
async def get_me(current_user: User = Depends(get_current_user)) -> UserPublicResponse:
    """Returns authenticated user's profile details."""
    return UserPublicResponse.model_validate(current_user)


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout User",
    description="Invalidates current access token and optional refresh token in Redis.",
)
async def logout(
    payload: LogoutRequest | None = None,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Revokes active access token and companion refresh token in Redis."""
    token = credentials.credentials
    now_ts = int(datetime.now(timezone.utc).timestamp())

    try:
        # Revoke access token
        access_payload = decode_token(token)
        access_jti = access_payload.get("jti")
        access_exp = access_payload.get("exp", 0)
        access_ttl = max(1, access_exp - now_ts)
        if access_jti:
            await revoke_token(access_jti, access_ttl)

        # Revoke refresh token if provided
        if payload and payload.refresh_token:
            try:
                refresh_payload = decode_token(payload.refresh_token)
                refresh_jti = refresh_payload.get("jti")
                refresh_exp = refresh_payload.get("exp", 0)
                refresh_ttl = max(1, refresh_exp - now_ts)
                if refresh_jti:
                    await revoke_token(refresh_jti, refresh_ttl)
            except jwt.PyJWTError:
                pass  # Refresh token is already expired or invalid

        log_audit_event(
            AuditEvent.LOGOUT,
            user_id=str(current_user.id),
            username=current_user.username,
        )

        try:
            await record_audit_log(
                session=db,
                event_type=AuditEvent.LOGOUT.value,
                action="logout",
                resource_type="user",
                actor_id=current_user.id,
                actor_role=current_user.role.value,
                resource_id=str(current_user.id),
                decision="success",
                event_data={"username": current_user.username},
            )
            await db.commit()
        except Exception as audit_err:
            await db.rollback()
            logger.critical("MANDATORY AUDIT PERSISTENCE FAILED for logout: %s", audit_err)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Security audit persistence failed; logout aborted.",
            ) from audit_err

        return {"status": "success", "message": "Logged out and token revoked successfully."}
    except Exception as e:
        logger.error("Error during token revocation on logout: %s", type(e).__name__)
        return {"status": "success", "message": "Logged out successfully."}


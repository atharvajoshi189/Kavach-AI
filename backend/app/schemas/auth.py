"""Schemas for user authentication, token issuance, and profile representation."""

from datetime import datetime
import uuid
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from app.models.user import UserRole


class UserRegisterRequest(BaseModel):
    """Payload for user self-registration."""

    email: EmailStr = Field(..., description="Valid corporate email address")
    username: str = Field(..., min_length=3, max_length=64, description="Unique username")
    password: str = Field(..., min_length=8, description="Strong password")


class UserLoginRequest(BaseModel):
    """Payload for user authentication."""

    username_or_email: str = Field(..., description="Registered username or email address")
    password: str = Field(..., description="User password")


class TokenResponse(BaseModel):
    """Bearer token pair issued upon successful authentication or refresh."""

    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token scheme")
    expires_in: int = Field(..., description="Access token expiration window in seconds")


class TokenRefreshRequest(BaseModel):
    """Payload for requesting an access token refresh."""

    refresh_token: str = Field(..., description="Valid JWT refresh token")


class UserPublicResponse(BaseModel):
    """Public user profile data excluding sensitive credentials and internal hashes."""

    id: uuid.UUID = Field(..., description="Unique user identifier")
    email: str = Field(..., description="User email address")
    username: str = Field(..., description="Platform username")
    role: UserRole = Field(..., description="Assigned platform role")
    is_active: bool = Field(..., description="Account active status")
    created_at: datetime = Field(..., description="Account creation timestamp")
    last_login_at: datetime | None = Field(default=None, description="Last recorded login timestamp")

    model_config = ConfigDict(from_attributes=True)


class LogoutRequest(BaseModel):
    """Optional payload during logout providing the companion refresh token for simultaneous invalidation."""

    refresh_token: str | None = Field(default=None, description="Optional refresh token to revoke alongside access token")

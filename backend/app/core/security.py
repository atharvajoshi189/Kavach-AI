"""Security service providing Argon2 password hashing, JWT generation, and token revocation."""

from datetime import datetime, timedelta, timezone
import re
import uuid
import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from app.core.config import settings
from app.core.redis import redis_client

# Initialize Argon2 password hasher
_password_hash = PasswordHash((Argon2Hasher(),))

# Password strength regex: min 8 chars, 1 upper, 1 lower, 1 digit, 1 special character
PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_\-#])[A-Za-z\d@$!%*?&_\-#]{8,}$"
)


def validate_password_strength(password: str) -> None:
    """Validates that a password satisfies platform complexity requirements.

    Raises ValueError with a descriptive message if the password fails requirements.
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if len(password) > 128:
        raise ValueError("Password cannot exceed 128 characters.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit.")
    if not re.search(r"[@$!%*?&_\-#]", password):
        raise ValueError("Password must contain at least one special character (@$!%*?&_#-).")


def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id."""
    return _password_hash.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Performs constant-time verification of password against its Argon2 hash."""
    return _password_hash.verify(plain_password, hashed_password)


def create_access_token(
    subject: str | uuid.UUID,
    role: str,
    extra_claims: dict | None = None,
) -> str:
    """Generates a signed JWT access token containing subject, role, and expiration."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())

    payload = {
        "sub": str(subject),
        "role": role,
        "type": "access",
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(
    subject: str | uuid.UUID,
    extra_claims: dict | None = None,
) -> str:
    """Generates a signed JWT refresh token for session continuity."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    jti = str(uuid.uuid4())

    payload = {
        "sub": str(subject),
        "type": "refresh",
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decodes and cryptographically validates a JWT token.

    Raises jwt.PyJWTError subclasses on invalid signatures, expired tokens, or malformed claims.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["exp", "iat", "sub", "type", "jti"]},
    )


async def revoke_token(jti: str, expires_in_seconds: int) -> None:
    """Stores a revoked JWT JTI in Redis with a TTL matching token lifetime."""
    if expires_in_seconds > 0:
        await redis_client.setex(f"revoked_token:{jti}", expires_in_seconds, "true")


async def is_token_revoked(jti: str) -> bool:
    """Queries Redis to check whether a JTI has been revoked."""
    exists = await redis_client.exists(f"revoked_token:{jti}")
    return bool(exists)


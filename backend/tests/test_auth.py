"""Automated security test suite covering registration, authentication, RBAC, and token lifecycle."""

import uuid
import pytest
from httpx import ASGITransport, AsyncClient
from app.core.security import hash_password, validate_password_strength, verify_password
from app.main import app
from app.models.user import User, UserRole


# --- 1. Password Hashing and Strength Validation Tests ---

def test_password_hashing_and_verification():
    """Verify Argon2 hashing and constant-time verification."""
    password = "SuperSecurePassword123!"
    hashed = hash_password(password)

    assert hashed != password
    assert hashed.startswith("$argon2")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_password_strength_validation():
    """Verify password complexity requirements."""
    # Valid
    validate_password_strength("ValidPassword123@")

    # Too short
    with pytest.raises(ValueError, match="at least 8 characters"):
        validate_password_strength("Short1!")

    # Missing uppercase
    with pytest.raises(ValueError, match="uppercase"):
        validate_password_strength("lowercase123!")

    # Missing lowercase
    with pytest.raises(ValueError, match="lowercase"):
        validate_password_strength("UPPERCASE123!")

    # Missing digit
    with pytest.raises(ValueError, match="digit"):
        validate_password_strength("NoDigitPassword!")

    # Missing special character
    with pytest.raises(ValueError, match="special character"):
        validate_password_strength("NoSpecialChar123")


# --- 2. Registration Tests ---

@pytest.mark.asyncio
async def test_successful_registration():
    """Verify user registration defaults to VIEWER role and returns public profile."""
    unique_suffix = str(uuid.uuid4())[:8]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": f"newuser_{unique_suffix}@example.com",
                "username": f"user_{unique_suffix}",
                "password": "SecurePassword123!",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == f"newuser_{unique_suffix}@example.com"
        assert data["username"] == f"user_{unique_suffix}"
        assert data["role"] == "viewer"
        assert data["is_active"] is True
        assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_duplicate_registration_rejection():
    """Verify registering duplicate email or username returns 409 Conflict."""
    unique_suffix = str(uuid.uuid4())[:8]
    reg_payload = {
        "email": f"duplicate_{unique_suffix}@example.com",
        "username": f"dup_{unique_suffix}",
        "password": "SecurePassword123!",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # First registration
        res1 = await client.post("/api/v1/auth/register", json=reg_payload)
        assert res1.status_code == 201

        # Duplicate registration
        res2 = await client.post("/api/v1/auth/register", json=reg_payload)
        assert res2.status_code == 409
        assert "already registered" in res2.json()["detail"]


# --- 3. Login and Token Acquisition Tests ---

@pytest.mark.asyncio
async def test_successful_login_and_token_issuance(test_operator):
    """Verify login with valid credentials issues access and refresh tokens."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "username_or_email": test_operator.username,
                "password": "OperatorPass123!",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0


@pytest.mark.asyncio
async def test_invalid_login_rejection():
    """Verify invalid password or non-existent user returns 401 with generic error message."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "username_or_email": "nonexistent_user",
                "password": "WrongPassword123!",
            },
        )
        assert response.status_code == 401
        assert "Invalid username/email or password" in response.json()["detail"]


@pytest.mark.asyncio
async def test_deactivated_user_login(db_session):
    """Verify deactivated accounts cannot log in."""
    unique_suffix = str(uuid.uuid4())[:8]
    inactive_user = User(
        email=f"inactive_{unique_suffix}@example.com",
        username=f"inactive_{unique_suffix}",
        hashed_password=hash_password("InactivePass123!"),
        role=UserRole.VIEWER,
        is_active=False,
    )
    db_session.add(inactive_user)
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "username_or_email": inactive_user.username,
                "password": "InactivePass123!",
            },
        )
        assert response.status_code == 403
        assert "deactivated" in response.json()["detail"]


# --- 4. User Profile & Token Refresh Tests ---

@pytest.mark.asyncio
async def test_get_current_user_profile(operator_token, test_operator):
    """Verify GET /api/v1/auth/me returns authenticated caller profile."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == test_operator.username
        assert data["role"] == "security_operator"
        assert data["email"] == test_operator.email


@pytest.mark.asyncio
async def test_token_refresh_and_rotation(test_operator):
    """Verify refresh token issuance, rotation, and rejection of reused old refresh tokens."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Login to obtain initial tokens
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"username_or_email": test_operator.username, "password": "OperatorPass123!"},
        )
        initial_refresh_token = login_res.json()["refresh_token"]

        # Refresh
        refresh_res = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": initial_refresh_token},
        )
        assert refresh_res.status_code == 200
        data = refresh_res.json()
        new_access_token = data["access_token"]
        new_refresh_token = data["refresh_token"]

        assert new_access_token != login_res.json()["access_token"]
        assert new_refresh_token != initial_refresh_token

        # Verify old refresh token is now revoked and cannot be reused
        reuse_res = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": initial_refresh_token},
        )
        assert reuse_res.status_code == 401
        assert "revoked" in reuse_res.json()["detail"]


@pytest.mark.asyncio
async def test_reject_access_token_on_refresh(operator_token):
    """Verify that an access token cannot be used as a refresh token."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": operator_token},
        )
        assert response.status_code == 401
        assert "must be 'refresh'" in response.json()["detail"]


# --- 5. Logout and Token Revocation Tests ---

@pytest.mark.asyncio
async def test_logout_revokes_token(test_operator):
    """Verify that logging out invalidates the access token in Redis."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"username_or_email": test_operator.username, "password": "OperatorPass123!"},
        )
        access_token = login_res.json()["access_token"]
        refresh_token = login_res.json()["refresh_token"]

        # Verify access token works initially
        me_res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"})
        assert me_res.status_code == 200

        # Logout
        logout_res = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {access_token}"},
            json={"refresh_token": refresh_token},
        )
        assert logout_res.status_code == 200

        # Verify access token is now revoked and rejected
        post_logout_me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"})
        assert post_logout_me.status_code == 401
        assert "revoked" in post_logout_me.json()["detail"]


# --- 6. Role-Based Access Control and Job Protection Tests ---

@pytest.mark.asyncio
async def test_viewer_denied_job_submission(viewer_token):
    """Verify that a user with VIEWER role is denied access to submit background jobs."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/jobs/health-check",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert response.status_code == 403
        assert "insufficient role permissions" in response.json()["detail"]


@pytest.mark.asyncio
async def test_operator_allowed_job_submission(operator_token):
    """Verify that an authorized SECURITY_OPERATOR can submit a background job."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/jobs/health-check",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert response.status_code == 202
        assert response.json()["status"] == "queued"


@pytest.mark.asyncio
async def test_user_cannot_inspect_another_users_job(operator_token, viewer_token):
    """Verify that users cannot inspect tasks submitted by another user unless Admin."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Operator submits a job
        submit_res = await client.post(
            "/api/v1/jobs/health-check",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        task_id = submit_res.json()["task_id"]

        # Different user (viewer) attempts to inspect it
        inspect_res = await client.get(
            f"/api/v1/jobs/{task_id}",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert inspect_res.status_code == 403
        assert "Access denied" in inspect_res.json()["detail"]


@pytest.mark.asyncio
async def test_admin_can_inspect_any_users_job(operator_token, admin_token):
    """Verify that an Administrator can inspect tasks submitted by any user."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Operator submits a job
        submit_res = await client.post(
            "/api/v1/jobs/health-check",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        task_id = submit_res.json()["task_id"]

        # Admin inspects it
        inspect_res = await client.get(
            f"/api/v1/jobs/{task_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert inspect_res.status_code == 200
        assert inspect_res.json()["task_id"] == task_id

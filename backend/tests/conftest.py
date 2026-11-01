"""Shared pytest fixtures and test authentication helpers."""

import uuid
import pytest_asyncio
from app.core.security import create_access_token, hash_password
from app.database.session import AsyncSessionLocal
from app.models.user import User, UserRole


@pytest_asyncio.fixture
async def db_session():
    """Provides an isolated database session for tests."""
    async with AsyncSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def test_operator(db_session):
    """Creates a test user with the SECURITY_OPERATOR role."""
    unique_suffix = str(uuid.uuid4())[:8]
    user = User(
        email=f"operator_{unique_suffix}@example.com",
        username=f"operator_{unique_suffix}",
        hashed_password=hash_password("OperatorPass123!"),
        role=UserRole.SECURITY_OPERATOR,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_viewer(db_session):
    """Creates a test user with the VIEWER role."""
    unique_suffix = str(uuid.uuid4())[:8]
    user = User(
        email=f"viewer_{unique_suffix}@example.com",
        username=f"viewer_{unique_suffix}",
        hashed_password=hash_password("ViewerPass123!"),
        role=UserRole.VIEWER,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_admin(db_session):
    """Creates a test user with the ADMIN role."""
    unique_suffix = str(uuid.uuid4())[:8]
    user = User(
        email=f"admin_{unique_suffix}@example.com",
        username=f"admin_{unique_suffix}",
        hashed_password=hash_password("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_analyst(db_session):
    """Creates a test user with the SECURITY_ANALYST role."""
    unique_suffix = str(uuid.uuid4())[:8]
    user = User(
        email=f"analyst_{unique_suffix}@example.com",
        username=f"analyst_{unique_suffix}",
        hashed_password=hash_password("AnalystPass123!"),
        role=UserRole.SECURITY_ANALYST,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
def operator_token(test_operator):
    """Returns a valid access token for the test operator."""
    return create_access_token(subject=test_operator.id, role=test_operator.role.value)


@pytest_asyncio.fixture
def viewer_token(test_viewer):
    """Returns a valid access token for the test viewer."""
    return create_access_token(subject=test_viewer.id, role=test_viewer.role.value)


@pytest_asyncio.fixture
def admin_token(test_admin):
    """Returns a valid access token for the test admin."""
    return create_access_token(subject=test_admin.id, role=test_admin.role.value)


@pytest_asyncio.fixture
def analyst_token(test_analyst):
    """Returns a valid access token for the test analyst."""
    return create_access_token(subject=test_analyst.id, role=test_analyst.role.value)

"""Database integration tests."""

import pytest
from sqlalchemy import text
from app.database.session import AsyncSessionLocal, engine, get_db


@pytest.mark.asyncio
async def test_database_direct_connection():
    """Verify raw engine connection and SELECT 1 execution."""
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT 1"))
        scalar = result.scalar()
        assert scalar == 1


@pytest.mark.asyncio
async def test_database_session_execution():
    """Verify AsyncSessionLocal can establish a session and execute a query."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(text("SELECT 1 AS alive"))
        row = result.fetchone()
        assert row is not None
        assert row[0] == 1


@pytest.mark.asyncio
async def test_get_db_dependency_lifecycle():
    """Verify get_db generator properly yields an active AsyncSession."""
    async_gen = get_db()
    session = await anext(async_gen)
    try:
        assert session is not None
        result = await session.execute(text("SELECT 1"))
        assert result.scalar() == 1
    finally:
        with pytest.raises(StopAsyncIteration):
            await anext(async_gen)


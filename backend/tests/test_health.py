"""Tests for API health and root metadata endpoints."""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from httpx import ASGITransport, AsyncClient
from app.core.config import settings
from app.main import app


@pytest.mark.asyncio
async def test_health_endpoint():
    """Verify GET /api/v1/health returns status 200, healthy status, and PostgreSQL/Redis service status."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["application"] == settings.PROJECT_NAME
        assert data["version"] == settings.VERSION
        assert "timestamp" in data
        assert "services" in data
        assert data["services"]["postgresql"] == "healthy"
        assert data["services"]["redis"] == "healthy"


@pytest.mark.asyncio
async def test_health_endpoint_when_database_fails():
    """Verify GET /api/v1/health returns 503 and degraded status when database is unreachable while Redis is up."""
    mock_engine = MagicMock()
    mock_engine.connect.side_effect = Exception("Database unreachable")
    with patch("app.api.health.engine", mock_engine):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/health")
            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "degraded"
            assert data["services"]["postgresql"] == "unhealthy"
            assert data["services"]["redis"] == "healthy"
            assert "Database unreachable" not in response.text


@pytest.mark.asyncio
async def test_health_endpoint_when_redis_fails():
    """Verify GET /api/v1/health returns 503 and degraded status when Redis is unreachable while Postgres is up."""
    with patch("app.api.health.redis_ping", new_callable=AsyncMock, return_value=False):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/health")
            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "degraded"
            assert data["services"]["postgresql"] == "healthy"
            assert data["services"]["redis"] == "unhealthy"


@pytest.mark.asyncio
async def test_root_endpoint():
    """Verify GET / returns API metadata and documentation links."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["application"] == settings.PROJECT_NAME
        assert data["version"] == settings.VERSION
        assert data["docs_url"] == settings.DOCS_URL
        assert data["health_url"] == f"{settings.API_V1_STR}/health"


@pytest.mark.asyncio
async def test_docs_endpoint():
    """Verify GET /docs loads Swagger UI documentation."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/docs")
        assert response.status_code == 200

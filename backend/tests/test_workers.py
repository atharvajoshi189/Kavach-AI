"""Tests for Redis connection, Celery task registration, and jobs API endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient
from app.core.redis import redis_client, redis_ping, verify_redis_connection
from app.main import app
from app.workers.celery_app import celery_app
from app.workers.tasks import health_check_task


@pytest.mark.asyncio
async def test_redis_connection_and_ping():
    """Verify Redis client connects and PING returns True."""
    pong = await redis_ping()
    assert pong is True

    # Test raw client ping
    raw_pong = await redis_client.ping()
    assert raw_pong is True


@pytest.mark.asyncio
async def test_redis_verify_connection_success():
    """Verify verify_redis_connection completes without raising exceptions."""
    await verify_redis_connection()


def test_celery_task_registration():
    """Verify that health_check_task is registered in Celery application registry."""
    task_name = "app.workers.tasks.health_check_task"
    assert task_name in celery_app.tasks
    assert celery_app.tasks[task_name] == health_check_task


def test_health_check_task_direct_execution():
    """Verify direct local execution of health_check_task returns expected structure."""
    result = health_check_task.apply()
    assert result.successful()
    payload = result.result
    assert payload["task_name"] == "health_check_task"
    assert payload["status"] == "completed"
    assert "timestamp" in payload


@pytest.mark.asyncio
async def test_submit_health_check_job_unauthenticated():
    """Verify POST /api/v1/jobs/health-check rejects unauthenticated calls with 401/403."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/api/v1/jobs/health-check")
        assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_submit_health_check_job_authenticated(operator_token):
    """Verify POST /api/v1/jobs/health-check enqueues task and returns 202 when called by operator."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/jobs/health-check",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert response.status_code == 202
        data = response.json()
        assert "task_id" in data
        assert data["status"] == "queued"
        assert len(data["task_id"]) > 0


@pytest.mark.asyncio
async def test_get_job_status_endpoint(operator_token):
    """Verify GET /api/v1/jobs/{task_id} returns task status safely for the owner."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Submit a task
        submit_res = await client.post(
            "/api/v1/jobs/health-check",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        task_id = submit_res.json()["task_id"]

        # Poll status as owner
        status_res = await client.get(
            f"/api/v1/jobs/{task_id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert status_res.status_code == 200
        data = status_res.json()
        assert data["task_id"] == task_id
        assert "status" in data
        assert "ready" in data


@pytest.mark.asyncio
async def test_get_job_status_unknown_id(operator_token):
    """Verify GET /api/v1/jobs/{task_id} handles non-existent or arbitrary task IDs safely."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/api/v1/jobs/non-existent-task-id-12345",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == "non-existent-task-id-12345"
        assert data["ready"] is False
        assert data["result"] is None

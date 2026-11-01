"""Health check API endpoints."""

from datetime import datetime, timezone
import logging
from fastapi import APIRouter, Response, status
from sqlalchemy import text
from app.core.config import settings
from app.core.redis import redis_ping
from app.database.session import engine
from app.schemas.health import HealthResponse, HealthServices

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Service Health Check",
    description="Returns current status, application name, version, timestamp, and status of connected services.",
)
async def check_health(response: Response) -> HealthResponse:
    """Evaluate and report API, PostgreSQL, and Redis availability independently."""
    # Check PostgreSQL
    db_status = "healthy"
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as e:
        logger.error("Health check database probe failed: %s", type(e).__name__)
        db_status = "unhealthy"

    # Check Redis
    redis_status = "healthy"
    try:
        is_redis_alive = await redis_ping()
        if not is_redis_alive:
            redis_status = "unhealthy"
    except Exception as e:
        logger.error("Health check redis probe failed: %s", type(e).__name__)
        redis_status = "unhealthy"

    # Aggregate status
    is_healthy = db_status == "healthy" and redis_status == "healthy"
    overall_status = "healthy" if is_healthy else "degraded"

    if not is_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(
        status=overall_status,
        application=settings.PROJECT_NAME,
        version=settings.VERSION,
        timestamp=datetime.now(timezone.utc),
        services=HealthServices(
            postgresql=db_status,
            redis=redis_status,
        ),
    )

"""FastAPI application lifespan management.

Manages startup checks and shutdown cleanup for critical subsystems
(database, Redis, and OPA).
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from sqlalchemy import text
from app.core.config import settings
from app.core.redis import close_redis_connection, verify_redis_connection
from app.database.session import engine
from app.security.opa_client import close_opa_client

logger = logging.getLogger(__name__)


async def verify_database_connection() -> None:
    """Verifies that the database is reachable on application startup."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("Database connection verified successfully.")
    except Exception as e:
        logger.warning(
            "Database connection verification failed during startup (%s). Running in memory/simulation mode.",
            type(e).__name__,
        )
        if settings.ENVIRONMENT == "production":
            raise RuntimeError(
                "Database connectivity check failed during startup. Verify database is running."
            ) from None


async def close_database_connection() -> None:
    """Disposes the engine connection pool cleanly on application shutdown."""
    try:
        logger.info("Closing database engine pool.")
        await engine.dispose()
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Context manager handling startup and shutdown hooks."""
    # Startup
    try:
        await verify_database_connection()
    except Exception as exc:
        logger.warning("Database startup check bypassed: %s", exc)

    try:
        await verify_redis_connection()
    except Exception as exc:
        logger.warning("Redis startup check bypassed: %s", exc)

    yield

    # Shutdown
    try:
        await close_opa_client()
    except Exception:
        pass

    try:
        await close_redis_connection()
    except Exception:
        pass

    try:
        await close_database_connection()
    except Exception:
        pass

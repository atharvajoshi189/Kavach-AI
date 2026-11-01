"""Async Redis client initialization and lifecycle management.

Maintains a single shared async Redis client with connection pooling
to avoid creating new connections per request.
"""

import logging
from redis.asyncio import Redis, ConnectionPool
from app.core.config import settings

logger = logging.getLogger(__name__)

# Shared connection pool — reused across the application lifetime
_pool: ConnectionPool = ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=20,
    decode_responses=True,
)

# Shared async Redis client backed by the connection pool
redis_client: Redis = Redis(connection_pool=_pool)


async def verify_redis_connection() -> None:
    """Verifies that Redis is reachable. Raises RuntimeError on failure."""
    try:
        pong = await redis_client.ping()
        if pong:
            logger.info("Redis connection verified successfully.")
        else:
            raise RuntimeError("Redis PING did not return True.")
    except Exception as e:
        logger.critical("Redis connection verification failed: %s", type(e).__name__)
        raise RuntimeError(
            "Redis connectivity check failed. Verify Redis is running and configuration is correct."
        ) from None


async def redis_ping() -> bool:
    """Returns True if Redis responds to PING, False otherwise."""
    try:
        return await redis_client.ping()
    except Exception as e:
        logger.error("Redis ping failed: %s", type(e).__name__)
        return False


async def close_redis_connection() -> None:
    """Gracefully closes the Redis connection pool."""
    logger.info("Closing Redis connection pool.")
    await redis_client.aclose()


import asyncio

import structlog
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

_MAX_RETRIES = 5
_BASE_DELAY = 1.0


async def create_redis_client() -> Redis:
    """
    Create and verify a Redis client connection.
    Retries with exponential backoff on startup failures — prevents
    the app from crashing when Redis is slow to start in Docker Compose.
    """
    client = Redis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            await client.ping()
            logger.info("redis_connected", url=settings.redis_url)
            return client
        except RedisConnectionError as exc:
            if attempt == _MAX_RETRIES:
                logger.error(
                    "redis_connection_failed",
                    url=settings.redis_url,
                    attempts=attempt,
                    error=str(exc),
                )
                raise
            delay = _BASE_DELAY * (2 ** (attempt - 1))
            logger.warning(
                "redis_connection_retry",
                attempt=attempt,
                delay=delay,
                error=str(exc),
            )
            await asyncio.sleep(delay)

    raise RedisConnectionError("Redis unavailable after retries")


async def close_redis_client(client: Redis) -> None:
    """Gracefully close the Redis connection."""
    await client.aclose()
    logger.info("redis_closed")


async def is_shadow_mode_enabled(redis: Redis, fallback: bool) -> bool:
    """
    Read shadow mode state from Redis at request time.
    Falls back to the settings value if the key doesn't exist,
    allowing runtime toggle without redeployment.

    Set via: redis-cli SET config:shadow_mode_enabled "true" / "false"
    Or via the admin endpoint once wired up.
    """
    val = await redis.get("config:shadow_mode_enabled")
    if val is None:
        return fallback
    return str(val).lower() == "true"

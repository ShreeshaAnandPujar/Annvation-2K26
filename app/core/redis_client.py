# app/core/redis_client.py
import logging
from redis.asyncio import Redis
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


async def create_redis_client() -> Redis:
    """Create and verify a Redis client connection."""
    client = Redis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )
    await client.ping()
    logger.info("Redis connection established", extra={"url": settings.redis_url})
    return client


async def close_redis_client(client: Redis) -> None:
    """Gracefully close the Redis connection."""
    await client.aclose()
    logger.info("Redis connection closed")

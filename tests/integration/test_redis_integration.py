import pytest
from redis.asyncio import Redis
from app.config import get_settings

settings = get_settings()


@pytest.fixture
async def redis_client():
    """Real Redis client for integration tests."""
    client = Redis.from_url(
        "redis://localhost:6379/1",  # DB 1 to avoid polluting dev data
        encoding="utf-8",
        decode_responses=True,
    )
    yield client
    await client.flushdb()  # clean up after each test
    await client.aclose()


@pytest.mark.asyncio
async def test_redis_ping(redis_client):
    result = await redis_client.ping()
    assert result is True


@pytest.mark.asyncio
async def test_redis_set_and_get(redis_client):
    await redis_client.set("test_key", "test_value", ex=10)
    value = await redis_client.get("test_key")
    assert value == "test_value"


@pytest.mark.asyncio
async def test_redis_key_expiry(redis_client):
    await redis_client.set("expiring_key", "value", ex=10)
    ttl = await redis_client.ttl("expiring_key")
    assert ttl > 0


@pytest.mark.asyncio
async def test_redis_sorted_set(redis_client):
    """Sorted sets are the foundation of the sliding window rate limiter."""
    await redis_client.zadd("test_zset", {"request_1": 1000, "request_2": 2000})
    count = await redis_client.zcard("test_zset")
    assert count == 2

    # Remove entries older than score 1500
    await redis_client.zremrangebyscore("test_zset", 0, 1500)
    count = await redis_client.zcard("test_zset")
    assert count == 1

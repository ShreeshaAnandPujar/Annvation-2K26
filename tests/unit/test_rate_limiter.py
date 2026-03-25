import pytest
from unittest.mock import AsyncMock, MagicMock
from app.services.rate_limiter import RateLimiter


@pytest.fixture
def mock_redis():
    redis = MagicMock()
    script = AsyncMock()
    redis.register_script = MagicMock(return_value=script)
    return redis, script


@pytest.mark.asyncio
async def test_rate_limit_allowed(mock_redis):
    redis, script = mock_redis
    script.return_value = [1, 99]

    limiter = RateLimiter(redis)
    allowed, remaining = await limiter.check_rate_limit("client_1", 100, 60)

    assert allowed is True
    assert remaining == 99


@pytest.mark.asyncio
async def test_rate_limit_exceeded(mock_redis):
    redis, script = mock_redis
    script.return_value = [0, 0]

    limiter = RateLimiter(redis)
    allowed, remaining = await limiter.check_rate_limit("client_1", 100, 60)

    assert allowed is False
    assert remaining == 0

import pytest
from unittest.mock import AsyncMock, MagicMock
from app.services.bloom_filter import BloomFilterService


@pytest.fixture
def mock_redis():
    redis = MagicMock()
    redis.smembers = AsyncMock(return_value={"1.2.3.4", "5.6.7.8"})
    redis.sadd = AsyncMock(return_value=1)
    return redis


@pytest.mark.asyncio
async def test_sync_loads_ips(mock_redis):
    service = BloomFilterService(mock_redis)
    count = await service.sync_from_redis()
    assert count == 2
    assert service.loaded_count == 2


def test_might_contain_after_add(mock_redis):
    service = BloomFilterService(mock_redis)
    service.add("10.0.0.1")
    assert service.might_contain("10.0.0.1") is True


def test_definitely_not_contains(mock_redis):
    service = BloomFilterService(mock_redis)
    assert service.might_contain("99.99.99.99") is False

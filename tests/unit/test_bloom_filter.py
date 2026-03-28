from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.bloom_filter import BloomFilterService


@pytest.fixture
def mock_redis():
    redis = MagicMock()
    redis.smembers = AsyncMock(return_value=set())
    redis.sadd = AsyncMock(return_value=1)
    return redis


@pytest.mark.asyncio
async def test_sync_loads_ips_and_agents(mock_redis):
    mock_redis.smembers = AsyncMock(
        side_effect=[
            {"1.2.3.4", "5.6.7.8"},  # known_bad_ips
            {"python-requests/2.28"},  # abusive_agents
        ]
    )
    service = BloomFilterService(mock_redis)
    count = await service.sync_from_redis()
    assert count == 3
    assert service._loaded_ip_count == 2
    assert service._loaded_agent_count == 1


def test_might_contain_ip_after_add(mock_redis):
    service = BloomFilterService(mock_redis)
    service.add_ip("10.0.0.1")
    assert service.might_contain_ip("10.0.0.1") is True


def test_definitely_not_contains_ip(mock_redis):
    service = BloomFilterService(mock_redis)
    assert service.might_contain_ip("99.99.99.99") is False


def test_might_contain_agent_after_add(mock_redis):
    service = BloomFilterService(mock_redis)
    service.add_agent("python-requests/2.28")
    assert service.might_contain_agent("python-requests/2.28") is True


def test_definitely_not_contains_agent(mock_redis):
    service = BloomFilterService(mock_redis)
    assert service.might_contain_agent("Mozilla/5.0") is False

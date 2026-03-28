import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.shadow_logger import ShadowLogger


@pytest.fixture
def mock_redis():
    redis = MagicMock()
    redis.set = AsyncMock(return_value=True)
    return redis


@pytest.mark.asyncio
async def test_log_shadow_event(mock_redis):
    logger = ShadowLogger(mock_redis)
    await logger.log_shadow_event(
        request_id="req_123",
        rule_triggered="rate_limit",
        client_id="client_1",
        path="/api/data",
        reason="sliding_window_exceeded",
    )
    mock_redis.set.assert_called_once()
    call_args = mock_redis.set.call_args
    key = call_args[0][0]
    assert key == "shadow_log:req_123"


@pytest.mark.asyncio
async def test_get_shadow_stats(mock_redis):
    event = json.dumps(
        {
            "rule_triggered": "rate_limit",
            "client_id": "client_1",
            "path": "/api",
            "request_id": "req_1",
            "timestamp": 1000,
        }
    )
    mock_redis.scan_iter = MagicMock(return_value=async_generator(["shadow_log:req_1"]))

    mock_pipe = MagicMock()
    mock_pipe.execute = AsyncMock(return_value=[event])
    mock_redis.pipeline = MagicMock(return_value=mock_pipe)

    logger = ShadowLogger(mock_redis)
    stats = await logger.get_shadow_stats()

    assert stats["total"] == 1
    assert stats["by_rule"]["rate_limit"] == 1


async def async_generator(items):
    for item in items:
        yield item

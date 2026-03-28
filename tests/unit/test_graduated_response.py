from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.graduated_response import (
    ClientState,
    GraduatedResponseService,
)


@pytest.fixture
def mock_redis():
    redis = MagicMock()
    redis.exists = AsyncMock(return_value=0)
    redis.set = AsyncMock(return_value=True)
    redis.delete = AsyncMock(return_value=1)
    redis.mget = AsyncMock(return_value=[None, None])
    return redis


@pytest.mark.asyncio
async def test_allowed_when_no_signals(mock_redis):
    service = GraduatedResponseService(mock_redis)
    state, reason = await service.compute_abuse_score(
        ip="1.2.3.4",
        client_id="user1",
        ip_fail_count=0,
        user_fail_count=0,
        timing_entropy=500.0,
        ip_threshold=10,
        user_threshold=20,
        entropy_threshold=50.0,
    )
    assert state == ClientState.ALLOWED
    assert reason == ""


@pytest.mark.asyncio
async def test_soft_block_when_ip_threshold_exceeded(mock_redis):
    service = GraduatedResponseService(mock_redis)
    state, reason = await service.compute_abuse_score(
        ip="1.2.3.4",
        client_id="user1",
        ip_fail_count=10,
        user_fail_count=0,
        timing_entropy=500.0,
        ip_threshold=10,
        user_threshold=20,
        entropy_threshold=50.0,
    )
    assert state == ClientState.SOFT_BLOCK
    assert "ip_failures" in reason
    mock_redis.set.assert_called_once()


@pytest.mark.asyncio
async def test_soft_block_when_user_threshold_exceeded(mock_redis):
    service = GraduatedResponseService(mock_redis)
    state, reason = await service.compute_abuse_score(
        ip="1.2.3.4",
        client_id="user1",
        ip_fail_count=0,
        user_fail_count=20,
        timing_entropy=500.0,
        ip_threshold=10,
        user_threshold=20,
        entropy_threshold=50.0,
    )
    assert state == ClientState.SOFT_BLOCK
    assert "user_failures" in reason


@pytest.mark.asyncio
async def test_throttled_when_approaching_threshold(mock_redis):
    service = GraduatedResponseService(mock_redis)
    state, reason = await service.compute_abuse_score(
        ip="1.2.3.4",
        client_id="user1",
        ip_fail_count=7,  # 70% of threshold of 10
        user_fail_count=0,
        timing_entropy=500.0,
        ip_threshold=10,
        user_threshold=20,
        entropy_threshold=50.0,
    )
    assert state == ClientState.THROTTLED
    assert "approaching_auth_threshold" in reason


@pytest.mark.asyncio
async def test_existing_soft_block_returns_immediately(mock_redis):
    mock_redis.exists = AsyncMock(return_value=1)
    service = GraduatedResponseService(mock_redis)
    state, reason = await service.compute_abuse_score(
        ip="1.2.3.4",
        client_id="user1",
        ip_fail_count=0,
        user_fail_count=0,
        timing_entropy=500.0,
        ip_threshold=10,
        user_threshold=20,
        entropy_threshold=50.0,
    )
    assert state == ClientState.SOFT_BLOCK
    assert reason == "existing_soft_block"


@pytest.mark.asyncio
async def test_apply_and_remove_soft_block(mock_redis):
    service = GraduatedResponseService(mock_redis)
    await service.apply_soft_block("1.2.3.4")
    mock_redis.set.assert_called_once_with("blocked_ip:1.2.3.4", "1", ex=300)

    await service.remove_soft_block("1.2.3.4")
    mock_redis.delete.assert_called_once_with("blocked_ip:1.2.3.4")


@pytest.mark.asyncio
async def test_soft_block_on_very_low_entropy(mock_redis):
    """Entropy below 50% of threshold triggers soft block."""
    service = GraduatedResponseService(mock_redis)
    state, reason = await service.compute_abuse_score(
        ip="1.2.3.4",
        client_id="user1",
        ip_fail_count=0,
        user_fail_count=0,
        timing_entropy=10.0,  # well below 50% of threshold (50.0)
        ip_threshold=10,
        user_threshold=20,
        entropy_threshold=50.0,
    )
    assert state == ClientState.SOFT_BLOCK
    assert "very_low_entropy" in reason


@pytest.mark.asyncio
async def test_throttled_on_low_entropy(mock_redis):
    """Entropy below threshold but above 50% of threshold triggers throttle."""
    service = GraduatedResponseService(mock_redis)
    state, reason = await service.compute_abuse_score(
        ip="1.2.3.4",
        client_id="user1",
        ip_fail_count=0,
        user_fail_count=0,
        timing_entropy=30.0,  # below threshold (50.0) but above 25.0 (50%)
        ip_threshold=10,
        user_threshold=20,
        entropy_threshold=50.0,
    )
    assert state == ClientState.THROTTLED
    assert "low_entropy" in reason

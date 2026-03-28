from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.abuse_detector import AbuseDetector


@pytest.fixture
def mock_redis():
    redis = MagicMock()
    pipeline = MagicMock()
    pipeline.execute = AsyncMock(return_value=[1, True, 1, True])
    redis.pipeline = MagicMock(return_value=pipeline)
    return redis


@pytest.mark.asyncio
async def test_record_auth_failure(mock_redis):
    detector = AbuseDetector(mock_redis)
    await detector.record_auth_failure("1.2.3.4", "admin", 300)
    mock_redis.pipeline.assert_called_once()


@pytest.mark.asyncio
async def test_credential_stuffing_ip_threshold():
    redis = MagicMock()
    redis.mget = AsyncMock(return_value=[b"15", b"2"])

    detector = AbuseDetector(redis)
    is_abuse, reason = await detector.is_credential_stuffing(
        "1.2.3.4", "admin", ip_threshold=10, user_threshold=20
    )

    assert is_abuse is True
    assert "ip_threshold_exceeded" in reason


@pytest.mark.asyncio
async def test_credential_stuffing_user_threshold():
    redis = MagicMock()
    redis.mget = AsyncMock(return_value=[b"3", b"25"])

    detector = AbuseDetector(redis)
    is_abuse, reason = await detector.is_credential_stuffing(
        "1.2.3.4", "admin", ip_threshold=10, user_threshold=20
    )

    assert is_abuse is True
    assert "user_threshold_exceeded" in reason


@pytest.mark.asyncio
async def test_no_abuse_below_thresholds():
    redis = MagicMock()
    redis.mget = AsyncMock(return_value=[b"2", b"3"])

    detector = AbuseDetector(redis)
    is_abuse, reason = await detector.is_credential_stuffing(
        "1.2.3.4", "admin", ip_threshold=10, user_threshold=20
    )

    assert is_abuse is False
    assert reason == ""


@pytest.mark.asyncio
async def test_compute_timing_entropy_insufficient_samples():
    """Returns None when fewer than 3 samples are available."""
    redis = MagicMock()
    # Only 2 timestamps — not enough to compute entropy
    redis.zrange = AsyncMock(
        return_value=[
            ("1000", 1000.0),
            ("2000", 2000.0),
        ]
    )
    detector = AbuseDetector(redis)
    result = await detector.compute_timing_entropy("client_1")
    assert result is None


@pytest.mark.asyncio
async def test_is_bot_behavior_insufficient_samples():
    """Returns False with reason when not enough samples to decide."""
    redis = MagicMock()
    pipeline = MagicMock()
    pipeline.execute = AsyncMock(return_value=[1, 0, True])
    redis.pipeline = MagicMock(return_value=pipeline)
    redis.zrange = AsyncMock(return_value=[("1000", 1000.0)])

    detector = AbuseDetector(redis)
    is_bot, reason = await detector.is_bot_behavior(
        client_id="client_1",
        entropy_threshold=50.0,
        max_samples=20,
    )
    assert is_bot is False
    assert reason == "insufficient_samples"


@pytest.mark.asyncio
async def test_is_bot_behavior_low_entropy_detected():
    """Returns True when timing entropy is below threshold."""
    redis = MagicMock()
    pipeline = MagicMock()
    pipeline.execute = AsyncMock(return_value=[1, 0, True])
    redis.pipeline = MagicMock(return_value=pipeline)

    # Highly regular timestamps — low entropy
    redis.zrange = AsyncMock(
        return_value=[
            ("1000", 1000.0),
            ("1100", 1100.0),
            ("1200", 1200.0),
            ("1300", 1300.0),
            ("1400", 1400.0),
        ]
    )

    detector = AbuseDetector(redis)
    is_bot, reason = await detector.is_bot_behavior(
        client_id="client_1",
        entropy_threshold=50.0,
        max_samples=20,
    )
    assert is_bot is True
    assert "low_timing_entropy" in reason

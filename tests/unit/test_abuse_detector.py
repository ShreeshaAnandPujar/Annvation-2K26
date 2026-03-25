import pytest
from unittest.mock import AsyncMock, MagicMock
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

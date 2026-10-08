from unittest.mock import AsyncMock, patch

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.redis_client import close_redis_client, create_redis_client


@pytest.mark.asyncio
async def test_create_redis_client_calls_ping():
    """Client calls ping on creation to verify connection."""
    mock_client = AsyncMock()
    mock_client.ping = AsyncMock(return_value=True)

    with patch("app.core.redis_client.Redis.from_url", return_value=mock_client):
        client = await create_redis_client()
        mock_client.ping.assert_called_once()
        assert client is mock_client


@pytest.mark.asyncio
async def test_close_redis_client_calls_aclose():
    """Client calls aclose on shutdown."""
    mock_client = AsyncMock()
    mock_client.aclose = AsyncMock()

    await close_redis_client(mock_client)
    mock_client.aclose.assert_called_once()


@pytest.mark.asyncio
async def test_create_redis_client_retries_on_failure():
    """Client retries connection before succeeding or falling back."""
    mock_client = AsyncMock()
    call_count = 0

    async def flaky_ping():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise RedisConnectionError("Redis not ready")
        return True

    mock_client.ping = flaky_ping

    with patch("app.core.redis_client.Redis.from_url", return_value=mock_client):
        with patch("app.core.redis_client.asyncio.sleep", new_callable=AsyncMock):
            client = await create_redis_client()
            assert call_count == 2
            assert client is mock_client


@pytest.mark.asyncio
async def test_create_redis_client_fallback_after_max_retries():
    """Client falls back to in-memory Redis after exhausting all retries."""
    mock_client = AsyncMock()
    mock_client.ping = AsyncMock(side_effect=RedisConnectionError("Redis down"))

    with patch("app.core.redis_client.Redis.from_url", return_value=mock_client):
        with patch("app.core.redis_client.asyncio.sleep", new_callable=AsyncMock):
            client = await create_redis_client()
            assert client is not None
            assert hasattr(client, "get")
            assert hasattr(client, "set")
            assert await client.ping() is True


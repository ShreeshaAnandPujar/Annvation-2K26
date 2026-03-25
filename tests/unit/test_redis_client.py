# tests/unit/test_redis_client.py
from unittest.mock import AsyncMock, patch
import pytest
from app.core.redis_client import create_redis_client, close_redis_client


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

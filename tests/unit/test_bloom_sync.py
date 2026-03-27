import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_bloom_sync_worker_calls_sync():
    """Worker calls sync_from_redis on each cycle."""
    mock_redis = MagicMock()

    with patch("app.workers.bloom_sync.BloomFilterService") as MockBloom:
        mock_bloom = MagicMock()
        mock_bloom.sync_from_redis = AsyncMock(return_value=5)
        MockBloom.return_value = mock_bloom

        from app.workers.bloom_sync import bloom_sync_worker

        # Run one cycle then cancel
        task = asyncio.create_task(bloom_sync_worker(mock_redis))
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        mock_bloom.sync_from_redis.assert_called()


@pytest.mark.asyncio
async def test_bloom_sync_worker_survives_exception():
    """Worker continues running even when sync raises an exception."""
    mock_redis = MagicMock()
    call_count = 0

    with patch("app.workers.bloom_sync.BloomFilterService") as MockBloom:
        mock_bloom = MagicMock()

        async def flaky_sync():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ConnectionError("Redis unavailable")
            return 3

        mock_bloom.sync_from_redis = flaky_sync
        MockBloom.return_value = mock_bloom

        with patch("app.workers.bloom_sync.SYNC_INTERVAL_SECONDS", 0):
            from app.workers.bloom_sync import bloom_sync_worker
            task = asyncio.create_task(bloom_sync_worker(mock_redis))
            await asyncio.sleep(0.1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Should have been called more than once — proving it survived the error
        assert call_count >= 2

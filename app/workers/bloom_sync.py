# app/workers/bloom_sync.py
import asyncio

import structlog
from redis.asyncio import Redis

from app.services.bloom_filter import BloomFilterService

logger = structlog.get_logger()

SYNC_INTERVAL_SECONDS = 60


async def bloom_sync_worker(redis: Redis) -> None:
    """
    Background worker that reloads the in-memory Bloom filter
    from Redis every 60 seconds.

    Why this exists:
    The Bloom filter lives in process memory — it is fast but
    it does not automatically see new bad IPs added via the
    /admin/block-ip endpoint. This worker bridges that gap by
    periodically syncing from the Redis source of truth.

    In a multi-instance deployment, each gateway process runs
    its own sync worker, so all instances converge within one
    sync interval of a new block being applied.
    """
    bloom = BloomFilterService(redis)
    logger.info("bloom_sync_worker_started")

    while True:
        try:
            count = await bloom.sync_from_redis()
            logger.info("bloom_filter_synced", ip_count=count)
        except Exception as exc:
            # Log but never crash the worker — a failed sync
            # means the filter uses its last known state, which
            # is acceptable for one cycle.
            logger.error("bloom_filter_sync_failed", error=str(exc))

        await asyncio.sleep(SYNC_INTERVAL_SECONDS)

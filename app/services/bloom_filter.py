import logging
from pybloom_live import BloomFilter
from redis.asyncio import Redis
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class BloomFilterService:
    """
    In-memory Bloom filter for O(1) known-bad IP lookups.

    Eliminates a Redis round-trip on every request for the
    common case (IP is not known-bad). Only confirmed bad IPs
    trigger a Redis lookup.

    False positive rate is configurable. At 0.1%, 1 in 1000
    legitimate IPs may be incorrectly flagged — shadow mode
    catches these before enforcement is enabled.
    """

    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self._filter = BloomFilter(
            capacity=settings.bloom_filter_capacity,
            error_rate=settings.bloom_filter_error_rate,
        )
        self._loaded_count = 0

    def add(self, ip: str) -> None:
        """Add an IP to the in-memory filter."""
        self._filter.add(ip)

    def might_contain(self, ip: str) -> bool:
        """
        Returns True if IP is POSSIBLY in the bad IP set.
        Returns False if IP is DEFINITELY NOT in the set.
        """
        return ip in self._filter

    async def add_to_redis(self, ip: str) -> None:
        """Persist a bad IP to Redis so it survives restarts."""
        await self.redis.sadd("known_bad_ips", ip)
        self.add(ip)

    async def sync_from_redis(self) -> int:
        """
        Reload the in-memory filter from Redis.
        Called on startup and every 60 seconds by the background worker.

        Returns count of IPs loaded.
        """
        bad_ips = await self.redis.smembers("known_bad_ips")

        # Rebuild the filter to avoid unbounded growth
        self._filter = BloomFilter(
            capacity=settings.bloom_filter_capacity,
            error_rate=settings.bloom_filter_error_rate,
        )

        for ip in bad_ips:
            self._filter.add(ip)

        self._loaded_count = len(bad_ips)
        logger.info(
            "Bloom filter synced",
            extra={"ip_count": self._loaded_count}
        )
        return self._loaded_count

    @property
    def loaded_count(self) -> int:
        return self._loaded_count

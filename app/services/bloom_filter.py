import structlog
from pybloom_live import BloomFilter
from redis.asyncio import Redis

from app.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


class BloomFilterService:
    """
    Two in-memory Bloom filters for O(1) hot-path screening.

    Filter 1 — known_bad_ips:
        Screens every request against known malicious IP addresses.
        Eliminates a Redis round-trip on the common case.

    Filter 2 — abusive_agents:
        Screens User-Agent headers against known bot/scraper signatures.
        Catches automated clients that rotate IPs but reuse agents.

    Both filters sync from Redis every 60 seconds via the bloom sync worker.
    False positive rate is configurable — at 0.1%, 1 in 1000 legitimate
    requests may be incorrectly flagged. Shadow mode catches these before
    enforcement is enabled.
    """

    def __init__(self, redis: Redis):
        self.redis = redis
        self._ip_filter = BloomFilter(
            capacity=settings.bloom_filter_capacity,
            error_rate=settings.bloom_filter_error_rate,
        )
        self._agent_filter = BloomFilter(
            capacity=settings.bloom_filter_capacity,
            error_rate=settings.bloom_filter_error_rate,
        )
        self._loaded_ip_count = 0
        self._loaded_agent_count = 0

    # ── IP filter ─────────────────────────────────────────────────────────────

    def add_ip(self, ip: str) -> None:
        """Add an IP to the in-memory filter."""
        self._ip_filter.add(ip)

    def might_contain_ip(self, ip: str) -> bool:
        """
        Returns True if IP is POSSIBLY in the bad IP set.
        Returns False if IP is DEFINITELY NOT in the set.
        """
        return ip in self._ip_filter

    async def add_ip_to_redis(self, ip: str) -> None:
        """Persist a bad IP to Redis so it survives restarts."""
        await self.redis.sadd("known_bad_ips", ip)
        self.add_ip(ip)

    # ── Agent filter ──────────────────────────────────────────────────────────

    def add_agent(self, user_agent: str) -> None:
        """Add a user-agent string to the in-memory filter."""
        self._agent_filter.add(user_agent)

    def might_contain_agent(self, user_agent: str) -> bool:
        """
        Returns True if user-agent is POSSIBLY in the abusive agents set.
        Returns False if it is DEFINITELY NOT in the set.
        """
        return user_agent in self._agent_filter

    async def add_agent_to_redis(self, user_agent: str) -> None:
        """Persist an abusive user-agent to Redis."""
        await self.redis.sadd("abusive_agents", user_agent)
        self.add_agent(user_agent)

    # ── Sync ──────────────────────────────────────────────────────────────────

    async def sync_from_redis(self) -> int:
        """
        Reload both in-memory filters from Redis.
        Called on startup and every 60 seconds by the background worker.
        Rebuilds filters from scratch to avoid unbounded growth.

        Returns total count of entries loaded across both filters.
        """
        bad_ips = await self.redis.smembers("known_bad_ips")
        bad_agents = await self.redis.smembers("abusive_agents")

        self._ip_filter = BloomFilter(
            capacity=settings.bloom_filter_capacity,
            error_rate=settings.bloom_filter_error_rate,
        )
        self._agent_filter = BloomFilter(
            capacity=settings.bloom_filter_capacity,
            error_rate=settings.bloom_filter_error_rate,
        )

        for ip in bad_ips:
            self._ip_filter.add(ip)

        for agent in bad_agents:
            self._agent_filter.add(agent)

        self._loaded_ip_count = len(bad_ips)
        self._loaded_agent_count = len(bad_agents)

        logger.info(
            "bloom_filter_synced",
            ip_count=self._loaded_ip_count,
            agent_count=self._loaded_agent_count,
        )
        return self._loaded_ip_count + self._loaded_agent_count

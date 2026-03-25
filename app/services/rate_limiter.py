import time
import logging
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

# Lua script runs atomically on the Redis server.
# No other client can interleave between the three operations.
SLIDING_WINDOW_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local request_id = ARGV[4]

-- Remove all entries outside the current window
redis.call('ZREMRANGEBYSCORE', key, 0, now - window * 1000)

-- Count remaining entries
local count = redis.call('ZCARD', key)

if count < limit then
    -- Add current request
    redis.call('ZADD', key, now, request_id)
    -- Set TTL so keys expire automatically
    redis.call('EXPIRE', key, window + 1)
    return {1, limit - count - 1}
else
    return {0, 0}
end
"""


class RateLimiter:
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self._script = self.redis.register_script(SLIDING_WINDOW_SCRIPT)

    async def check_rate_limit(
        self,
        client_id: str,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, int]:
        """
        Check if a client is within their rate limit.

        Uses a sliding window algorithm via Redis sorted sets.
        Each request is stored as a timestamped entry. Entries
        older than the window are removed before counting.

        Returns:
            (allowed, remaining) — allowed is True if request
            should proceed, remaining is how many requests are left.
        """
        key = f"rate_limit:{client_id}"
        now = int(time.time() * 1000)  # milliseconds
        request_id = f"{now}-{client_id}"

        result = await self._script(
            keys=[key],
            args=[now, window_seconds, limit, request_id],
        )

        allowed = bool(result[0])
        remaining = int(result[1])

        if not allowed:
            logger.warning(
                "Rate limit exceeded",
                extra={"client_id": client_id, "limit": limit}
            )

        return allowed, remaining

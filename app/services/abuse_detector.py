import statistics
import time

import structlog
from redis.asyncio import Redis

logger = structlog.get_logger()


class AbuseDetector:
    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def record_auth_failure(
        self,
        ip: str,
        username: str,
        window_seconds: int,
    ) -> None:
        """
        Record a failed authentication attempt on two axes:
        - The source IP (catches one attacker hitting many accounts)
        - The target username (catches many attackers hitting one account)
        """
        ip_key = f"failed_auth:{ip}"
        user_key = f"failed_auth:{username}"

        pipe = self.redis.pipeline()
        pipe.incr(ip_key)
        pipe.expire(ip_key, window_seconds)
        pipe.incr(user_key)
        pipe.expire(user_key, window_seconds)
        await pipe.execute()

        logger.info("auth_failure_recorded", ip=ip, username=username)

    async def is_credential_stuffing(
        self,
        ip: str,
        username: str,
        ip_threshold: int,
        user_threshold: int,
    ) -> tuple[bool, str]:
        """
        Check both axes for credential stuffing signals.

        Returns:
            (is_abuse, reason) — reason explains which threshold
            was exceeded so the caller can log it accurately.
        """
        ip_key = f"failed_auth:{ip}"
        user_key = f"failed_auth:{username}"

        ip_count_raw, user_count_raw = await self.redis.mget(ip_key, user_key)

        ip_count = int(ip_count_raw or 0)
        user_count = int(user_count_raw or 0)

        if ip_count >= ip_threshold:
            return True, f"ip_threshold_exceeded:{ip_count}"

        if user_count >= user_threshold:
            return True, f"user_threshold_exceeded:{user_count}"

        return False, ""

    async def record_request_timing(
        self,
        client_id: str,
        max_samples: int,
    ) -> None:
        """Store the current request timestamp for timing entropy analysis."""
        key = f"request_times:{client_id}"
        now = int(time.time() * 1000)

        pipe = self.redis.pipeline()
        pipe.zadd(key, {str(now): now})
        # Keep only the last N samples
        pipe.zremrangebyrank(key, 0, -(max_samples + 1))
        pipe.expire(key, 3600)
        await pipe.execute()

    async def compute_timing_entropy(
        self,
        client_id: str,
    ) -> float | None:
        """
        Compute standard deviation of inter-request timing gaps.

        Human users have HIGH variance (they pause, think, scroll).
        Bots have LOW variance (requests are suspiciously regular).

        Returns None if not enough samples to compute.
        """
        key = f"request_times:{client_id}"
        timestamps = await self.redis.zrange(key, 0, -1, withscores=True)

        if len(timestamps) < 3:
            return None

        scores = [score for _, score in timestamps]
        gaps = [scores[i + 1] - scores[i] for i in range(len(scores) - 1)]

        if len(gaps) < 2:
            return None

        return float(statistics.stdev(gaps))

    async def is_bot_behavior(
        self,
        client_id: str,
        entropy_threshold: float,
        max_samples: int,
    ) -> tuple[bool, str]:
        """
        Detect bot behavior by checking timing regularity.
        Records the current request then checks entropy.
        """
        await self.record_request_timing(client_id, max_samples)
        entropy = await self.compute_timing_entropy(client_id)

        if entropy is None:
            return False, "insufficient_samples"

        if entropy < entropy_threshold:
            return True, f"low_timing_entropy:{entropy:.2f}"

        return False, ""

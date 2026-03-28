import asyncio
from enum import StrEnum

import structlog
from redis.asyncio import Redis

logger = structlog.get_logger()

SOFT_BLOCK_TTL = 300  # 5 minutes
THROTTLE_DELAY_SECONDS = 2  # delay applied to throttled clients


class ClientState(StrEnum):
    """
    Three escalating enforcement states.

    ALLOWED    → request proceeds normally
    THROTTLED  → request is delayed and served with Retry-After header
                 used when abuse score is elevated but not conclusive
    SOFT_BLOCK → client receives 429 immediately, block expires after TTL
                 used when abuse is confirmed but may be transient
    HARD_BLOCK → client receives 403, IP added to Bloom filter permanently
                 used for confirmed malicious actors
    """

    ALLOWED = "allowed"
    THROTTLED = "throttled"
    SOFT_BLOCK = "soft_block"
    HARD_BLOCK = "hard_block"


class GraduatedResponseService:
    def __init__(self, redis: Redis):
        self.redis = redis

    async def get_client_state(self, ip: str) -> ClientState:
        """
        Check if an IP is currently soft-blocked.
        Hard blocks are handled by the Bloom filter before this runs.
        """
        key = f"blocked_ip:{ip}"
        is_blocked = await self.redis.exists(key)
        if is_blocked:
            return ClientState.SOFT_BLOCK
        return ClientState.ALLOWED

    async def apply_soft_block(self, ip: str, ttl: int = SOFT_BLOCK_TTL) -> None:
        """
        Temporarily block an IP with an auto-expiring Redis key.
        The client will receive 429 responses until the TTL expires.
        If they continue abusing after the block expires, they escalate
        to a hard block via the Bloom filter.
        """
        key = f"blocked_ip:{ip}"
        await self.redis.set(key, "1", ex=ttl)
        logger.warning("soft_block_applied", ip=ip, ttl=ttl)

    async def remove_soft_block(self, ip: str) -> None:
        """Manually lift a soft block — used by admin endpoints."""
        key = f"blocked_ip:{ip}"
        await self.redis.delete(key)
        logger.info("soft_block_removed", ip=ip)

    async def apply_throttle(self) -> None:
        """
        Delay the current request proportional to the abuse signal.
        The client still receives a response but is slowed down.
        Served with a Retry-After header by the middleware.
        """
        await asyncio.sleep(THROTTLE_DELAY_SECONDS)

    async def compute_abuse_score(
        self,
        ip: str,
        client_id: str,
        ip_fail_count: int,
        user_fail_count: int,
        timing_entropy: float | None,
        ip_threshold: int,
        user_threshold: int,
        entropy_threshold: float,
    ) -> tuple[ClientState, str]:
        """
        Compute the graduated response state based on multiple abuse signals.

        Scoring logic:
        - Any single signal near threshold → THROTTLED
        - Any single signal at threshold  → SOFT_BLOCK
        - Existing soft block             → SOFT_BLOCK (from Redis)
        - Bloom filter hit                → HARD_BLOCK (handled upstream)

        Returns (ClientState, reason) so the caller can log and respond
        with the appropriate status code and headers.
        """
        # Check existing soft block first
        existing_state = await self.get_client_state(ip)
        if existing_state == ClientState.SOFT_BLOCK:
            return ClientState.SOFT_BLOCK, "existing_soft_block"

        # Score each signal
        ip_ratio = ip_fail_count / ip_threshold if ip_threshold else 0
        user_ratio = user_fail_count / user_threshold if user_threshold else 0
        low_entropy = timing_entropy is not None and timing_entropy < entropy_threshold

        # Hard thresholds → soft block
        if ip_fail_count >= ip_threshold:
            await self.apply_soft_block(ip)
            return ClientState.SOFT_BLOCK, f"ip_failures:{ip_fail_count}"

        if user_fail_count >= user_threshold:
            await self.apply_soft_block(ip)
            return ClientState.SOFT_BLOCK, f"user_failures:{user_fail_count}"

        if (
            low_entropy
            and timing_entropy is not None
            and timing_entropy < entropy_threshold * 0.5
        ):
            await self.apply_soft_block(ip)
            return ClientState.SOFT_BLOCK, f"very_low_entropy:{timing_entropy:.2f}"

        # Approaching thresholds → throttle
        if ip_ratio >= 0.7 or user_ratio >= 0.7:
            return ClientState.THROTTLED, "approaching_auth_threshold"

        if low_entropy and timing_entropy is not None:
            return ClientState.THROTTLED, f"low_entropy:{timing_entropy:.2f}"

        return ClientState.ALLOWED, ""

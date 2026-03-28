from typing import Any

from fastapi import APIRouter, Depends, Request
from redis.asyncio import Redis

from app.dependencies import get_redis, require_admin
from app.services.bloom_filter import BloomFilterService
from app.services.graduated_response import GraduatedResponseService
from app.services.shadow_logger import ShadowLogger

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/shadow-stats")
async def shadow_stats(
    redis: Redis = Depends(get_redis),
    _: str = Depends(require_admin),  # enforces admin check
) -> dict[str, Any]:
    """Aggregate shadow events by rule for threshold tuning."""
    logger = ShadowLogger(redis)
    return await logger.get_shadow_stats()


@router.post("/block-ip/{ip}")
async def block_ip(
    ip: str,
    request: Request,
    redis: Redis = Depends(get_redis),
    _: str = Depends(require_admin),
) -> dict[str, Any]:
    """Hard block — add IP to Bloom filter and persist to Redis.
    Updates the live in-memory filter immediately so the middleware
    enforces the block on the next request, not after the 60s sync cycle.
    """
    bloom: BloomFilterService = request.app.state.bloom
    await bloom.add_ip_to_redis(ip)
    return {"hard_blocked": ip}


@router.post("/block-agent")
async def block_agent(
    user_agent: str,
    request: Request,
    redis: Redis = Depends(get_redis),
    _: str = Depends(require_admin),
) -> dict[str, Any]:
    """Add a user-agent string to the abusive agents Bloom filter.
    Updates the live in-memory filter immediately.
    """
    bloom: BloomFilterService = request.app.state.bloom
    await bloom.add_agent_to_redis(user_agent)
    return {"blocked_agent": user_agent}


@router.post("/soft-block-ip/{ip}")
async def soft_block_ip(
    ip: str,
    redis: Redis = Depends(get_redis),
    _: str = Depends(require_admin),
) -> dict[str, Any]:
    """Soft block — temporary 429 block with auto-expiry TTL."""
    graduated = GraduatedResponseService(redis)
    await graduated.apply_soft_block(ip)
    return {"soft_blocked": ip}


@router.delete("/soft-block-ip/{ip}")
async def remove_soft_block(
    ip: str,
    redis: Redis = Depends(get_redis),
    _: str = Depends(require_admin),
) -> dict[str, Any]:
    """Lift a soft block manually before it expires."""
    graduated = GraduatedResponseService(redis)
    await graduated.remove_soft_block(ip)
    return {"unblocked": ip}


@router.get("/block-status/{ip}")
async def block_status(
    ip: str,
    request: Request,
    redis: Redis = Depends(get_redis),
    _: str = Depends(require_admin),
) -> dict[str, Any]:
    """Check the current block state of an IP."""
    graduated = GraduatedResponseService(redis)
    bloom: BloomFilterService = request.app.state.bloom

    state = await graduated.get_client_state(ip)
    in_bloom = bloom.might_contain_ip(ip)

    return {
        "ip": ip,
        "soft_blocked": state.value == "soft_block",
        "hard_blocked_bloom": in_bloom,
    }


@router.post("/shadow-mode")
async def set_shadow_mode(
    enabled: bool,
    request: Request,
    redis: Redis = Depends(get_redis),
    _: str = Depends(require_admin),
) -> dict[str, Any]:
    """Toggle shadow mode at runtime without redeployment."""
    await redis.set("config:shadow_mode_enabled", str(enabled).lower())
    return {"shadow_mode_enabled": enabled}

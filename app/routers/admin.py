from fastapi import APIRouter, Depends, Request
from redis.asyncio import Redis
from app.dependencies import get_redis
from app.services.shadow_logger import ShadowLogger
from app.services.bloom_filter import BloomFilterService

router = APIRouter(prefix="/admin", tags=["admin"])

@router.get("/shadow-stats")
async def shadow_stats(redis: Redis = Depends(get_redis)):
    """Aggregate shadow events by rule for threshold tuning."""
    logger = ShadowLogger(redis)
    return await logger.get_shadow_stats()

@router.post("/block-ip/{ip}")
async def block_ip(ip: str, redis: Redis = Depends(get_redis)):
    """Add an IP to the known-bad set and Bloom filter."""
    bloom = BloomFilterService(redis)
    await bloom.add_to_redis(ip)
    return {"blocked": ip}

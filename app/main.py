# app/main.py
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends
from fastapi.responses import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from app.config import get_settings
from app.core.redis_client import create_redis_client, close_redis_client
from app.dependencies import get_settings_dep, Settings
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.auth import AuthMiddleware
from app.middleware.bloom_filter import BloomFilterMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.abuse_detector import AbuseDetectorMiddleware
from app.middleware.shadow_mode import ShadowModeMiddleware
from app.routers import auth, gateway, admin
from app.services.bloom_filter import BloomFilterService
from app.workers.bloom_sync import bloom_sync_worker

logger = logging.getLogger(__name__)
settings = get_settings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ───────────────────────────────────────────────
    app.state.redis = await create_redis_client()

    # Initial Bloom filter load
    app.state.bloom = BloomFilterService(app.state.redis)
    await app.state.bloom.sync_from_redis()

    # Start background sync worker as a non-blocking task
    sync_task = asyncio.create_task(
        bloom_sync_worker(app.state.redis),
        name="bloom_sync_worker",
    )
    logger.info("Application started")

    yield

    # ── Shutdown ──────────────────────────────────────────────
    sync_task.cancel()
    try:
        await sync_task
    except asyncio.CancelledError:
        logger.info("Bloom sync worker stopped cleanly")

    await close_redis_client(app.state.redis)
    logger.info("Application shutdown")


app = FastAPI(title="API Gateway with Abuse Detection", lifespan=lifespan)

# Middleware — added in reverse execution order
# Last added executes first on the way in
app.add_middleware(ShadowModeMiddleware)
app.add_middleware(AbuseDetectorMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(BloomFilterMiddleware)
app.add_middleware(AuthMiddleware)
app.add_middleware(RequestIDMiddleware)

# Routers
app.include_router(auth.router)
app.include_router(gateway.router)
app.include_router(admin.router)


@app.get("/health")
async def health():
    try:
        await app.state.redis.ping()
        redis_status = "ok"
    except Exception:
        redis_status = "error"
    return {
        "status": "ok",
        "redis": redis_status,
        "bloom_filter_loaded": app.state.bloom.loaded_count,
    }


@app.get("/metrics")
async def metrics():
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.get("/debug/config")
async def debug_config(settings: Settings = Depends(get_settings_dep)):
    if settings.app_env != "development":
        return {"error": "not available in production"}
    return {
        "app_env": settings.app_env,
        "rate_limit_requests": settings.rate_limit_requests,
        "shadow_mode_enabled": settings.shadow_mode_enabled,
    }

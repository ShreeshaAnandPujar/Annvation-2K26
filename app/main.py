import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any, cast

import structlog
from fastapi import Depends, FastAPI
from fastapi import Request as FastAPIRequest
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy.pool import QueuePool

from app.config import Settings, get_settings
from app.core.database import engine
from app.core.exceptions import (
    AbuseDetectedError,
    RateLimitExceededError,
)
from app.core.logging import configure_logging
from app.core.metrics import record_pool_stats
from app.core.redis_client import close_redis_client, create_redis_client
from app.dependencies import get_settings_dep
from app.middleware.abuse_detector import AbuseDetectorMiddleware
from app.middleware.auth import AuthMiddleware
from app.middleware.bloom_filter import BloomFilterMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.shadow_mode import ShadowModeMiddleware
from app.routers import admin, auth, gateway
from app.services.bloom_filter import BloomFilterService
from app.workers.bloom_sync import bloom_sync_worker

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    configure_logging()
    logger = structlog.get_logger()

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


@app.exception_handler(RateLimitExceededError)
async def rate_limit_handler(
    request: FastAPIRequest, exc: RateLimitExceededError
) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers,
    )


@app.exception_handler(AbuseDetectedError)
async def abuse_handler(
    request: FastAPIRequest, exc: AbuseDetectedError
) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


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
async def health() -> dict[str, Any]:
    try:
        await app.state.redis.ping()
        redis_status = "ok"
    except Exception:
        redis_status = "error"

    # Pool stats — cheap call, no I/O
    record_pool_stats(engine.sync_engine)
    pool = cast(QueuePool, engine.sync_engine.pool)
    db_pool = {
        "checked_out": pool.checkedout(),
        "checked_in": pool.checkedin(),
        "overflow": pool.overflow(),
        "size": pool.size(),
    }

    return {
        "status": "ok",
        "redis": redis_status,
        "bloom_filter_ips_loaded": app.state.bloom._loaded_ip_count,
        "bloom_filter_agents_loaded": app.state.bloom._loaded_agent_count,
        "db_pool": db_pool,
    }


@app.get("/metrics")
async def metrics() -> Response:
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.get("/debug/config")
async def debug_config(
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, Any]:
    if settings.app_env != "development":
        return {"error": "not available in production"}
    return {
        "app_env": settings.app_env,
        "rate_limit_requests": settings.rate_limit_requests,
        "shadow_mode_enabled": settings.shadow_mode_enabled,
    }

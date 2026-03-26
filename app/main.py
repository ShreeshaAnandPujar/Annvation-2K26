from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from app.core.redis_client import create_redis_client, close_redis_client
from app.services.bloom_filter import BloomFilterService
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.auth import AuthMiddleware
from app.middleware.bloom_filter import BloomFilterMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.abuse_detector import AbuseDetectorMiddleware
from app.middleware.shadow_mode import ShadowModeMiddleware
from app.routers import auth, gateway, admin
from app.config import get_settings

import logging
logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    app.state.redis = await create_redis_client()
    app.state.bloom = BloomFilterService(app.state.redis)
    await app.state.bloom.sync_from_redis()
    logger.info("Application started")
    yield
    # Shutdown
    await close_redis_client(app.state.redis)
    logger.info("Application shutdown")


app = FastAPI(title="API Gateway with Abuse Detection", lifespan=lifespan)

# Middleware — order matters, outermost added last executes first
app.add_middleware(ShadowModeMiddleware)
app.add_middleware(AbuseDetectorMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(BloomFilterMiddleware)
app.add_middleware(AuthMiddleware)
app.add_middleware(RequestIDMiddleware)


@app.get("/health")
async def health():
    try:
        await app.state.redis.ping()
        redis_status = "ok"
    except Exception:
        redis_status = "error"
    return {"status": "ok", "redis": redis_status}

@app.get("/metrics")
async def metrics():
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )

# Routers
app.include_router(auth.router)
app.include_router(gateway.router)
app.include_router(admin.router)

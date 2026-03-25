from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.responses import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from app.config import get_settings
from app.dependencies import get_settings_dep, Settings
from app.core.redis_client import create_redis_client, close_redis_client

import logging
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    app.state.redis = await create_redis_client()
    logger.info("Application started")
    yield
    # Shutdown
    await close_redis_client(app.state.redis)
    logger.info("Application shutdown")

app = FastAPI(title="API Gateway", lifespan=lifespan)

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

@app.get("/debug/config")
async def debug_config(settings: Settings = Depends(get_settings_dep)):
    if settings.app_env != "development":
        return {"error": "not available in production"}
    return {
        "app_env": settings.app_env,
        "rate_limit_requests": settings.rate_limit_requests,
        "shadow_mode_enabled": settings.shadow_mode_enabled,
    }

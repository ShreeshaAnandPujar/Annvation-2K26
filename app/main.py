from fastapi import FastAPI, Depends
from fastapi.responses import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from app.config import get_settings
from app.dependencies import get_settings_dep, Settings

app = FastAPI(title="API Gateway")

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/metrics")
async def metrics():
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )

@app.get("/debug/config")
async def debug_config(settings: Settings = Depends(get_settings_dep)):
    """Only use in development to confirm settings load correctly."""
    if settings.app_env != "development":
        return {"error": "not available in production"}
    return {
        "app_env": settings.app_env,
        "rate_limit_requests": settings.rate_limit_requests,
        "shadow_mode_enabled": settings.shadow_mode_enabled,
    }

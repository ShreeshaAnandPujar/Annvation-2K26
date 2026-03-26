from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from app.services.abuse_detector import AbuseDetector
from app.config import get_settings

settings = get_settings()


class AbuseDetectorMiddleware(BaseHTTPMiddleware):
    """
    Behavioral abuse detection.
    Checks timing entropy for bot detection.
    Auth failure tracking is handled in the auth router.
    """

    async def dispatch(self, request: Request, call_next):
        redis = request.app.state.redis
        client_id = getattr(request.state, "client_id", "anonymous")
        detector = AbuseDetector(redis)

        is_bot, reason = await detector.is_bot_behavior(
            client_id=client_id,
            entropy_threshold=settings.scraping_entropy_threshold,
            max_samples=settings.scraping_sample_size,
        )

        if is_bot:
            if settings.shadow_mode_enabled:
                request.state.shadow_reason = reason
                request.state.shadow_rule = "bot_behavior"
            else:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Abusive behavior detected"},
                )

        return await call_next(request)

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from app.services.shadow_logger import ShadowLogger
from app.config import get_settings

settings = get_settings()


class ShadowModeMiddleware(BaseHTTPMiddleware):
    """
    Last middleware in the chain.
    Logs would-be blocks that were flagged by earlier middleware
    but not enforced because shadow mode is enabled.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if not settings.shadow_mode_enabled:
            return response

        shadow_rule = getattr(request.state, "shadow_rule", None)
        shadow_reason = getattr(request.state, "shadow_reason", "")

        if shadow_rule:
            redis = request.app.state.redis
            request_id = getattr(request.state, "request_id", "unknown")
            client_id = getattr(request.state, "client_id", "anonymous")

            logger = ShadowLogger(redis)
            await logger.log_shadow_event(
                request_id=request_id,
                rule_triggered=shadow_rule,
                client_id=client_id,
                path=request.url.path,
                reason=shadow_reason,
            )

        return response

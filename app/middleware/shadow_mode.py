from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.config import get_settings
from app.core.redis_client import is_shadow_mode_enabled
from app.services.shadow_logger import ShadowLogger

settings = get_settings()


class ShadowModeMiddleware(BaseHTTPMiddleware):
    """
    Last middleware in the chain.
    Logs would-be blocks that were flagged by earlier middleware
    but not enforced because shadow mode is enabled.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)

        # Get redis instance early to check the flag
        redis = request.app.state.redis

        # Perform the dynamic Redis check
        shadow_enabled = await is_shadow_mode_enabled(
            redis, fallback=settings.shadow_mode_enabled
        )

        if not shadow_enabled:
            return response

        shadow_rule = getattr(request.state, "shadow_rule", None)
        shadow_reason = getattr(request.state, "shadow_reason", "")

        if shadow_rule:
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

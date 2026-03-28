from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import get_settings
from app.core.exceptions import RateLimitExceededError
from app.core.metrics import RATE_LIMIT_REJECTIONS
from app.services.rate_limiter import RateLimiter

settings = get_settings()

# Paths excluded from rate limiting
EXCLUDED_PATHS = {
    "/health",
    "/metrics",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/auth/register",
}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding window rate limiter per authenticated client_id.

    Uses RateLimitExceededError so error formatting is consistent
    across all routes and the Retry-After header is always present.
    A legitimate user who hits the limit sees exactly when they can
    retry — a malicious client is slowed without being informed why.
    Public infrastructure paths are excluded — health checks and
    metrics must always be reachable regardless of client abuse score.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)

        redis = request.app.state.redis
        client_host = request.client.host if request.client else "127.0.0.1"
        client_id = getattr(request.state, "client_id", client_host)

        limiter = RateLimiter(redis)
        allowed, remaining = await limiter.check_rate_limit(
            client_id=client_id,
            limit=settings.rate_limit_requests,
            window_seconds=settings.rate_limit_window_seconds,
        )

        if not allowed:
            error = RateLimitExceededError(
                retry_after=settings.rate_limit_window_seconds
            )
            RATE_LIMIT_REJECTIONS.labels(client_id=client_id).inc()
            return JSONResponse(
                status_code=error.status_code,
                content={"detail": error.detail},
                headers=error.headers,
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response

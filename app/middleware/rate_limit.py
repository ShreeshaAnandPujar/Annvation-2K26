from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from app.services.rate_limiter import RateLimiter
from app.config import get_settings

settings = get_settings()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding window rate limiter per client_id.
    client_id is set by AuthMiddleware so we rate limit
    by authenticated identity, not just IP.
    """

    async def dispatch(self, request: Request, call_next):
        redis = request.app.state.redis
        client_id = getattr(request.state, "client_id", request.client.host)

        limiter = RateLimiter(redis)
        allowed, remaining = await limiter.check_rate_limit(
            client_id=client_id,
            limit=settings.rate_limit_requests,
            window_seconds=settings.rate_limit_window_seconds,
        )

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={
                    "Retry-After": str(settings.rate_limit_window_seconds),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response

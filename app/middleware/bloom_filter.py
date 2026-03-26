from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from app.services.bloom_filter import BloomFilterService


class BloomFilterMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        bloom = request.app.state.bloom

        if bloom.might_contain(client_ip):
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied"},
            )

        request.state.client_ip = client_ip
        return await call_next(request)

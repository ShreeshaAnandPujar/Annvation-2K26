from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.security import decode_access_token

# Paths that don't require strict JWT tokens
PUBLIC_PATHS = {
    "/",
    "/dashboard",
    "/health",
    "/metrics",
    "/auth/login",
    "/auth/register",
    "/docs",
    "/openapi.json",
    "/favicon.ico",
}


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Validates JWT token if present, extracts client identity,
    and attaches client_id and client_ip to request state.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "127.0.0.1")
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()
        request.state.client_ip = client_ip

        auth_header = request.headers.get("Authorization", "")
        token = None
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            payload = decode_access_token(token)
            request.state.client_id = payload.get("sub", client_ip) if payload else client_ip
        else:
            request.state.client_id = request.headers.get("X-Client-ID", client_ip)

        # Only internal /admin endpoints require strict valid JWT authentication
        if request.url.path.startswith("/admin"):
            if not token:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Not authenticated"},
                    headers={"WWW-Authenticate": "Bearer"},
                )
            payload = decode_access_token(token)
            if payload is None:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or expired token"},
                    headers={"WWW-Authenticate": "Bearer"},
                )
            request.state.client_id = payload.get("sub", "unknown")

        return await call_next(request)

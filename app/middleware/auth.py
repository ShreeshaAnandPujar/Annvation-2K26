from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.security import decode_access_token

# Paths that don't require strict JWT tokens
PUBLIC_PATHS = {
    "/health",
    "/metrics",
    "/auth/login",
    "/auth/register",
    "/docs",
    "/openapi.json",
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

        # Public paths or proxied gateway paths
        if request.url.path in PUBLIC_PATHS or request.url.path.startswith("/gateway"):
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
                payload = decode_access_token(token)
                request.state.client_id = payload.get("sub", client_ip) if payload else client_ip
            else:
                request.state.client_id = request.headers.get("X-Client-ID", client_ip)
            return await call_next(request)

        # Standard protected internal endpoints (e.g. /admin)
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Not authenticated"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header.split(" ")[1]
        payload = decode_access_token(token)
        if payload is None:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        request.state.client_id = payload.get("sub", "unknown")
        return await call_next(request)

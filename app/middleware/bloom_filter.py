from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.metrics import BLOOM_FILTER_HITS


class BloomFilterMiddleware(BaseHTTPMiddleware):
    """
    O(1) in-memory screening against two known-bad sets.

    Check 1 — IP address against known_bad_ips.
    Check 2 — User-Agent header against abusive_agents.

    Both checks use the in-memory Bloom filter — no Redis round-trip.
    Confirmed bad entries are added to Redis for persistence and
    sync'd back to all gateway instances within one sync interval.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path
        # Allow internal telemetry, dashboard, and administrative routes
        if (
            path in (
                "/",
                "/dashboard",
                "/health",
                "/metrics",
                "/docs",
                "/openapi.json",
                "/favicon.ico",
            )
            or path.startswith("/api/autonomous-agent")
            or path.startswith("/api/dashboard")
            or path.startswith("/api/block-ip")
            or path.startswith("/api/unblock-ip")
            or path.startswith("/api/clear-")
            or path.startswith("/docs")
            or path.startswith("/redoc")
        ):
            return await call_next(request)

        client_ip = getattr(
            request.state,
            "client_ip",
            request.headers.get("X-Forwarded-For", request.client.host if request.client else "127.0.0.1"),
        )
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()

        user_agent = request.headers.get("User-Agent", "")
        bloom = getattr(request.app.state, "bloom", None)

        from app.services.threat_engine import threat_engine
        is_banned, ban_cat, rem_ttl = threat_engine.local_store.is_blocked(client_ip)
        if is_banned and rem_ttl > 0:
            BLOOM_FILTER_HITS.labels(filter_type="ip").inc()
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access Blocked by Perimeter Defense",
                    "detail": f"Access denied — IP address {client_ip} is actively banned across the gateway firewall.",
                    "blocked_ip": client_ip,
                    "ttl_remaining_seconds": round(rem_ttl, 1),
                    "category": ban_cat.value if ban_cat else "PERIMETER_BAN",
                },
                headers={
                    "Retry-After": str(max(1, int(rem_ttl))),
                    "X-Threat-Score": "1.0",
                    "X-Threat-Category": ban_cat.value if ban_cat else "MANUAL_BAN",
                    "X-Threat-Action": "HARD_BLOCK",
                },
            )

        if bloom and user_agent and bloom.might_contain_agent(user_agent):
            BLOOM_FILTER_HITS.labels(filter_type="agent").inc()
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access Blocked by Perimeter Defense",
                    "detail": "Access denied — abusive user agent signature",
                    "user_agent": user_agent,
                },
                headers={
                    "X-Threat-Score": "1.0",
                    "X-Threat-Category": "AUTOMATED_BOT",
                    "X-Threat-Action": "HARD_BLOCK",
                },
            )

        if bloom and user_agent and bloom.might_contain_agent(user_agent):
            BLOOM_FILTER_HITS.labels(filter_type="agent").inc()
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access Blocked by Perimeter Defense",
                    "detail": "Access denied — abusive user agent signature",
                    "user_agent": user_agent,
                },
                headers={
                    "X-Threat-Score": "1.0",
                    "X-Threat-Category": "AUTOMATED_BOT",
                    "X-Threat-Action": "HARD_BLOCK",
                },
            )

        request.state.client_ip = client_ip
        request.state.user_agent = user_agent
        return await call_next(request)

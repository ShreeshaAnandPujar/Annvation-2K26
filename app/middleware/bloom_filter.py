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
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("User-Agent", "")
        bloom = request.app.state.bloom

        if bloom.might_contain_ip(client_ip):
            BLOOM_FILTER_HITS.labels(filter_type="ip").inc()
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied — known bad IP"},
            )

        if user_agent and bloom.might_contain_agent(user_agent):
            BLOOM_FILTER_HITS.labels(filter_type="agent").inc()
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied — abusive user agent"},
            )

        request.state.client_ip = client_ip
        request.state.user_agent = user_agent
        return await call_next(request)

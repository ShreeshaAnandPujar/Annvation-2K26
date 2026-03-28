import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.metrics import REQUEST_DURATION, REQUESTS_TOTAL


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    First middleware in the chain.
    Attaches a unique trace ID to every request.
    All subsequent logs include this ID for correlation.
    Records end-to-end latency and total request count for Prometheus.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start

        route = request.url.path
        REQUEST_DURATION.observe(duration)
        REQUESTS_TOTAL.labels(
            status_code=str(response.status_code),
            route=route,
        ).inc()

        response.headers["X-Request-ID"] = request_id
        return response

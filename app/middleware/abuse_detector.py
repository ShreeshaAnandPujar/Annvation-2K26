from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import get_settings
from app.core.metrics import ABUSE_DETECTIONS
from app.core.redis_client import is_shadow_mode_enabled
from app.services.abuse_detector import AbuseDetector
from app.services.graduated_response import (
    SOFT_BLOCK_TTL,
    THROTTLE_DELAY_SECONDS,
    ClientState,
    GraduatedResponseService,
)

settings = get_settings()


class AbuseDetectorMiddleware(BaseHTTPMiddleware):
    """
    Behavioral abuse detection with graduated enforcement.

    States in escalating order:
    ALLOWED    → request proceeds normally
    THROTTLED  → request delayed, Retry-After header attached
    SOFT_BLOCK → 429 returned immediately, block stored in Redis with TTL
    HARD_BLOCK → 403 returned, handled upstream by BloomFilterMiddleware

    Shadow mode overrides enforcement — would-be blocks are logged
    but requests are allowed through for threshold tuning.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        redis = request.app.state.redis
        client_id = getattr(request.state, "client_id", "anonymous")
        client_ip = getattr(request.state, "client_ip", "unknown")

        detector = AbuseDetector(redis)
        graduated = GraduatedResponseService(redis)

        # Gather abuse signals
        ip_count_raw, user_count_raw = await redis.mget(
            f"failed_auth:{client_ip}",
            f"failed_auth:{client_id}",
        )
        ip_fail_count = int(ip_count_raw or 0)
        user_fail_count = int(user_count_raw or 0)

        # Record timing and compute entropy
        await detector.record_request_timing(client_id, settings.scraping_sample_size)
        timing_entropy = await detector.compute_timing_entropy(client_id)

        # Compute graduated state
        state, reason = await graduated.compute_abuse_score(
            ip=client_ip,
            client_id=client_id,
            ip_fail_count=ip_fail_count,
            user_fail_count=user_fail_count,
            timing_entropy=timing_entropy,
            ip_threshold=settings.auth_failure_ip_threshold,
            user_threshold=settings.auth_failure_user_threshold,
            entropy_threshold=settings.scraping_entropy_threshold,
        )

        # Shadow mode — log but never enforce
        shadow_enabled = await is_shadow_mode_enabled(
            redis, fallback=settings.shadow_mode_enabled
        )
        if shadow_enabled and state != ClientState.ALLOWED:
            ABUSE_DETECTIONS.labels(
                state=state.value,
                reason_type=reason.split(":")[0],
            ).inc()
            request.state.shadow_rule = f"abuse_detector:{state.value}"
            request.state.shadow_reason = reason
            return await call_next(request)

        # Graduated enforcement
        if state == ClientState.SOFT_BLOCK:
            ABUSE_DETECTIONS.labels(
                state="soft_block",
                reason_type=reason.split(":")[0],
            ).inc()
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests — temporary block applied"},
                headers={"Retry-After": str(SOFT_BLOCK_TTL)},
            )

        if state == ClientState.THROTTLED:
            ABUSE_DETECTIONS.labels(
                state="throttled",
                reason_type=reason.split(":")[0],
            ).inc()
            await graduated.apply_throttle()
            response = await call_next(request)
            response.headers["Retry-After"] = str(THROTTLE_DELAY_SECONDS)
            return response

        return await call_next(request)

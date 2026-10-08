import asyncio
import json
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import get_settings
from app.core.metrics import ABUSE_DETECTIONS
from app.core.redis_client import is_shadow_mode_enabled
from app.services.threat_engine import (
    EnforcementAction,
    threat_engine,
)

settings = get_settings()


def extract_client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        ip = xff.split(",")[0].strip()
        if ip:
            return ip
    x_real = request.headers.get("X-Real-IP")
    if x_real:
        return x_real.strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


class AbuseDetectorMiddleware(BaseHTTPMiddleware):
    """
    Advanced Behavioral Abuse & Threat Detection Middleware (Pygenic Arc).

    Evaluates every incoming request against:
    1. Credential Stuffing (Dual-axis IP & Username failures)
    2. Content Scraping (Inter-arrival timing entropy & pacing)
    3. Endpoint Enumeration / IDOR (Sequential ID walking & 404 probing)
    4. Abnormal Request Sequences (Markov transition workflow validation)
    5. Benign Burst Traffic (Flash-sale human variance discrimination)

    Enforces Graduated Actions:
    - ALLOWED: Normal processing
    - THROTTLED: Async delay + Retry-After header
    - SOFT_BLOCK: 429 Too Many Requests with TTL
    - HARD_BLOCK: 403 Forbidden with permanent block
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        redis = getattr(request.app.state, "redis", None)
        client_ip = extract_client_ip(request)
        request.state.client_ip = client_ip
        client_id = getattr(request.state, "client_id", None) or client_ip
        path = request.url.path

        # Ignore internal telemetry, dashboard, and administrative routes from threat evaluation
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

        # Extract target username if present in auth attempts
        target_username = None
        if path.endswith("/login") and request.method == "POST":
            try:
                body = await request.body()
                if body:
                    data = json.loads(body.decode("utf-8"))
                    target_username = data.get("username")
            except Exception:
                pass

        # Perform Behavioral Threat Assessment
        verdict = threat_engine.analyze_request(
            client_id=client_id,
            ip=client_ip,
            path=path,
            username=target_username,
        )
        request.state.threat_verdict = verdict

        # Shadow mode check
        shadow_enabled = False
        if redis:
            try:
                shadow_enabled = await is_shadow_mode_enabled(
                    redis, fallback=settings.shadow_mode_enabled
                )
            except Exception:
                shadow_enabled = settings.shadow_mode_enabled
        # Actively banned IPs must NEVER be bypassed by shadow mode
        is_actively_banned, _, _ = threat_engine.local_store.is_blocked(client_ip)
        if is_actively_banned:
            shadow_enabled = False

        if shadow_enabled and verdict.action != EnforcementAction.ALLOWED:
            try:
                ABUSE_DETECTIONS.labels(
                    state=verdict.action.value.lower(),
                    reason_type=verdict.behaviour_category.value.lower(),
                ).inc()
            except Exception:
                pass
            request.state.shadow_rule = f"threat_engine:{verdict.behaviour_category.value}"
            request.state.shadow_reason = verdict.explanation
            response = await call_next(request)
            threat_engine.record_response_status(client_id, client_ip, path, response.status_code, target_username)
            self._attach_threat_headers(response, verdict)
            return response

        # Graduated Enforcement
        if verdict.action in (EnforcementAction.SOFT_BLOCK, EnforcementAction.HARD_BLOCK):
            try:
                ABUSE_DETECTIONS.labels(
                    state=verdict.action.value.lower(),
                    reason_type=verdict.behaviour_category.value.lower(),
                ).inc()
            except Exception:
                pass

            status_code = 403 if verdict.action == EnforcementAction.HARD_BLOCK else 429
            content = {
                "error": "Access Blocked by API Threat Gateway",
                "risk_score": verdict.risk_score,
                "behaviour_category": verdict.behaviour_category.value,
                "action": verdict.action.value,
                "explanation": verdict.explanation,
                "evidence": verdict.evidence,
            }
            headers = {
                "Retry-After": "180",
                "X-Threat-Score": str(verdict.risk_score),
                "X-Threat-Category": verdict.behaviour_category.value,
                "X-Threat-Action": verdict.action.value,
            }
            return JSONResponse(status_code=status_code, content=content, headers=headers)

        if verdict.action == EnforcementAction.THROTTLED:
            try:
                ABUSE_DETECTIONS.labels(
                    state="throttled",
                    reason_type=verdict.behaviour_category.value.lower(),
                ).inc()
            except Exception:
                pass
            # Delay to degrade automation
            await asyncio.sleep(1.5)
            response = await call_next(request)
            threat_engine.record_response_status(client_id, client_ip, path, response.status_code, target_username)
            response.headers["Retry-After"] = "2"
            self._attach_threat_headers(response, verdict)
            return response

        # ALLOWED
        response = await call_next(request)
        threat_engine.record_response_status(client_id, client_ip, path, response.status_code, target_username)
        self._attach_threat_headers(response, verdict)
        return response

    @staticmethod
    def _attach_threat_headers(response: Response, verdict) -> None:
        response.headers["X-Threat-Score"] = str(verdict.risk_score)
        response.headers["X-Threat-Category"] = verdict.behaviour_category.value
        response.headers["X-Threat-Action"] = verdict.action.value

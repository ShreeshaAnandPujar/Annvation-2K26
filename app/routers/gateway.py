"""
Gateway Reverse Proxy & Upstream Dispatcher

Receives requests routed through the API Gateway, applies behavioral
threat analysis in coordination with the middleware, and dynamically forwards
clean requests to the protected upstream target application (e.g. VulnStore).
"""

import json
from typing import Any, Dict
import httpx
from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/gateway", tags=["gateway"])
UPSTREAM_BASE_URL = "http://127.0.0.1:8001"


@router.api_route("", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@router.api_route("/", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@router.api_route("/{upstream_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def gateway_proxy(request: Request, upstream_path: str = ""):
    """
    Proxies requests to the upstream application while attaching threat analysis metadata.
    """
    client_id = getattr(request.state, "client_id", "anonymous")
    client_ip = getattr(request.state, "client_ip", request.client.host if request.client else "127.0.0.1")
    request_id = getattr(request.state, "request_id", "req-unknown")
    verdict = getattr(request.state, "threat_verdict", None)

    # Standard threat headers
    headers_to_attach = {
        "X-Gateway-Request-ID": request_id,
        "X-Protected-By": "Pygenic-Arc-Gateway (Team Rudranix)",
    }
    if verdict:
        headers_to_attach["X-Threat-Score"] = str(round(verdict.risk_score, 3))
        headers_to_attach["X-Threat-Category"] = verdict.behaviour_category.value
        headers_to_attach["X-Threat-Action"] = verdict.action.value
        headers_to_attach["X-Threat-Evidence"] = json.dumps(verdict.evidence)

    # Prepare forwarding to upstream
    clean_path = upstream_path.lstrip("/")
    target_url = f"{UPSTREAM_BASE_URL}/{clean_path}"
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"

    body = await request.body()
    forward_headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
    forward_headers["X-Forwarded-For"] = client_ip
    forward_headers["X-Client-ID"] = client_id

    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
            upstream_resp = await client.request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                content=body,
            )
            resp_headers = dict(upstream_resp.headers)
            resp_headers.update(headers_to_attach)

            return Response(
                content=upstream_resp.content,
                status_code=upstream_resp.status_code,
                headers=resp_headers,
                media_type=upstream_resp.headers.get("content-type"),
            )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "error": "Upstream target application unreachable",
                "target_url": target_url,
                "detail": str(e),
                "client_id": client_id,
                "client_ip": client_ip,
                "threat_assessment": verdict.to_dict() if verdict else None,
            },
            headers=headers_to_attach,
        )


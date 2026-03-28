from typing import Any

from fastapi import APIRouter, Request

router = APIRouter(prefix="/gateway", tags=["gateway"])


@router.get("/proxy")
async def proxy(request: Request) -> dict[str, Any]:
    """
    Represents the upstream service endpoint.
    In production this would forward to real backend services.
    All abuse detection happens in middleware before reaching here.
    """
    client_id = getattr(request.state, "client_id", "anonymous")
    request_id = getattr(request.state, "request_id", "unknown")

    return {
        "message": "Request reached upstream service",
        "client_id": client_id,
        "request_id": request_id,
    }

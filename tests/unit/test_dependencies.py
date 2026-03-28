from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.config import get_settings
from app.dependencies import require_admin


@pytest.mark.asyncio
async def test_require_admin_missing_token():
    request = MagicMock()
    request.headers.get.return_value = ""
    settings = get_settings()
    with pytest.raises(HTTPException) as exc:
        await require_admin(request=request, settings=settings)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_require_admin_non_admin_user():
    request = MagicMock()
    request.headers.get.return_value = "Bearer sometoken"
    settings = get_settings()
    # Token has role: "user" — should be denied
    with patch(
        "app.dependencies.decode_access_token",
        return_value={"sub": "regularuser", "role": "user"},
    ):
        with pytest.raises(HTTPException) as exc:
            await require_admin(request=request, settings=settings)
        assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_require_admin_valid_admin():
    request = MagicMock()
    request.headers.get.return_value = "Bearer sometoken"
    settings = get_settings()
    with patch(
        "app.dependencies.decode_access_token",
        return_value={"sub": "adminuser", "role": "admin"},
    ):
        username = await require_admin(request=request, settings=settings)
        assert username == "adminuser"

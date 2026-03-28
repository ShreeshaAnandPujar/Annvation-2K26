from unittest.mock import AsyncMock, patch

import pytest

from app.services.graduated_response import ClientState


async def get_token(client) -> str:
    await client.post(
        "/auth/register",
        json={
            "username": "enforcementuser",
            "email": "enforcement@test.com",
            "password": "secret123",
        },
    )
    response = await client.post(
        "/auth/login",
        json={
            "username": "enforcementuser",
            "password": "secret123",
        },
    )
    return response.json()["access_token"]


@pytest.mark.asyncio
async def test_soft_blocked_ip_gets_429(client):
    """A soft-blocked IP receives 429 on any request.
    Shadow mode is disabled so enforcement actually runs.
    """
    token = await get_token(client)

    with patch(
        "app.middleware.abuse_detector.GraduatedResponseService.compute_abuse_score",
        new_callable=AsyncMock,
        return_value=(ClientState.SOFT_BLOCK, "ip_failures:10"),
    ):
        response = await client.get(
            "/gateway/proxy",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 429
    assert "Retry-After" in response.headers


@pytest.mark.asyncio
async def test_throttled_client_gets_retry_after_header(client):
    """A throttled client still gets a 200 but with Retry-After header.
    Shadow mode is disabled so enforcement actually runs.
    """
    token = await get_token(client)

    with (
        patch(
            "app.middleware.abuse_detector.GraduatedResponseService.compute_abuse_score",
            new_callable=AsyncMock,
            return_value=(ClientState.THROTTLED, "approaching_auth_threshold"),
        ),
        patch(
            "app.middleware.abuse_detector.GraduatedResponseService.apply_throttle",
            new_callable=AsyncMock,
        ),
    ):
        response = await client.get(
            "/gateway/proxy",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    assert "Retry-After" in response.headers


@pytest.mark.asyncio
async def test_shadow_mode_logs_would_be_block(client):
    """With shadow mode ON, a would-be block is logged but request goes through."""
    await client.post(
        "/auth/register",
        json={
            "username": "shadowuser",
            "email": "shadow@test.com",
            "password": "secret123",
        },
    )
    login = await client.post(
        "/auth/login",
        json={
            "username": "shadowuser",
            "password": "secret123",
        },
    )
    token = login.json()["access_token"]

    with (
        patch(
            "app.middleware.abuse_detector.GraduatedResponseService.compute_abuse_score",
            new_callable=AsyncMock,
            return_value=(ClientState.SOFT_BLOCK, "ip_failures:10"),
        ),
        patch(
            "app.middleware.abuse_detector.settings.shadow_mode_enabled",
            True,
        ),
        patch(
            "app.middleware.shadow_mode.settings.shadow_mode_enabled",
            True,
        ),
    ):
        response = await client.get(
            "/gateway/proxy",
            headers={"Authorization": f"Bearer {token}"},
        )

    # Shadow mode — request goes through, not blocked
    assert response.status_code == 200

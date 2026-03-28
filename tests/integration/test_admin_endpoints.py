import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_shadow_stats_returns_empty(
    client: AsyncClient, admin_token: str
) -> None:
    response = await client.get(
        "/admin/shadow-stats",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 0


@pytest.mark.asyncio
async def test_hard_block_ip(client: AsyncClient, admin_token: str) -> None:
    response = await client.post(
        "/admin/block-ip/192.168.1.1",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert response.json()["hard_blocked"] == "192.168.1.1"


@pytest.mark.asyncio
async def test_soft_block_ip(client: AsyncClient, admin_token: str) -> None:
    response = await client.post(
        "/admin/soft-block-ip/10.0.0.5",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert response.json()["soft_blocked"] == "10.0.0.5"


@pytest.mark.asyncio
async def test_remove_soft_block(client: AsyncClient, admin_token: str) -> None:
    await client.post(
        "/admin/soft-block-ip/10.0.0.6",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    response = await client.delete(
        "/admin/soft-block-ip/10.0.0.6",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert response.json()["unblocked"] == "10.0.0.6"


@pytest.mark.asyncio
async def test_block_status_clean_ip(client: AsyncClient, admin_token: str) -> None:
    response = await client.get(
        "/admin/block-status/9.9.9.9",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ip"] == "9.9.9.9"
    assert data["soft_blocked"] is False


@pytest.mark.asyncio
async def test_block_agent(client: AsyncClient, admin_token: str) -> None:
    response = await client.post(
        "/admin/block-agent",
        params={"user_agent": "python-requests/2.28"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert response.json()["blocked_agent"] == "python-requests/2.28"


@pytest.mark.asyncio
async def test_blocked_agent_gets_403(client: AsyncClient, admin_token: str) -> None:
    """A request with a known-bad User-Agent is rejected at the Bloom filter."""
    await client.post(
        "/admin/block-agent",
        params={"user_agent": "evil-bot/1.0"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    from app.main import app as fastapi_app

    await fastapi_app.state.bloom.sync_from_redis()

    response = await client.get(
        "/gateway/proxy",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "User-Agent": "evil-bot/1.0",
        },
    )
    assert response.status_code == 403
    assert "abusive user agent" in response.json()["detail"]


@pytest.mark.asyncio
async def test_non_admin_cannot_access_admin_routes(client: AsyncClient) -> None:
    """A regular user receives 403 on all admin endpoints."""
    await client.post(
        "/auth/register",
        json={
            "username": "regularuser",
            "email": "regular@test.com",
            "password": "pass123",
        },
    )
    login = await client.post(
        "/auth/login",
        json={
            "username": "regularuser",
            "password": "pass123",
        },
    )
    token = login.json()["access_token"]

    response = await client.get(
        "/admin/shadow-stats",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required"

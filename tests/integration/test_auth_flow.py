import pytest
from httpx import AsyncClient, ASGITransport
from asgi_lifespan import LifespanManager
from app.main import app
from sqlalchemy import select
from app.models.user import User


@pytest.fixture
async def client():
    async with LifespanManager(app, startup_timeout=30.0) as manager:
        async with AsyncClient(
            transport=ASGITransport(app=manager.app),
            base_url="http://test"
        ) as c:
            yield c


@pytest.mark.asyncio
async def test_register_and_login(client):
    response = await client.post("/auth/register", json={
        "username": "integrationuser",
        "email": "integration@test.com",
        "password": "testpass123",
    })
    assert response.status_code == 201
    assert response.json()["username"] == "integrationuser"

    response = await client.post("/auth/login", json={
        "username": "integrationuser",
        "password": "testpass123",
    })
    assert response.status_code == 200
    assert "access_token" in response.json()


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    response = await client.post("/auth/login", json={
        "username": "integrationuser",
        "password": "wrongpassword",
    })
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_gateway_requires_auth(client):
    response = await client.get("/gateway/proxy")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_gateway_with_valid_token(client):
    await client.post("/auth/register", json={
        "username": "gatewayuser",
        "email": "gateway@test.com",
        "password": "testpass123",
    })
    login = await client.post("/auth/login", json={
        "username": "gatewayuser",
        "password": "testpass123",
    })
    token = login.json()["access_token"]

    response = await client.get(
        "/gateway/proxy",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["client_id"] == "gatewayuser"

async def test_register_persists_user(client, db_session):
    await client.post("/auth/register", json={
        "username": "dbtest",
        "email": "db@test.com",
        "password": "secret123",
    })
    result = await db_session.execute(
        select(User).where(User.username == "dbtest")
    )
    user = result.scalar_one_or_none()
    assert user is not None
    assert user.email == "db@test.com"
    assert user.is_active is True

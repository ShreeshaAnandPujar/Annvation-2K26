import os

import pytest_asyncio
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ── 1. Load test environment variables FIRST ─────────────────────────────────
# Must happen before any app imports so Pydantic reads the correct values.
load_dotenv(".env.test")

TEST_DATABASE_URL: str = os.environ["TEST_DATABASE_URL"]
TEST_REDIS_URL: str = os.environ["TEST_REDIS_URL"]

# ── 2. Map to standard variable names that pydantic-settings expects ──────────
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["REDIS_URL"] = TEST_REDIS_URL
os.environ["APP_ENV"] = "test"
os.environ["SHADOW_MODE_ENABLED"] = os.environ.get("SHADOW_MODE_ENABLED", "false")

# ── 3. Clear settings cache so it rebuilds with the test values ───────────────
from app.config import get_settings

get_settings.cache_clear()

# ── 4. App imports (safe now that env is fully configured) ────────────────────
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.pool import NullPool

from app.core.database import Base
from app.dependencies import get_db
from app.main import app

# ── 5. Isolated test database engine ─────────────────────────────────────────
# NullPool prevents connections from persisting between tests.
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    poolclass=NullPool,
    echo=False,
)

TestingSessionLocal = async_sessionmaker(
    bind=test_engine,
    expire_on_commit=False,
    autoflush=False,
)


# ── 6. Override the FastAPI DB dependency ────────────────────────────────────
async def override_get_db():
    async with TestingSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


app.dependency_overrides[get_db] = override_get_db


# ── 7. Fixtures ───────────────────────────────────────────────────────────────


@pytest_asyncio.fixture(autouse=True, scope="session")
async def setup_test_schema():
    """
    Runs exactly ONCE at the very beginning of the test session.
    Drops and recreates the schema to guarantee it matches the current models.
    This completely removes the need to run Alembic on the test DB.
    """
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture(autouse=True, scope="function")
async def reset_database(setup_test_schema):
    """
    Runs before EVERY individual test.
    Fast truncation keeps tests isolated without the overhead of schema rebuilding.
    """
    async with test_engine.begin() as conn:
        await conn.execute(text("TRUNCATE TABLE users RESTART IDENTITY CASCADE"))
    yield


@pytest_asyncio.fixture(autouse=True, scope="function")
async def reset_redis():
    """Flush the test Redis DB before and after each test.
    Prevents rate limit counters and auth failure keys from
    leaking between tests.
    """
    redis = Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    await redis.flushdb()
    yield
    await redis.flushdb()
    await redis.aclose()


@pytest_asyncio.fixture(scope="function")
async def db_session():
    """Expose a direct DB session for asserting database state.

    Use this when you want to verify what was actually written
    to the database without going through the HTTP layer.

    Example:
        async def test_user_saved(client, db_session):
            await client.post("/auth/register", json={...})
            result = await db_session.execute(select(User))
            assert result.scalar_one_or_none() is not None
    """
    async with TestingSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client():
    """Full integration test client with lifespan support.
    LifespanManager triggers the FastAPI startup/shutdown events
    so app.state.redis and app.state.bloom are properly initialized.
    """
    async with LifespanManager(app) as manager:
        async with AsyncClient(
            transport=ASGITransport(app=manager.app),
            base_url="http://test",
        ) as ac:
            yield ac


@pytest_asyncio.fixture(scope="function")
async def admin_token(client: AsyncClient, db_session: AsyncSession) -> str:
    """Register a user and promote them to admin in the DB."""
    await client.post(
        "/auth/register",
        json={
            "username": "admin",
            "email": "admin@test.com",
            "password": "adminpass123",
        },
    )
    # Promote to admin directly — simulates an ops team DB update
    await db_session.execute(
        text("UPDATE users SET role = 'admin' WHERE username = 'admin'")
    )
    await db_session.commit()

    response = await client.post(
        "/auth/login",
        json={
            "username": "admin",
            "password": "adminpass123",
        },
    )
    return response.json()["access_token"]

# tests/conftest.py
import os
import pytest
from dotenv import load_dotenv
import pytest_asyncio

# ── 1. Load test environment variables FIRST ─────────────────────────────────
# Must happen before any app imports so Pydantic reads the correct values.
load_dotenv(".env.test")

TEST_DATABASE_URL: str = os.environ["TEST_DATABASE_URL"]
TEST_REDIS_URL: str = os.environ["TEST_REDIS_URL"]

# ── 2. Map to standard variable names that pydantic-settings expects ──────────
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["REDIS_URL"] = TEST_REDIS_URL
os.environ["APP_ENV"] = "test"

# ── 3. Clear settings cache so it rebuilds with the test values ───────────────
from app.config import get_settings
get_settings.cache_clear()

# ── 4. App imports (safe now that env is fully configured) ────────────────────
from asgi_lifespan import LifespanManager
from httpx import AsyncClient, ASGITransport
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy import text

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

@pytest_asyncio.fixture(autouse=True, scope="function")
async def reset_database():
    """Ensure tables exist then truncate before each test.
    TRUNCATE is faster than drop_all/create_all and avoids
    rebuilding the schema on every test.
    """
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(
            text("TRUNCATE TABLE users RESTART IDENTITY CASCADE")
        )
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

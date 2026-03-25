from collections.abc import AsyncGenerator
from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis
from app.config import Settings, get_settings
from app.core.database import AsyncSessionFactory


def get_settings_dep() -> Settings:
    return get_settings()

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionFactory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def get_redis(request: Request) -> Redis:
    """Get the Redis client from app state."""
    return request.app.state.redis

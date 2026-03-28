from collections.abc import AsyncGenerator
from typing import cast

from fastapi import Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.core.database import AsyncSessionFactory
from app.core.security import decode_access_token
from app.models.user import UserRole


def get_settings_dep() -> Settings:
    return get_settings()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionFactory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def get_redis(request: Request) -> Redis:
    """Get the Redis client from app state."""
    return cast(Redis, request.app.state.redis)


async def require_admin(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> str:
    """
    Restricts access to users with the admin role.
    Role is embedded in the JWT at login time from the database User.role column.
    No database query needed on each request — the JWT claim carries the role.

    To promote a user to admin, update their role column directly:
        UPDATE users SET role = 'admin' WHERE username = 'targetuser';
    Then ask them to log in again to receive a token with the updated claim.
    """
    auth_header = request.headers.get("Authorization", "")

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(parts[1])
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = cast(str, payload.get("sub", ""))
    role = cast(str, payload.get("role", UserRole.USER))

    if role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    return username

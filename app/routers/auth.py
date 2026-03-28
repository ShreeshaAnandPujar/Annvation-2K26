from fastapi import APIRouter, Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy import select

from app.config import get_settings
from app.core.database import AsyncSessionFactory
from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.dependencies import get_redis
from app.models.user import User, UserRole
from app.schemas.auth import (
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from app.services.abuse_detector import AbuseDetector

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(payload: UserRegisterRequest) -> User:
    # 1. Do the heavy CPU math FIRST.
    # No database connections are held hostage during these 300ms!
    hashed_pw = await hash_password(payload.password)

    # 2. Fast Checkout: Enter the DB, execute quickly (5ms), and immediately close the session
    async with AsyncSessionFactory() as db:
        result = await db.execute(select(User).where(User.username == payload.username))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists",
            )

        user = User(
            username=payload.username,
            email=payload.email,
            hashed_password=hashed_pw,
            is_active=True,
            role=UserRole.USER,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: UserLoginRequest,
    request: Request,
    redis: Redis = Depends(get_redis),
) -> TokenResponse:
    client_ip = request.client.host if request.client else "unknown"
    detector = AbuseDetector(redis)

    # Check credential stuffing before attempting auth
    is_stuffing, reason = await detector.is_credential_stuffing(
        ip=client_ip,
        username=payload.username,
        ip_threshold=settings.auth_failure_ip_threshold,
        user_threshold=settings.auth_failure_user_threshold,
    )
    if is_stuffing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Too many failed attempts",
        )

    # 1. Fast Checkout: Quick DB Transaction to fetch the user (5ms).
    # The session automatically closes as soon as this block exits.
    async with AsyncSessionFactory() as db:
        result = await db.execute(select(User).where(User.username == payload.username))
        user = result.scalar_one_or_none()

    # 2. Do the heavy CPU math with NO Postgres connections checked out!
    if not user or not await verify_password(payload.password, user.hashed_password):
        await detector.record_auth_failure(
            ip=client_ip,
            username=payload.username,
            window_seconds=settings.auth_failure_window_seconds,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Role embedded in JWT — require_admin reads this claim
    token = create_access_token({"sub": user.username, "role": user.role})
    return TokenResponse(access_token=token)

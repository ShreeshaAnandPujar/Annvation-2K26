import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
from jose import JWTError, jwt

from app.config import get_settings

settings = get_settings()

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


async def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Run CPU-bound bcrypt verification in a background thread.
    Prevents event loop blocking under concurrent load.
    """
    return await asyncio.to_thread(
        bcrypt.checkpw,
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


async def hash_password(password: str) -> str:
    """Run CPU-bound bcrypt hashing in a background thread.
    Prevents event loop blocking under concurrent load.
    """

    def _hash() -> str:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    return await asyncio.to_thread(_hash)


def create_access_token(data: dict[str, Any]) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any] | None:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

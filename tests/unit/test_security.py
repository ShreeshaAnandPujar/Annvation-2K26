import pytest

from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


@pytest.mark.asyncio
async def test_password_hash_and_verify():
    hashed = await hash_password("mysecret")
    assert await verify_password("mysecret", hashed) is True
    assert await verify_password("wrongpassword", hashed) is False


def test_create_and_decode_token():
    token = create_access_token({"sub": "testuser"})
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "testuser"


def test_decode_invalid_token():
    result = decode_access_token("not.a.valid.token")
    assert result is None

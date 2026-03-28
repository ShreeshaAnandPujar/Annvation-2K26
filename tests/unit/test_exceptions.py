from app.core.exceptions import (
    AbuseDetectedError,
    ForbiddenError,
    RateLimitExceededError,
    UnauthorizedError,
)


def test_rate_limit_exceeded_error():
    exc = RateLimitExceededError(retry_after=60)
    assert exc.status_code == 429
    assert exc.headers["Retry-After"] == "60"
    assert "retry" in exc.detail.lower()


def test_rate_limit_exceeded_default_retry_after():
    exc = RateLimitExceededError()
    assert exc.headers["Retry-After"] == "60"


def test_unauthorized_error():
    exc = UnauthorizedError()
    assert exc.status_code == 401
    assert exc.headers["WWW-Authenticate"] == "Bearer"


def test_unauthorized_error_custom_detail():
    exc = UnauthorizedError(detail="Token expired")
    assert exc.detail == "Token expired"


def test_forbidden_error():
    exc = ForbiddenError()
    assert exc.status_code == 403


def test_abuse_detected_error():
    exc = AbuseDetectedError(reason="ip_threshold_exceeded:15")
    assert exc.status_code == 403
    assert "ip_threshold_exceeded" in exc.detail

from fastapi import HTTPException, status


class RateLimitExceededError(HTTPException):
    """
    Raised when a client exceeds their rate limit.
    Returns 429 with Retry-After header so clients know
    when to retry — protecting both legitimate users who
    hit the limit accidentally and blocking malicious ones.
    """

    def __init__(self, retry_after: int = 60):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded — please retry after the indicated period",
            headers={"Retry-After": str(retry_after)},
        )


class UnauthorizedError(HTTPException):
    """Raised when JWT is missing or invalid."""

    def __init__(self, detail: str = "Not authenticated"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class ForbiddenError(HTTPException):
    """Raised when a client is hard-blocked."""

    def __init__(self, detail: str = "Access denied"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


class AbuseDetectedError(HTTPException):
    """
    Raised when behavioral analysis confirms abusive patterns.
    Carries the specific reason so the error handler can include
    it in the response for admin visibility.
    """

    def __init__(self, reason: str = "Abusive behavior detected"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=reason,
        )

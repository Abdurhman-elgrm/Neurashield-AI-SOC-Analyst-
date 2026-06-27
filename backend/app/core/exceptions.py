from __future__ import annotations

from datetime import UTC
from typing import Any

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.logging import get_request_id

logger = structlog.get_logger(__name__)


# ─── Base exception ───────────────────────────────────────────────────────────


class AppError(Exception):
    """
    Base class for all application-layer errors.
    code: machine-readable identifier (e.g. "USER_NOT_FOUND")
    message: human-readable description
    status_code: HTTP status code to return
    details: optional structured data for the client
    """

    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details


# ─── Domain exceptions ────────────────────────────────────────────────────────


class NotFoundError(AppError):
    def __init__(self, message: str = "Resource not found", details: Any = None) -> None:
        super().__init__(
            message=message,
            code="NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
            details=details,
        )


class UnauthorizedError(AppError):
    def __init__(self, message: str = "Authentication required", details: Any = None) -> None:
        super().__init__(
            message=message,
            code="UNAUTHORIZED",
            status_code=status.HTTP_401_UNAUTHORIZED,
            details=details,
        )


class ForbiddenError(AppError):
    def __init__(self, message: str = "Insufficient permissions", details: Any = None) -> None:
        super().__init__(
            message=message,
            code="FORBIDDEN",
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
        )


class ConflictError(AppError):
    def __init__(self, message: str = "Resource conflict", details: Any = None) -> None:
        super().__init__(
            message=message,
            code="CONFLICT",
            status_code=status.HTTP_409_CONFLICT,
            details=details,
        )


class ValidationError(AppError):
    def __init__(self, message: str = "Validation failed", details: Any = None) -> None:
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )


class RateLimitError(AppError):
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: int = 60,
    ) -> None:
        super().__init__(
            message=message,
            code="RATE_LIMIT_EXCEEDED",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details={"retry_after": retry_after},
        )
        self.retry_after = retry_after


class ServiceUnavailableError(AppError):
    def __init__(self, message: str = "Service temporarily unavailable") -> None:
        super().__init__(
            message=message,
            code="SERVICE_UNAVAILABLE",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class LockedError(AppError):
    def __init__(self, message: str = "Resource is locked", details: Any = None) -> None:
        super().__init__(
            message=message,
            code="AGENT_LOCKED",
            status_code=423,
            details=details,
        )


# ─── Response builder ─────────────────────────────────────────────────────────


def _error_response(
    status_code: int,
    code: str,
    message: str,
    details: Any = None,
) -> JSONResponse:
    from datetime import datetime

    return JSONResponse(
        status_code=status_code,
        content={
            "data": None,
            "error": {
                "code": code,
                "message": message,
                "details": details,
            },
            "meta": {
                "request_id": get_request_id(),
                "timestamp": datetime.now(tz=UTC).isoformat(),
            },
        },
    )


# ─── Exception handlers ───────────────────────────────────────────────────────


def register_exception_handlers(app: FastAPI) -> None:

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        if exc.status_code >= 500:
            logger.error(
                "application_error",
                code=exc.code,
                message=exc.message,
                path=str(request.url.path),
            )
        else:
            logger.info(
                "client_error",
                code=exc.code,
                message=exc.message,
                status_code=exc.status_code,
            )
        headers: dict[str, str] = {}
        if isinstance(exc, RateLimitError):
            headers["Retry-After"] = str(exc.retry_after)
        if isinstance(exc, UnauthorizedError):
            headers["WWW-Authenticate"] = "Bearer"

        response = _error_response(exc.status_code, exc.code, exc.message, exc.details)
        for k, v in headers.items():
            response.headers[k] = v
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        details = [
            {
                "field": ".".join(str(loc) for loc in err["loc"][1:])
                if len(err["loc"]) > 1
                else "body",
                "message": err["msg"],
                "type": err["type"],
            }
            for err in exc.errors()
        ]
        response = _error_response(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Request validation failed",
            details,
        )
        return response

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "unhandled_exception",
            path=str(request.url.path),
            method=request.method,
            exc_type=type(exc).__name__,
        )
        response = _error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "An unexpected error occurred",
        )
        return response

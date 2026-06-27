from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from app.core.logging import get_request_id

T = TypeVar("T")


# ─── Response meta ────────────────────────────────────────────────────────────


class ResponseMeta(BaseModel):
    model_config = ConfigDict(frozen=True)

    request_id: str
    timestamp: str

    @classmethod
    def now(cls) -> ResponseMeta:
        return cls(
            request_id=get_request_id(),
            timestamp=datetime.now(tz=UTC).isoformat(),
        )


# ─── Error detail ─────────────────────────────────────────────────────────────


class ErrorDetail(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    message: str
    details: Any = None


# ─── Standard API response envelope ──────────────────────────────────────────


class APIResponse(BaseModel, Generic[T]):
    """
    All API responses use this envelope.
    Successful responses: data is populated, error is None.
    Error responses:     data is None, error is populated.
    """

    data: T | None = None
    error: ErrorDetail | None = None
    meta: ResponseMeta

    @classmethod
    def ok(cls, data: T) -> APIResponse[T]:
        return cls(data=data, error=None, meta=ResponseMeta.now())

    @classmethod
    def fail(cls, code: str, message: str, details: Any = None) -> APIResponse[None]:
        return cls(
            data=None,
            error=ErrorDetail(code=code, message=message, details=details),
            meta=ResponseMeta.now(),
        )


# ─── Pagination ───────────────────────────────────────────────────────────────


class CursorPagination(BaseModel):
    """For large collections: events, alerts."""

    next_cursor: str | None = None
    prev_cursor: str | None = None
    has_more: bool
    limit: int


class OffsetPagination(BaseModel):
    """For small bounded collections: members, rules, agents."""

    page: int
    limit: int
    total: int
    pages: int


class PaginatedResponse(BaseModel, Generic[T]):
    data: list[T]
    pagination: CursorPagination | OffsetPagination
    meta: ResponseMeta

    @classmethod
    def cursor(
        cls,
        data: list[T],
        next_cursor: str | None,
        prev_cursor: str | None,
        has_more: bool,
        limit: int,
    ) -> PaginatedResponse[T]:
        return cls(
            data=data,
            pagination=CursorPagination(
                next_cursor=next_cursor,
                prev_cursor=prev_cursor,
                has_more=has_more,
                limit=limit,
            ),
            meta=ResponseMeta.now(),
        )

    @classmethod
    def offset(
        cls,
        data: list[T],
        page: int,
        limit: int,
        total: int,
    ) -> PaginatedResponse[T]:
        return cls(
            data=data,
            pagination=OffsetPagination(
                page=page,
                limit=limit,
                total=total,
                pages=max(1, (total + limit - 1) // limit),
            ),
            meta=ResponseMeta.now(),
        )


# ─── Empty success response ───────────────────────────────────────────────────


class EmptyResponse(BaseModel):
    """Used for operations that return nothing on success (e.g. DELETE)."""

    pass


# ─── Common query params ──────────────────────────────────────────────────────


class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=25, ge=1, le=100)

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.limit

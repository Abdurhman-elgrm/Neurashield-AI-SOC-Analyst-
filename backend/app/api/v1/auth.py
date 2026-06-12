from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import CurrentUser
from app.core.exceptions import RateLimitError, UnauthorizedError
from app.core.redis import get_redis_optional
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenPair
from app.schemas.common import APIResponse, EmptyResponse
from app.schemas.user import UserResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])

_LOGIN_RATE_LIMIT    = 10     # attempts
_LOGIN_RATE_WINDOW   = 900    # 15 minutes
_REGISTER_RATE_LIMIT = 5      # attempts
_REGISTER_RATE_WINDOW = 3600  # 1 hour


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    """Store the refresh token in an httpOnly cookie (never readable by JS)."""
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=7 * 24 * 3600,
        path="/api/v1/auth",
    )


def _extract_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if forwarded:
        return forwarded
    return request.client.host if request.client else "unknown"


async def _check_rate_limit(
    redis: object | None,
    key: str,
    limit: int,
    window: int,
) -> None:
    """Increment an IP-scoped counter; raise RateLimitError when exceeded."""
    if redis is None:
        return  # Redis unavailable — degrade gracefully
    try:
        from redis.asyncio import Redis as RedisType
        r: RedisType = redis  # type: ignore[assignment]
        current = await r.incr(key)
        if current == 1:
            await r.expire(key, window)
        if current > limit:
            raise RateLimitError(
                f"Too many attempts — try again in {window // 60} minutes",
                retry_after=window,
            )
    except RateLimitError:
        raise
    except Exception:
        pass  # Redis error — degrade gracefully


@router.post(
    "/register",
    response_model=APIResponse[TokenPair],
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(
    payload: RegisterRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[TokenPair]:
    """
    Creates a new global user account and returns an initial token pair.
    Email addresses are case-insensitively unique across the platform.
    """
    ip = _extract_client_ip(request)
    await _check_rate_limit(redis, f"auth_register_ip:{ip}", _REGISTER_RATE_LIMIT, _REGISTER_RATE_WINDOW)

    ip_str = request.headers.get("X-Forwarded-For", request.client.host if request.client else None)
    _user, token_pair = await AuthService.register(
        db,
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
        ip_address=ip_str,
    )
    _set_refresh_cookie(response, token_pair.refresh_token)
    return APIResponse.ok(token_pair)


@router.post(
    "/login",
    response_model=APIResponse[TokenPair],
    summary="Authenticate and receive token pair",
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[TokenPair]:
    ip = _extract_client_ip(request)
    await _check_rate_limit(redis, f"auth_login_ip:{ip}", _LOGIN_RATE_LIMIT, _LOGIN_RATE_WINDOW)

    ip_str = request.headers.get("X-Forwarded-For", request.client.host if request.client else None)
    _user, token_pair = await AuthService.login(
        db,
        email=payload.email,
        password=payload.password,
        ip_address=ip_str,
    )
    _set_refresh_cookie(response, token_pair.refresh_token)
    return APIResponse.ok(token_pair)


@router.post(
    "/refresh",
    response_model=APIResponse[TokenPair],
    summary="Rotate tokens using a valid refresh token",
)
async def refresh_tokens(
    request: Request,
    response: Response,
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> APIResponse[TokenPair]:
    """
    Validates the refresh token, revokes it, and issues a new token pair.
    Accepts the token from the httpOnly cookie or the request body.
    """
    refresh_token = payload.refresh_token
    if not refresh_token:
        refresh_token = request.cookies.get("refresh_token", "")
    if not refresh_token:
        raise UnauthorizedError("Refresh token required")

    token_pair = await AuthService.refresh(db, refresh_token)
    _set_refresh_cookie(response, token_pair.refresh_token)
    return APIResponse.ok(token_pair)


@router.post(
    "/logout",
    response_model=APIResponse[EmptyResponse],
    summary="Revoke refresh token",
)
async def logout(
    request: Request,
    response: Response,
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> APIResponse[EmptyResponse]:
    """
    Revokes the provided refresh token server-side.
    Accepts the token from the httpOnly cookie or the request body.
    """
    refresh_token = payload.refresh_token
    if not refresh_token:
        refresh_token = request.cookies.get("refresh_token", "")
    await AuthService.logout(db, refresh_token)
    response.delete_cookie(key="refresh_token", path="/api/v1/auth")
    return APIResponse.ok(EmptyResponse())


@router.get(
    "/me",
    response_model=APIResponse[UserResponse],
    summary="Get the currently authenticated user",
)
async def get_me(current_user: CurrentUser) -> APIResponse[UserResponse]:
    return APIResponse.ok(UserResponse.model_validate(current_user))

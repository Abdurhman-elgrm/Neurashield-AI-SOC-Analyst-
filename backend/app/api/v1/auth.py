from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import CurrentUser
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenPair
from app.schemas.common import APIResponse, EmptyResponse
from app.schemas.user import UserResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=APIResponse[TokenPair],
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(
    payload: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> APIResponse[TokenPair]:
    """
    Creates a new global user account and returns an initial token pair.
    Email addresses are case-insensitively unique across the platform.
    """
    ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else None)
    _user, token_pair = await AuthService.register(
        db,
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
        ip_address=ip,
    )
    return APIResponse.ok(token_pair)


@router.post(
    "/login",
    response_model=APIResponse[TokenPair],
    summary="Authenticate and receive token pair",
)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> APIResponse[TokenPair]:
    ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else None)
    _user, token_pair = await AuthService.login(
        db,
        email=payload.email,
        password=payload.password,
        ip_address=ip,
    )
    return APIResponse.ok(token_pair)


@router.post(
    "/refresh",
    response_model=APIResponse[TokenPair],
    summary="Rotate tokens using a valid refresh token",
)
async def refresh_tokens(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> APIResponse[TokenPair]:
    """
    Validates the refresh token, revokes it, and issues a new token pair.
    Implements full token rotation — the old refresh token cannot be reused.
    """
    token_pair = await AuthService.refresh(db, payload.refresh_token)
    return APIResponse.ok(token_pair)


@router.post(
    "/logout",
    response_model=APIResponse[EmptyResponse],
    summary="Revoke refresh token",
)
async def logout(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> APIResponse[EmptyResponse]:
    """
    Revokes the provided refresh token server-side.
    Access token expiry is handled by its short TTL (15 minutes).
    """
    await AuthService.logout(db, payload.refresh_token)
    return APIResponse.ok(EmptyResponse())


@router.get(
    "/me",
    response_model=APIResponse[UserResponse],
    summary="Get the currently authenticated user",
)
async def get_me(current_user: CurrentUser) -> APIResponse[UserResponse]:
    return APIResponse.ok(UserResponse.model_validate(current_user))

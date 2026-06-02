from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import CurrentUser
from app.schemas.common import APIResponse
from app.schemas.user import UserResponse, UserUpdateRequest
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "/me",
    response_model=APIResponse[UserResponse],
    summary="Get current user profile",
)
async def get_profile(current_user: CurrentUser) -> APIResponse[UserResponse]:
    return APIResponse.ok(UserResponse.model_validate(current_user))


@router.patch(
    "/me",
    response_model=APIResponse[UserResponse],
    summary="Update current user profile",
)
async def update_profile(
    payload: UserUpdateRequest,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> APIResponse[UserResponse]:
    updated = await UserService.update_profile(
        db,
        user=current_user,
        full_name=payload.full_name,
    )
    return APIResponse.ok(UserResponse.model_validate(updated))

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse, EmptyResponse, PaginatedResponse
from app.schemas.tenant import MemberResponse, MemberRoleUpdateRequest
from app.services.tenant_service import TenantService

router = APIRouter(prefix="/tenants/{tenant_id}/members", tags=["Team Management"])


@router.get(
    "",
    response_model=PaginatedResponse[MemberResponse],
    summary="List all members of a tenant",
)
async def list_members(
    tenant_id: UUID,
    _member: Annotated[object, require_permission(Permission.MEMBERS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=25, ge=1, le=100),
) -> PaginatedResponse[MemberResponse]:
    members_data, total = await TenantService.get_members(db, tenant_id, page, limit)
    members = [MemberResponse.model_validate(m) for m in members_data]
    return PaginatedResponse.offset(data=members, page=page, limit=limit, total=total)


@router.patch(
    "/{user_id}/role",
    response_model=APIResponse[MemberResponse],
    summary="Change a member's role",
)
async def update_member_role(
    tenant_id: UUID,
    user_id: UUID,
    payload: MemberRoleUpdateRequest,
    actor: Annotated[object, require_permission(Permission.MEMBERS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[MemberResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = actor  # type: ignore[assignment]
    updated = await TenantService.update_member_role(
        db, tenant_id, user_id, payload.role, actor=m
    )
    return APIResponse.ok(MemberResponse.model_validate(updated))


@router.delete(
    "/{user_id}",
    response_model=APIResponse[EmptyResponse],
    status_code=status.HTTP_200_OK,
    summary="Remove a member from the tenant",
)
async def remove_member(
    tenant_id: UUID,
    user_id: UUID,
    actor: Annotated[object, require_permission(Permission.MEMBERS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EmptyResponse]:
    """
    Soft-removes the member. Their global user account is preserved.
    They can be re-invited to this or other tenants in the future.
    """
    from app.models.tenant_member import TenantMember
    m: TenantMember = actor  # type: ignore[assignment]
    await TenantService.remove_member(db, tenant_id, user_id, actor=m)
    return APIResponse.ok(EmptyResponse())

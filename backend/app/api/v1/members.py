from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.core.exceptions import ForbiddenError, NotFoundError, ValidationError
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse, EmptyResponse, PaginatedResponse
from app.schemas.tenant import MemberResponse, MemberRoleUpdateRequest
from app.services.tenant_service import TenantService

router = APIRouter(prefix="/tenants/{tenant_id}/members", tags=["Team Management"])


class CustomPermissionsRequest(BaseModel):
    grant: list[str] = []
    revoke: list[str] = []


@router.get(
    "",
    response_model=PaginatedResponse[MemberResponse],
    summary="List all members of a tenant",
)
async def list_members(
    tenant_id: UUID,
    actor: Annotated[object, require_permission(Permission.MEMBERS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=25, ge=1, le=100),
) -> PaginatedResponse[MemberResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = actor  # type: ignore[assignment]
    if m.tenant_id != tenant_id:
        raise ForbiddenError("Tenant ID mismatch")

    members_data, total = await TenantService.get_members(db, tenant_id, page, limit)
    members = [MemberResponse.model_validate(mem) for mem in members_data]
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
    if m.tenant_id != tenant_id:
        raise ForbiddenError("Tenant ID mismatch")

    updated = await TenantService.update_member_role(db, tenant_id, user_id, payload.role, actor=m)
    return APIResponse.ok(MemberResponse.model_validate(updated))


@router.patch(
    "/{user_id}/permissions",
    response_model=APIResponse[MemberResponse],
    summary="Set custom permission overrides for a member",
)
async def update_member_permissions(
    tenant_id: UUID,
    user_id: UUID,
    payload: CustomPermissionsRequest,
    actor: Annotated[object, require_permission(Permission.MEMBERS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[MemberResponse]:
    from app.models.tenant_member import TenantMember
    from app.rbac.roles import get_effective_permissions

    m: TenantMember = actor  # type: ignore[assignment]
    if m.tenant_id != tenant_id:
        raise ForbiddenError("Tenant ID mismatch")

    # Actor cannot grant permissions they don't hold themselves
    actor_perms = get_effective_permissions(m.role, m.custom_permissions)
    for perm_str in payload.grant:
        try:
            perm = Permission(perm_str)
            if perm not in actor_perms:
                raise ForbiddenError(
                    f"Cannot grant permission '{perm_str}' — you don't have it yourself"
                )
        except ValueError:
            pass  # invalid perms caught by validator below

    # tenant:delete can only be granted by owners
    if "tenant:delete" in payload.grant and m.role != "owner":
        raise ForbiddenError("Only owners can grant tenant:delete")

    # Validate all permission strings
    valid_perms = {p.value for p in Permission}
    invalid = [p for p in payload.grant + payload.revoke if p not in valid_perms]
    if invalid:
        raise ValidationError(f"Invalid permissions: {invalid}")

    result = await db.execute(
        select(TenantMember).where(
            TenantMember.tenant_id == tenant_id,
            TenantMember.user_id == user_id,
            TenantMember.deleted_at.is_(None),
        )
    )
    member = result.scalar_one_or_none()
    if not member:
        raise NotFoundError("Member not found")
    if member.role == "owner":
        raise ValidationError("Cannot restrict owner permissions")

    member.custom_permissions = {
        "grant": list(set(payload.grant)),
        "revoke": list(set(payload.revoke)),
    }
    await db.commit()
    return APIResponse.ok(MemberResponse.model_validate(member))


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
    if m.tenant_id != tenant_id:
        raise ForbiddenError("Tenant ID mismatch")

    await TenantService.remove_member(db, tenant_id, user_id, actor=m)
    return APIResponse.ok(EmptyResponse())

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import CurrentUser, require_permission
from app.core.exceptions import ForbiddenError, NotFoundError
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse, PaginatedResponse
from app.schemas.tenant import TenantCreateRequest, TenantResponse, TenantUpdateRequest
from app.services.tenant_service import TenantService

router = APIRouter(prefix="/tenants", tags=["Tenants"])


@router.post(
    "",
    response_model=APIResponse[TenantResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a new tenant organization",
)
async def create_tenant(
    payload: TenantCreateRequest,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> APIResponse[TenantResponse]:
    """
    Creates a new tenant. The requesting user automatically becomes the OWNER.
    Any authenticated user can create a tenant — there is no platform-wide limit.
    """
    tenant = await TenantService.create(
        db,
        name=payload.name,
        slug=payload.slug,
        owner=current_user,
    )
    return APIResponse.ok(TenantResponse.model_validate(tenant))


@router.get(
    "",
    response_model=APIResponse[list[TenantResponse]],
    summary="List all tenants the current user belongs to",
)
async def list_my_tenants(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> APIResponse[list[TenantResponse]]:
    tenants = await TenantService.get_user_tenants(db, current_user.id)
    return APIResponse.ok([TenantResponse.model_validate(t) for t in tenants])


@router.get(
    "/{tenant_id}",
    response_model=APIResponse[TenantResponse],
    summary="Get tenant details",
)
async def get_tenant(
    tenant_id: UUID,
    # Any active member can read their own tenant
    _member: CurrentMember,
    db: AsyncSession = Depends(get_db),
) -> APIResponse[TenantResponse]:
    tenant = await TenantService.get_by_id(db, tenant_id)
    if tenant is None:
        raise NotFoundError("Tenant not found")
    return APIResponse.ok(TenantResponse.model_validate(tenant))


@router.patch(
    "/{tenant_id}",
    response_model=APIResponse[TenantResponse],
    summary="Update tenant settings",
)
async def update_tenant(
    tenant_id: UUID,
    payload: TenantUpdateRequest,
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[TenantResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    tenant = await TenantService.get_by_id(db, tenant_id)
    if tenant is None:
        raise NotFoundError("Tenant not found")
    updated = await TenantService.update(db, tenant, actor=m, name=payload.name)
    return APIResponse.ok(TenantResponse.model_validate(updated))

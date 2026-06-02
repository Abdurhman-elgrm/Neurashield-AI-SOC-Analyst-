from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse, EmptyResponse, PaginatedResponse
from app.schemas.detection import DetectionRuleCreateRequest, DetectionRuleResponse, DetectionRuleUpdateRequest
from app.services.audit_service import AuditService
from app.services.detection_service import DetectionService

router = APIRouter(prefix="/rules", tags=["detection-rules"])


@router.get("", response_model=PaginatedResponse[DetectionRuleResponse])
async def list_rules(
    member: Annotated[object, require_permission(Permission.RULES_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=25, ge=1, le=100),
    enabled_only: bool = Query(default=False),
) -> PaginatedResponse[DetectionRuleResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    rules, total = await DetectionService.list_rules(db, m.tenant_id, page=page, limit=limit, enabled_only=enabled_only)
    return PaginatedResponse[DetectionRuleResponse].offset(
        data=[DetectionRuleResponse.model_validate(r) for r in rules],
        page=page, limit=limit, total=total,
    )


@router.post("", response_model=APIResponse[DetectionRuleResponse], status_code=201)
async def create_rule(
    payload: DetectionRuleCreateRequest,
    member: Annotated[object, require_permission(Permission.RULES_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    rule = await DetectionService.create_rule(db, m.tenant_id, payload, m.user_id)
    await AuditService.log(
        db, action="rule.created", actor_id=m.user_id, actor_role=m.role,
        tenant_id=m.tenant_id, resource_type="detection_rule", resource_id=rule.id,
    )
    await db.commit()
    return APIResponse.ok(DetectionRuleResponse.model_validate(rule))


@router.get("/{rule_id}", response_model=APIResponse[DetectionRuleResponse])
async def get_rule(
    rule_id: UUID,
    member: Annotated[object, require_permission(Permission.RULES_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    rule = await DetectionService.require_by_id(db, m.tenant_id, rule_id)
    return APIResponse.ok(DetectionRuleResponse.model_validate(rule))


@router.patch("/{rule_id}", response_model=APIResponse[DetectionRuleResponse])
async def update_rule(
    rule_id: UUID,
    payload: DetectionRuleUpdateRequest,
    member: Annotated[object, require_permission(Permission.RULES_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    rule = await DetectionService.update_rule(db, m.tenant_id, rule_id, payload, m.user_id)
    await AuditService.log(
        db, action="rule.updated", actor_id=m.user_id, actor_role=m.role,
        tenant_id=m.tenant_id, resource_type="detection_rule", resource_id=rule_id,
    )
    await db.commit()
    return APIResponse.ok(DetectionRuleResponse.model_validate(rule))


@router.delete("/{rule_id}", response_model=APIResponse[EmptyResponse])
async def delete_rule(
    rule_id: UUID,
    member: Annotated[object, require_permission(Permission.RULES_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EmptyResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    await DetectionService.delete_rule(db, m.tenant_id, rule_id)
    await AuditService.log(
        db, action="rule.deleted", actor_id=m.user_id, actor_role=m.role,
        tenant_id=m.tenant_id, resource_type="detection_rule", resource_id=rule_id,
    )
    await db.commit()
    return APIResponse.ok(EmptyResponse())

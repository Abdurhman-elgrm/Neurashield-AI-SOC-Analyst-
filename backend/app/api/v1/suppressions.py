"""
User-defined alert suppression rules.
When a newly generated alert matches ALL non-null fields of a suppression rule,
the alert is discarded before persisting to the database.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.core.exceptions import NotFoundError, ValidationError
from app.models.suppression_rule import SuppressionRule
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse, EmptyResponse

router = APIRouter(prefix="/suppression-rules", tags=["Suppression Rules"])

_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_VALID_CATEGORIES = {
    "auth",
    "process",
    "network",
    "file",
    "registry",
    "wmi",
    "powershell",
    "firewall",
    "service",
    "scheduled_task",
    "other",
    "system",
}


class SuppressionRuleResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    detection_rule_id: UUID | None
    hostname_pattern: str | None
    category: str | None
    min_severity: str | None
    reason: str | None
    enabled: bool
    expires_at: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SuppressionRuleCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    detection_rule_id: UUID | None = None
    hostname_pattern: str | None = Field(default=None, max_length=255)
    category: str | None = None
    min_severity: str | None = None
    reason: str | None = Field(default=None, max_length=1000)
    enabled: bool = True
    expires_at: datetime = Field(..., description="When this suppression rule expires (ISO 8601)")


class SuppressionRuleUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    hostname_pattern: str | None = None
    category: str | None = None
    min_severity: str | None = None
    reason: str | None = None
    enabled: bool | None = None
    expires_at: datetime | None = None


def _validate_rule(
    category: str | None,
    min_severity: str | None,
    expires_at: datetime | None = None,
) -> None:
    if category and category not in _VALID_CATEGORIES:
        raise ValidationError(
            f"Invalid category. Must be one of: {', '.join(sorted(_VALID_CATEGORIES))}"
        )
    if min_severity and min_severity.lower() not in _VALID_SEVERITIES:
        raise ValidationError(
            f"Invalid min_severity. Must be one of: {', '.join(_VALID_SEVERITIES)}"
        )
    if expires_at and expires_at <= datetime.now(tz=UTC):
        raise ValidationError("expires_at must be in the future")


@router.get(
    "",
    response_model=APIResponse[list[SuppressionRuleResponse]],
    summary="List active suppression rules for the tenant",
)
async def list_rules(
    member: Annotated[object, require_permission(Permission.RULES_READ)],
    db: AsyncSession = Depends(get_db),
    include_expired: bool = False,
) -> APIResponse[list[SuppressionRuleResponse]]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore

    q = select(SuppressionRule).where(
        SuppressionRule.tenant_id == m.tenant_id,
        SuppressionRule.deleted_at.is_(None),
    )
    if not include_expired:
        q = q.where(SuppressionRule.expires_at > datetime.now(tz=UTC))

    result = await db.execute(q.order_by(SuppressionRule.created_at.desc()))
    rules = list(result.scalars().all())
    return APIResponse.ok([SuppressionRuleResponse.model_validate(r) for r in rules])


@router.post(
    "",
    response_model=APIResponse[SuppressionRuleResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a new suppression rule",
)
async def create_rule(
    payload: SuppressionRuleCreateRequest,
    member: Annotated[object, require_permission(Permission.RULES_MANAGE)],
    db: AsyncSession = Depends(get_db),
) -> APIResponse[SuppressionRuleResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore

    _validate_rule(payload.category, payload.min_severity, payload.expires_at)

    # Ensure expires_at is timezone-aware
    expires = payload.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)

    rule = SuppressionRule(
        tenant_id=m.tenant_id,
        name=payload.name.strip(),
        description=payload.description,
        detection_rule_id=payload.detection_rule_id,
        hostname_pattern=payload.hostname_pattern,
        category=payload.category,
        min_severity=payload.min_severity.lower() if payload.min_severity else None,
        reason=payload.reason,
        enabled=payload.enabled,
        expires_at=expires,
        created_by_id=m.user_id,
    )
    db.add(rule)
    await db.flush([rule])
    await db.commit()
    await db.refresh(rule)
    return APIResponse.ok(SuppressionRuleResponse.model_validate(rule))


@router.patch(
    "/{rule_id}",
    response_model=APIResponse[SuppressionRuleResponse],
    summary="Update a suppression rule",
)
async def update_rule(
    rule_id: UUID,
    payload: SuppressionRuleUpdateRequest,
    member: Annotated[object, require_permission(Permission.RULES_MANAGE)],
    db: AsyncSession = Depends(get_db),
) -> APIResponse[SuppressionRuleResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore

    result = await db.execute(
        select(SuppressionRule).where(
            SuppressionRule.id == rule_id,
            SuppressionRule.tenant_id == m.tenant_id,
            SuppressionRule.deleted_at.is_(None),
        )
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise NotFoundError("Suppression rule not found")

    _validate_rule(payload.category, payload.min_severity, payload.expires_at)

    if payload.name is not None:
        rule.name = payload.name.strip()
    if payload.description is not None:
        rule.description = payload.description
    if payload.hostname_pattern is not None:
        rule.hostname_pattern = payload.hostname_pattern or None
    if payload.category is not None:
        rule.category = payload.category or None
    if payload.min_severity is not None:
        rule.min_severity = payload.min_severity.lower() or None
    if payload.reason is not None:
        rule.reason = payload.reason
    if payload.enabled is not None:
        rule.enabled = payload.enabled
    if payload.expires_at is not None:
        expires = payload.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        rule.expires_at = expires

    rule.updated_at = datetime.now(tz=UTC)
    await db.flush([rule])
    await db.commit()
    await db.refresh(rule)
    return APIResponse.ok(SuppressionRuleResponse.model_validate(rule))


@router.delete(
    "/{rule_id}",
    response_model=APIResponse[EmptyResponse],
    summary="Delete a suppression rule",
)
async def delete_rule(
    rule_id: UUID,
    member: Annotated[object, require_permission(Permission.RULES_MANAGE)],
    db: AsyncSession = Depends(get_db),
) -> APIResponse[EmptyResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore

    result = await db.execute(
        select(SuppressionRule).where(
            SuppressionRule.id == rule_id,
            SuppressionRule.tenant_id == m.tenant_id,
            SuppressionRule.deleted_at.is_(None),
        )
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise NotFoundError("Suppression rule not found")

    rule.deleted_at = datetime.now(tz=UTC)
    await db.flush([rule])
    await db.commit()
    return APIResponse.ok(EmptyResponse())

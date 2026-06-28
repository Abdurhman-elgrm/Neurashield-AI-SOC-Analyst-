from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

router = APIRouter(prefix="/settings", tags=["Settings"])

_THRESHOLDS_KEY = "severity_thresholds"


class SeverityThresholds(BaseModel):
    critical_min_score: int = Field(default=80, ge=0, le=100)
    high_min_score: int = Field(default=60, ge=0, le=100)
    medium_min_score: int = Field(default=30, ge=0, le=100)
    low_min_score: int = Field(default=0, ge=0, le=100)
    escalate_after_minutes: int = Field(default=60, ge=1)
    auto_close_after_days: int = Field(default=30, ge=1)


@router.get(
    "/severity-thresholds",
    response_model=APIResponse[SeverityThresholds],
    summary="Get tenant severity threshold configuration",
)
async def get_severity_thresholds(
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[SeverityThresholds]:
    from app.models.tenant import Tenant
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    tenant = await db.get(Tenant, m.tenant_id)
    raw: dict = (tenant.settings_json or {}).get(_THRESHOLDS_KEY, {}) if tenant else {}
    return APIResponse.ok(SeverityThresholds(**raw))


@router.put(
    "/severity-thresholds",
    response_model=APIResponse[SeverityThresholds],
    summary="Update tenant severity threshold configuration",
)
async def put_severity_thresholds(
    payload: SeverityThresholds,
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[SeverityThresholds]:
    from app.models.tenant import Tenant
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    tenant = await db.get(Tenant, m.tenant_id)
    if tenant is not None:
        merged = {**(tenant.settings_json or {}), _THRESHOLDS_KEY: payload.model_dump()}
        await db.execute(
            update(Tenant).where(Tenant.id == m.tenant_id).values(settings_json=merged)
        )
        await db.commit()
    return APIResponse.ok(payload)


class QuotaResponse(BaseModel):
    plan: str
    ingestion_rate_eps: float
    ingestion_limit_eps: int
    agents_active: int
    agents_total: int
    members_active: int
    storage_used_gb: float
    storage_limit_gb: int
    renewal_date: str


@router.get(
    "/quota",
    response_model=APIResponse[QuotaResponse],
    summary="Current tenant quota and usage statistics",
)
async def get_quota(
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[QuotaResponse]:
    from app.models.agent import Agent
    from app.models.event import Event
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    tenant_id = m.tenant_id

    agents_total = (
        await db.scalar(
            select(func.count(Agent.id)).where(
                Agent.tenant_id == tenant_id,
                Agent.deleted_at.is_(None),
            )
        )
        or 0
    )
    agents_active = (
        await db.scalar(
            select(func.count(Agent.id)).where(
                Agent.tenant_id == tenant_id,
                Agent.deleted_at.is_(None),
                Agent.status == "online",
            )
        )
        or 0
    )
    members_active = (
        await db.scalar(
            select(func.count(TenantMember.id)).where(
                TenantMember.tenant_id == tenant_id,
            )
        )
        or 0
    )
    # Estimate storage from event count (avg ~2 KB per event)
    event_count = (
        await db.scalar(
            select(func.count(Event.id)).where(Event.tenant_id == tenant_id)
        )
        or 0
    )
    storage_used_gb = round((event_count * 2048) / (1024**3), 2)

    # Renewal date = 1st of the following month
    now = datetime.now(UTC)
    if now.month == 12:
        renewal = now.replace(year=now.year + 1, month=1, day=1)
    else:
        renewal = now.replace(month=now.month + 1, day=1)

    return APIResponse.ok(
        QuotaResponse(
            plan="enterprise",
            ingestion_rate_eps=0.0,
            ingestion_limit_eps=10_000,
            agents_active=agents_active,
            agents_total=agents_total,
            members_active=members_active,
            storage_used_gb=storage_used_gb,
            storage_limit_gb=1024,
            renewal_date=renewal.strftime("%Y-%m-%d"),
        )
    )

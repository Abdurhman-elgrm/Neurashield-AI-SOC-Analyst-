from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models.agent import Agent, AgentStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.investigation import Investigation, InvestigationStatus
from app.models.tenant import Tenant
from app.models.tenant_member import TenantMember
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

router = APIRouter(prefix="/mssp", tags=["mssp"])


# ─── Response schemas ─────────────────────────────────────────────────────────


class TenantHealthCard(BaseModel):
    tenant_id: str
    tenant_name: str
    open_critical_alerts: int
    unresolved_investigations: int
    agents_online: int
    last_event_at: str | None
    breach_status: str  # "green" | "amber" | "red"
    oldest_critical_alert_age_ms: int


class CrossTenantAlertPoint(BaseModel):
    date: str
    tenants: dict[str, int]


class MSSPOverviewResponse(BaseModel):
    tenants: list[TenantHealthCard]
    alert_trend: list[CrossTenantAlertPoint]


class CreateTenantRequest(BaseModel):
    name: str


class CreateTenantResponse(BaseModel):
    tenant_id: str
    name: str


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _breach_status(open_critical: int, oldest_ms: int) -> str:
    if open_critical == 0:
        return "green"
    # Red if any critical alert is older than 4 hours
    if oldest_ms > 4 * 3600 * 1000:
        return "red"
    return "amber"


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/overview", response_model=APIResponse[MSSPOverviewResponse])
async def get_mssp_overview(
    member: Annotated[object, require_permission(Permission.MSSP_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[MSSPOverviewResponse]:
    m: TenantMember = member  # type: ignore[assignment]

    # All tenants where this user is admin or owner
    memberships = (
        (
            await db.execute(
                select(TenantMember.tenant_id).where(
                    TenantMember.user_id == m.user_id,
                    TenantMember.role.in_(["admin", "owner"]),
                    TenantMember.deleted_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )

    tenant_ids = list(memberships)
    if not tenant_ids:
        return APIResponse.ok(MSSPOverviewResponse(tenants=[], alert_trend=[]))

    # Load tenant names
    tenants_result = await db.execute(
        select(Tenant.id, Tenant.name).where(
            Tenant.id.in_(tenant_ids),
            Tenant.deleted_at.is_(None),
        )
    )
    tenant_names: dict = {str(r.id): r.name for r in tenants_result.all()}

    now = datetime.now(tz=UTC)
    health_cards: list[TenantHealthCard] = []

    for tid in tenant_ids:
        tid_str = str(tid)

        # Alert stats
        alert_row = (
            await db.execute(
                select(
                    func.count()
                    .filter(
                        Alert.severity == AlertSeverity.CRITICAL.value,
                        Alert.status == AlertStatus.OPEN.value,
                    )
                    .label("open_critical"),
                    func.min(Alert.created_at)
                    .filter(
                        Alert.severity == AlertSeverity.CRITICAL.value,
                        Alert.status == AlertStatus.OPEN.value,
                    )
                    .label("oldest_critical_at"),
                ).where(Alert.tenant_id == tid, Alert.deleted_at.is_(None))
            )
        ).one()

        open_critical: int = int(alert_row.open_critical or 0)
        oldest_ms = 0
        if alert_row.oldest_critical_at:
            oldest_ms = int((now - alert_row.oldest_critical_at).total_seconds() * 1000)

        # Unresolved investigations
        unresolved: int = (
            await db.execute(
                select(func.count()).where(
                    Investigation.tenant_id == tid,
                    Investigation.status.notin_(
                        [
                            InvestigationStatus.CLOSED.value,
                            InvestigationStatus.FALSE_POSITIVE.value,
                        ]
                    ),
                )
            )
        ).scalar_one()

        # Online agents
        agents_online: int = (
            await db.execute(
                select(func.count()).where(
                    Agent.tenant_id == tid,
                    Agent.status == AgentStatus.ONLINE.value,
                    Agent.deleted_at.is_(None),
                )
            )
        ).scalar_one()

        # Last event
        last_event_row = (
            await db.execute(
                text(
                    "SELECT MAX(event_timestamp) FROM events WHERE tenant_id = CAST(:tid AS uuid)"
                ),
                {"tid": tid_str},
            )
        ).scalar_one()
        last_event_at = last_event_row.isoformat() if last_event_row else None

        health_cards.append(
            TenantHealthCard(
                tenant_id=tid_str,
                tenant_name=tenant_names.get(tid_str, "Unknown"),
                open_critical_alerts=open_critical,
                unresolved_investigations=unresolved,
                agents_online=agents_online,
                last_event_at=last_event_at,
                breach_status=_breach_status(open_critical, oldest_ms),
                oldest_critical_alert_age_ms=oldest_ms,
            )
        )

    # 7-day cross-tenant alert trend
    trend_rows = (
        await db.execute(
            text("""
            SELECT DATE(created_at AT TIME ZONE 'UTC') AS day,
                   tenant_id::text AS tid,
                   COUNT(*) AS cnt
            FROM alerts
            WHERE tenant_id = ANY(CAST(:tids AS uuid[]))
              AND created_at > NOW() - INTERVAL '7 days'
              AND deleted_at IS NULL
            GROUP BY day, tenant_id
            ORDER BY day
        """),
            {"tids": [str(t) for t in tenant_ids]},
        )
    ).all()

    from collections import defaultdict

    trend_map: dict[str, dict[str, int]] = defaultdict(dict)
    for r in trend_rows:
        trend_map[str(r.day)][r.tid] = int(r.cnt)

    alert_trend = [
        CrossTenantAlertPoint(date=day, tenants=tenants_data)
        for day, tenants_data in sorted(trend_map.items())
    ]

    return APIResponse.ok(
        MSSPOverviewResponse(
            tenants=sorted(health_cards, key=lambda c: c.open_critical_alerts, reverse=True),
            alert_trend=alert_trend,
        )
    )


@router.post("/tenants", response_model=APIResponse[CreateTenantResponse])
async def create_mssp_tenant(
    payload: CreateTenantRequest,
    member: Annotated[object, require_permission(Permission.MSSP_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[CreateTenantResponse]:
    m: TenantMember = member  # type: ignore[assignment]

    name = payload.name.strip()
    if not name or len(name) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tenant name must be at least 2 characters",
        )

    from app.models.user import User
    from app.services.tenant_service import TenantService

    user = (await db.execute(select(User).where(User.id == m.user_id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    tenant, _ = await TenantService.create_tenant(db, name=name, owner=user)
    await db.commit()

    return APIResponse.ok(
        CreateTenantResponse(
            tenant_id=str(tenant.id),
            name=tenant.name,
        )
    )

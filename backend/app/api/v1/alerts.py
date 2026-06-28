from __future__ import annotations

from datetime import UTC
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.core.exceptions import ValidationError
from app.rbac.permissions import Permission
from app.schemas.alert import AlertFilterParams, AlertResponse, AlertUpdateRequest
from app.schemas.common import APIResponse, EmptyResponse, PaginatedResponse
from app.services.alert_service import AlertService
from app.services.audit_service import AuditService

router = APIRouter(prefix="/alerts", tags=["alerts"])


# ─── Summary (status counts) ──────────────────────────────────────────────────


@router.get("/summary", response_model=APIResponse[dict])
async def get_alerts_summary(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    from sqlalchemy import func, select

    from app.models.alert import Alert
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    result = await db.execute(
        select(Alert.status, func.count(Alert.id))
        .where(Alert.tenant_id == m.tenant_id, Alert.deleted_at.is_(None))
        .group_by(Alert.status)
    )
    counts = {
        str(row[0].value if hasattr(row[0], "value") else row[0]): int(row[1]) for row in result
    }
    return APIResponse.ok(
        {
            "open": counts.get("open", 0),
            "acknowledged": counts.get("acknowledged", 0),
            "closed": counts.get("closed", 0),
            "false_positive": counts.get("false_positive", 0),
        }
    )


class BulkAlertUpdateRequest(BaseModel):
    alert_ids: list[UUID] = Field(min_length=1, max_length=100)
    status: Literal["open", "acknowledged", "closed", "false_positive"] | None = None
    notes: str | None = Field(default=None, max_length=2000)
    assignee_id: UUID | None = None


@router.get("", response_model=PaginatedResponse[AlertResponse])
async def list_alerts(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    source_host: str | None = Query(default=None),
    rule_id: UUID | None = Query(default=None),
    from_ts: str | None = Query(default=None, description="ISO-8601 start datetime filter"),
    to_ts: str | None = Query(default=None, description="ISO-8601 end datetime filter"),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> PaginatedResponse[AlertResponse]:
    from datetime import datetime

    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    def _parse_dt(s: str | None) -> datetime | None:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None

    params = AlertFilterParams(
        status=status,
        severity=severity,
        source_host=source_host,
        rule_id=rule_id,
        from_ts=_parse_dt(from_ts),
        to_ts=_parse_dt(to_ts),
        cursor=cursor,
        limit=limit,
    )
    alerts, next_cursor = await AlertService.list_alerts(db, m.tenant_id, params)
    return PaginatedResponse[AlertResponse].cursor(
        data=[AlertResponse.model_validate(a) for a in alerts],
        next_cursor=next_cursor,
        prev_cursor=None,
        has_more=next_cursor is not None,
        limit=limit,
    )


@router.get("/{alert_id}", response_model=APIResponse[AlertResponse])
async def get_alert(
    alert_id: UUID,
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    alert = await AlertService.require_by_id(db, m.tenant_id, alert_id)
    return APIResponse.ok(AlertResponse.model_validate(alert))


@router.patch("/{alert_id}", response_model=APIResponse[AlertResponse])
async def update_alert(
    alert_id: UUID,
    payload: AlertUpdateRequest,
    member: Annotated[object, require_permission(Permission.ALERTS_UPDATE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    alert = await AlertService.update_alert(db, m.tenant_id, alert_id, payload, m.user_id)
    await AuditService.log(
        db,
        action="alert.updated",
        actor_id=m.user_id,
        actor_role=m.role,
        tenant_id=m.tenant_id,
        resource_type="alert",
        resource_id=alert_id,
        changes={"status": payload.status} if payload.status else {},
    )
    await db.commit()
    return APIResponse.ok(AlertResponse.model_validate(alert))


@router.delete("/{alert_id}", response_model=APIResponse[EmptyResponse])
async def delete_alert(
    alert_id: UUID,
    member: Annotated[object, require_permission(Permission.ALERTS_DELETE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EmptyResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    await AlertService.delete_alert(db, m.tenant_id, alert_id, m.user_id)
    await AuditService.log(
        db,
        action="alert.deleted",
        actor_id=m.user_id,
        actor_role=m.role,
        tenant_id=m.tenant_id,
        resource_type="alert",
        resource_id=alert_id,
    )
    await db.commit()
    return APIResponse.ok(EmptyResponse())


# ─── Bulk update ─────────────────────────────────────────────────────────────


@router.post(
    "/bulk",
    response_model=APIResponse[dict],
    summary="Bulk update multiple alerts",
)
async def bulk_update_alerts(
    payload: BulkAlertUpdateRequest,
    member: Annotated[object, require_permission(Permission.ALERTS_UPDATE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    from datetime import datetime

    from sqlalchemy import update

    from app.models.alert import Alert

    m = member  # type: ignore

    updates: dict = {}
    if payload.status is not None:
        updates["status"] = payload.status
        if payload.status == "acknowledged":
            updates["acknowledged_at"] = datetime.now(tz=UTC)
        elif payload.status in ("closed", "false_positive"):
            updates["closed_at"] = datetime.now(tz=UTC)
    if payload.notes is not None:
        updates["notes"] = payload.notes
    if payload.assignee_id is not None:
        updates["assignee_id"] = payload.assignee_id

    if not updates:
        raise ValidationError("No fields to update")

    result = await db.execute(
        update(Alert)
        .where(
            Alert.id.in_(payload.alert_ids),
            Alert.tenant_id == m.tenant_id,
            Alert.deleted_at.is_(None),
        )
        .values(**updates)
        .returning(Alert.id)
    )
    updated_ids = result.fetchall()
    await db.commit()

    return APIResponse.ok({"updated": len(updated_ids)})


# ─── Alert timeline (synthesized from alert state transitions) ───────────────


@router.get("/{alert_id}/timeline", response_model=APIResponse[list])
async def get_alert_timeline(
    alert_id: UUID,
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    alert = await AlertService.require_by_id(db, m.tenant_id, alert_id)

    events = []

    # Alert created
    events.append(
        {
            "id": f"{alert.id}-created",
            "alertId": str(alert.id),
            "eventType": "alert_created",
            "actorName": "Detection Engine",
            "details": {
                "severity": alert.severity.value
                if hasattr(alert.severity, "value")
                else alert.severity,
                "rule": alert.rule_name or alert.title,
            },
            "createdAt": alert.created_at.isoformat(),
        }
    )

    if alert.acknowledged_at:
        events.append(
            {
                "id": f"{alert.id}-acknowledged",
                "alertId": str(alert.id),
                "eventType": "status_changed",
                "actorName": None,
                "details": {"from": "open", "to": "acknowledged"},
                "createdAt": alert.acknowledged_at.isoformat(),
            }
        )

    if alert.closed_at:
        events.append(
            {
                "id": f"{alert.id}-closed",
                "alertId": str(alert.id),
                "eventType": "status_changed",
                "actorName": None,
                "details": {
                    "from": "acknowledged",
                    "to": alert.status.value
                    if hasattr(alert.status, "value")
                    else str(alert.status),
                },
                "createdAt": alert.closed_at.isoformat(),
            }
        )

    if alert.notes:
        events.append(
            {
                "id": f"{alert.id}-note",
                "alertId": str(alert.id),
                "eventType": "note_added",
                "actorName": "Analyst",
                "details": {"note": alert.notes},
                "createdAt": alert.updated_at.isoformat(),
            }
        )

    return APIResponse.ok(events)


# ─── Alert investigation context (related alerts on same host) ────────────────


@router.get("/{alert_id}/context", response_model=APIResponse[dict])
async def get_alert_context(
    alert_id: UUID,
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    from datetime import timedelta

    from sqlalchemy import select

    from app.models.alert import Alert
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    alert = await AlertService.require_by_id(db, m.tenant_id, alert_id)

    related: list[Alert] = []
    if alert.source_host:
        cutoff = alert.created_at - timedelta(hours=24) if alert.created_at else None
        q = (
            select(Alert)
            .where(
                Alert.tenant_id == m.tenant_id,
                Alert.source_host == alert.source_host,
                Alert.id != alert_id,
                Alert.deleted_at.is_(None),
            )
            .order_by(Alert.created_at.desc())
            .limit(10)
        )
        if cutoff:
            q = q.where(Alert.created_at >= cutoff)
        result = await db.execute(q)
        related = list(result.scalars().all())

    # Check for linked investigation
    investigation = None
    try:
        from app.models.investigation import Investigation

        res = await db.execute(
            select(Investigation)
            .where(
                Investigation.tenant_id == m.tenant_id,
                Investigation.deleted_at.is_(None),
            )
            .filter(
                Investigation.alert_ids.contains([str(alert_id)])  # type: ignore
            )
            .limit(1)
        )
        inv = res.scalar_one_or_none()
        if inv:
            investigation = {
                "id": str(inv.id),
                "title": inv.title,
                "status": inv.status.value if hasattr(inv.status, "value") else str(inv.status),
                "createdAt": inv.created_at.isoformat() if inv.created_at else None,
                "alertCount": len(inv.alert_ids) if inv.alert_ids else 1,
            }
    except Exception:
        pass  # Investigation model may not have alert_ids array

    return APIResponse.ok(
        {
            "alertId": str(alert_id),
            "relatedAlerts": [
                AlertResponse.model_validate(a).model_dump(mode="json") for a in related
            ],
            "investigation": investigation,
        }
    )


# ─── Promote alert to investigation ──────────────────────────────────────────


@router.post("/{alert_id}/promote", response_model=APIResponse[dict])
async def promote_to_investigation(
    alert_id: UUID,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    """Promote an alert into a new manual investigation."""
    from fastapi import HTTPException

    from app.analyst.cases import CaseService
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    alert = await AlertService.get_alert(db, m.tenant_id, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    investigation = await CaseService.create_manual(
        db=db,
        tenant_id=m.tenant_id,
        created_by=m.user_id,
        title=f"Investigation: {alert.title}",
        description=f"Promoted from alert {alert_id}",
        severity=alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
        assigned_to=None,
        alert_ids=[str(alert_id)],
    )
    return APIResponse.ok({"investigation_id": str(investigation.id)})

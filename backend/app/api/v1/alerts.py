from __future__ import annotations

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
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> PaginatedResponse[AlertResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]

    params = AlertFilterParams(
        status=status,
        severity=severity,
        source_host=source_host,
        rule_id=rule_id,
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
        db, action="alert.updated", actor_id=m.user_id, actor_role=m.role,
        tenant_id=m.tenant_id, resource_type="alert", resource_id=alert_id,
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
        db, action="alert.deleted", actor_id=m.user_id, actor_role=m.role,
        tenant_id=m.tenant_id, resource_type="alert", resource_id=alert_id,
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
    from app.models.alert import Alert
    from sqlalchemy import update
    from datetime import datetime, timezone

    m = member  # type: ignore

    updates: dict = {}
    if payload.status is not None:
        updates["status"] = payload.status
        if payload.status == "acknowledged":
            updates["acknowledged_at"] = datetime.now(tz=timezone.utc)
        elif payload.status in ("closed", "false_positive"):
            updates["closed_at"] = datetime.now(tz=timezone.utc)
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


# ─── Promote alert to investigation ──────────────────────────────────────────

@router.post("/{alert_id}/promote", response_model=APIResponse[dict])
async def promote_to_investigation(
    alert_id: UUID,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    """Promote an alert into a new manual investigation."""
    from app.models.tenant_member import TenantMember
    from app.analyst.cases import CaseService
    from fastapi import HTTPException

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

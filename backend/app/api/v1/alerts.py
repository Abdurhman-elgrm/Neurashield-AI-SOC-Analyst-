from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.rbac.permissions import Permission
from app.schemas.alert import AlertFilterParams, AlertResponse, AlertUpdateRequest
from app.schemas.common import APIResponse, EmptyResponse, PaginatedResponse
from app.services.alert_service import AlertService
from app.services.audit_service import AuditService

router = APIRouter(prefix="/alerts", tags=["alerts"])


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

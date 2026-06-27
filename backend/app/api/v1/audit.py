from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, outerjoin, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models.audit_log import AuditLog
from app.models.tenant_member import TenantMember
from app.models.user import User
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEventResponse(BaseModel):
    id: str
    timestamp: str
    actor_name: str
    actor_id: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    resource_title: str | None
    old_value: object | None
    new_value: object | None
    ip_address: str | None


class AuditListResponse(BaseModel):
    events: list[AuditEventResponse]
    total: int
    page: int
    page_size: int


@router.get("/events", response_model=APIResponse[AuditListResponse])
async def list_audit_events(
    member: Annotated[object, require_permission(Permission.AUDIT_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    actor: str | None = Query(default=None),
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
) -> APIResponse[AuditListResponse]:
    m: TenantMember = member  # type: ignore[assignment]
    tenant_id = m.tenant_id

    base = (
        select(AuditLog, User.full_name.label("actor_name"))
        .select_from(outerjoin(AuditLog, User, AuditLog.actor_id == User.id))
        .where(AuditLog.tenant_id == tenant_id)
    )
    if actor:
        base = base.where(User.full_name.ilike(f"%{actor}%"))
    if action:
        base = base.where(AuditLog.action.ilike(f"%{action}%"))
    if resource_type:
        base = base.where(AuditLog.resource_type == resource_type)

    total_q = select(func.count()).select_from(base.subquery())
    total: int = (await db.scalar(total_q)) or 0

    rows_q = (
        base.order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await db.execute(rows_q)).all()

    events: list[AuditEventResponse] = []
    for row in rows:
        log: AuditLog = row[0]
        actor_name: str | None = row[1]
        changes = log.changes or {}
        events.append(
            AuditEventResponse(
                id=str(log.id),
                timestamp=log.created_at.isoformat(),
                actor_name=actor_name or "System",
                actor_id=str(log.actor_id) if log.actor_id else None,
                action=log.action,
                resource_type=log.resource_type,
                resource_id=str(log.resource_id) if log.resource_id else None,
                resource_title=None,
                old_value=changes.get("before"),
                new_value=changes.get("after"),
                ip_address=log.ip_address,
            )
        )

    return APIResponse.ok(
        AuditListResponse(events=events, total=total, page=page, page_size=page_size)
    )

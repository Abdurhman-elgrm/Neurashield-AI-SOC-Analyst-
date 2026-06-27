from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import CurrentMember
from app.schemas.common import APIResponse

router = APIRouter(prefix="/notifications", tags=["Notifications"])


class NotificationPreferencesResponse(BaseModel):
    email_high_critical_alerts: bool = True
    email_agent_offline: bool = True
    email_new_investigation: bool = False


class NotificationPreferencesUpdate(BaseModel):
    email_high_critical_alerts: bool | None = None
    email_agent_offline: bool | None = None
    email_new_investigation: bool | None = None


@router.get("", response_model=APIResponse[NotificationPreferencesResponse])
async def get_notification_preferences(
    member: CurrentMember,
) -> APIResponse[NotificationPreferencesResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore
    prefs = m.notification_preferences or {}
    return APIResponse.ok(
        NotificationPreferencesResponse(
            email_high_critical_alerts=prefs.get("email_high_critical_alerts", True),
            email_agent_offline=prefs.get("email_agent_offline", True),
            email_new_investigation=prefs.get("email_new_investigation", False),
        )
    )


@router.patch("", response_model=APIResponse[NotificationPreferencesResponse])
async def update_notification_preferences(
    payload: NotificationPreferencesUpdate,
    member: CurrentMember,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[NotificationPreferencesResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore

    # Load fresh record
    result = await db.execute(select(TenantMember).where(TenantMember.id == m.id))
    fresh = result.scalar_one()

    current = dict(fresh.notification_preferences or {})
    update_data = payload.model_dump(exclude_none=True)
    current.update(update_data)
    fresh.notification_preferences = current

    await db.commit()

    return APIResponse.ok(
        NotificationPreferencesResponse(
            email_high_critical_alerts=current.get("email_high_critical_alerts", True),
            email_agent_offline=current.get("email_agent_offline", True),
            email_new_investigation=current.get("email_new_investigation", False),
        )
    )

"""
Outbound notification channels — Slack, Microsoft Teams, custom webhook,
PagerDuty, and email recipient lists.
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
from app.models.notification_channel import NotificationChannel
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse, EmptyResponse

router = APIRouter(prefix="/notification-channels", tags=["Notification Channels"])

_VALID_TYPES = {"slack", "teams", "webhook", "pagerduty", "email"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class ChannelResponse(BaseModel):
    id: UUID
    name: str
    type: str
    enabled: bool
    min_severity: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ChannelCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., description="One of: slack, teams, webhook, pagerduty, email")
    config: dict = Field(default_factory=dict)
    min_severity: str = Field(default="high")
    enabled: bool = Field(default=True)


class ChannelUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    config: dict | None = None
    min_severity: str | None = None
    enabled: bool | None = None


def _validate_channel(type_: str, config: dict) -> None:
    if type_ not in _VALID_TYPES:
        raise ValidationError(
            f"Invalid channel type. Must be one of: {', '.join(sorted(_VALID_TYPES))}"
        )

    missing: list[str] = []
    if type_ == "slack" and not config.get("webhook_url"):
        missing.append("webhook_url")
    elif type_ == "teams" and not config.get("webhook_url"):
        missing.append("webhook_url")
    elif type_ == "webhook" and not config.get("url"):
        missing.append("url")
    elif type_ == "pagerduty" and not config.get("integration_key"):
        missing.append("integration_key")
    elif type_ == "email" and not config.get("recipients"):
        missing.append("recipients")

    if missing:
        raise ValidationError(f"Missing required config fields for {type_}: {', '.join(missing)}")


@router.get(
    "",
    response_model=APIResponse[list[ChannelResponse]],
    summary="List all notification channels for the tenant",
)
async def list_channels(
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: AsyncSession = Depends(get_db),
) -> APIResponse[list[ChannelResponse]]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore
    result = await db.execute(
        select(NotificationChannel)
        .where(
            NotificationChannel.tenant_id == m.tenant_id,
            NotificationChannel.deleted_at.is_(None),
        )
        .order_by(NotificationChannel.created_at.desc())
    )
    channels = list(result.scalars().all())
    return APIResponse.ok([ChannelResponse.model_validate(c) for c in channels])


@router.post(
    "",
    response_model=APIResponse[ChannelResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a new notification channel",
)
async def create_channel(
    payload: ChannelCreateRequest,
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: AsyncSession = Depends(get_db),
) -> APIResponse[ChannelResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore

    _validate_channel(payload.type, payload.config)

    min_sev = payload.min_severity.lower()
    if min_sev not in _VALID_SEVERITIES:
        raise ValidationError(
            f"Invalid min_severity. Must be one of: {', '.join(_VALID_SEVERITIES)}"
        )

    channel = NotificationChannel(
        tenant_id=m.tenant_id,
        name=payload.name.strip(),
        type=payload.type,
        config=payload.config,
        min_severity=min_sev,
        enabled=payload.enabled,
        created_by_id=m.user_id,
    )
    db.add(channel)
    await db.flush([channel])
    await db.commit()
    await db.refresh(channel)
    return APIResponse.ok(ChannelResponse.model_validate(channel))


@router.patch(
    "/{channel_id}",
    response_model=APIResponse[ChannelResponse],
    summary="Update a notification channel",
)
async def update_channel(
    channel_id: UUID,
    payload: ChannelUpdateRequest,
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: AsyncSession = Depends(get_db),
) -> APIResponse[ChannelResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore

    result = await db.execute(
        select(NotificationChannel).where(
            NotificationChannel.id == channel_id,
            NotificationChannel.tenant_id == m.tenant_id,
            NotificationChannel.deleted_at.is_(None),
        )
    )
    channel = result.scalar_one_or_none()
    if channel is None:
        raise NotFoundError("Notification channel not found")

    if payload.name is not None:
        channel.name = payload.name.strip()
    if payload.config is not None:
        _validate_channel(channel.type, payload.config)
        channel.config = payload.config
    if payload.min_severity is not None:
        min_sev = payload.min_severity.lower()
        if min_sev not in _VALID_SEVERITIES:
            raise ValidationError(
                f"Invalid min_severity. Must be one of: {', '.join(_VALID_SEVERITIES)}"
            )
        channel.min_severity = min_sev
    if payload.enabled is not None:
        channel.enabled = payload.enabled

    channel.updated_at = datetime.now(tz=UTC)
    await db.flush([channel])
    await db.commit()
    await db.refresh(channel)
    return APIResponse.ok(ChannelResponse.model_validate(channel))


@router.delete(
    "/{channel_id}",
    response_model=APIResponse[EmptyResponse],
    summary="Delete a notification channel",
)
async def delete_channel(
    channel_id: UUID,
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: AsyncSession = Depends(get_db),
) -> APIResponse[EmptyResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore

    result = await db.execute(
        select(NotificationChannel).where(
            NotificationChannel.id == channel_id,
            NotificationChannel.tenant_id == m.tenant_id,
            NotificationChannel.deleted_at.is_(None),
        )
    )
    channel = result.scalar_one_or_none()
    if channel is None:
        raise NotFoundError("Notification channel not found")

    channel.deleted_at = datetime.now(tz=UTC)
    await db.flush([channel])
    await db.commit()
    return APIResponse.ok(EmptyResponse())


@router.post(
    "/{channel_id}/test",
    response_model=APIResponse[dict],
    summary="Send a test notification to verify channel config",
)
async def test_channel(
    channel_id: UUID,
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: AsyncSession = Depends(get_db),
) -> APIResponse[dict]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore

    result = await db.execute(
        select(NotificationChannel).where(
            NotificationChannel.id == channel_id,
            NotificationChannel.tenant_id == m.tenant_id,
            NotificationChannel.deleted_at.is_(None),
        )
    )
    channel = result.scalar_one_or_none()
    if channel is None:
        raise NotFoundError("Notification channel not found")

    from app.services.outbound_notification_service import dispatch_test_notification

    success = await dispatch_test_notification(channel)
    return APIResponse.ok({"success": success, "channel_type": channel.type})

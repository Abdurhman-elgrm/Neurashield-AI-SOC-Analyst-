from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.core.exceptions import NotFoundError
from app.events.schemas import (
    EventContextResponse,
    EventSearchRequest,
    EventSearchResponse,
    ExportRequest,
    TimelineResponse,
)
from app.events.search import EventSearchService
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse, PaginatedResponse
from app.schemas.event import EventFilterParams, EventResponse
from app.services.event_service import EventService

router = APIRouter(prefix="/events", tags=["events"])


# ─── Phase 3.6: Static-path routes MUST come before /{event_id} ──────────────


@router.post("/search", response_model=EventSearchResponse)
async def search_events(
    member: Annotated[object, require_permission(Permission.EVENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    req: EventSearchRequest = Body(...),
) -> EventSearchResponse:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    return await EventSearchService.search(db, m.tenant_id, req)


@router.get("/timeline", response_model=TimelineResponse)
async def events_timeline(
    member: Annotated[object, require_permission(Permission.EVENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    from_ts: datetime | None = Query(default=None),
    to_ts: datetime | None = Query(default=None),
    categories: list[str] | None = Query(default=None),
    severity_min: int | None = Query(default=None, ge=1, le=4),
    host_names: list[str] | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> TimelineResponse:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    return await EventSearchService.timeline(
        db,
        m.tenant_id,
        from_ts=from_ts,
        to_ts=to_ts,
        categories=categories,
        severity_min=severity_min,
        host_names=host_names,
        cursor=cursor,
        limit=limit,
    )


@router.post("/export")
async def export_events(
    member: Annotated[object, require_permission(Permission.EVENTS_EXPORT)],
    db: Annotated[AsyncSession, Depends(get_db)],
    req: ExportRequest = Body(...),
) -> StreamingResponse:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    fmt = req.format.value
    media_types = {
        "csv": "text/csv",
        "json": "application/json",
        "ndjson": "application/x-ndjson",
    }
    media_type = media_types[fmt]
    filename = f"events_export.{fmt}"

    return StreamingResponse(
        EventSearchService.export_stream(db, m.tenant_id, req),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─── Phase 2: Original list route (preserved) ────────────────────────────────


@router.get("", response_model=PaginatedResponse[EventResponse])
async def list_events(
    member: Annotated[object, require_permission(Permission.EVENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    category: str | None = Query(default=None),
    severity_min: int | None = Query(default=None, ge=1, le=4),
    host_name: str | None = Query(default=None),
    agent_id: UUID | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> PaginatedResponse[EventResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    params = EventFilterParams(
        category=category,
        severity_min=severity_min,
        host_name=host_name,
        agent_id=agent_id,
        cursor=cursor,
        limit=limit,
    )
    events, next_cursor = await EventService.list_events(db, m.tenant_id, params)
    return PaginatedResponse[EventResponse].cursor(
        data=[EventResponse.model_validate(e) for e in events],
        next_cursor=next_cursor,
        prev_cursor=None,
        has_more=next_cursor is not None,
        limit=limit,
    )


# ─── Phase 3.6: /{event_id}/context BEFORE /{event_id} ───────────────────────


@router.get("/{event_id}/context", response_model=APIResponse[EventContextResponse])
async def get_event_context(
    event_id: UUID,
    member: Annotated[object, require_permission(Permission.EVENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EventContextResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    ctx = await EventSearchService.get_context(db, m.tenant_id, event_id)
    if ctx is None:
        raise NotFoundError(f"Event {event_id} not found")
    return APIResponse.ok(ctx)


# ─── Phase 2: Single-event route (preserved) ─────────────────────────────────


@router.get("/{event_id}", response_model=APIResponse[EventResponse])
async def get_event(
    event_id: UUID,
    member: Annotated[object, require_permission(Permission.EVENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EventResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    event = await EventService.get_by_id(db, m.tenant_id, event_id)
    if event is None:
        raise NotFoundError(f"Event {event_id} not found")
    return APIResponse.ok(EventResponse.model_validate(event))

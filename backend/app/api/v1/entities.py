from __future__ import annotations

"""
Entity-centric event queries.

Entity key format: {type}:{value}
  Examples:
    host:dc01.corp.local
    user:CORP\\john.doe
    ip:192.168.1.100
    process:cmd.exe

Valid entity types: host | user | ip | process
"""

from datetime import datetime
from typing import Annotated
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.events.schemas import EntityEventsResponse, EntityType
from app.events.search import EventSearchService
from app.rbac.permissions import Permission

router = APIRouter(prefix="/entities", tags=["entities"])

_VALID_ENTITY_TYPES: frozenset[str] = frozenset(t.value for t in EntityType)


@router.get("/{entity_key:path}/events", response_model=EntityEventsResponse)
async def get_entity_events(
    entity_key: str,
    member: Annotated[object, require_permission(Permission.EVENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    from_ts: datetime | None = Query(default=None),
    to_ts: datetime | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> EntityEventsResponse:
    """
    Returns events scoped to a single entity.

    Path: /entities/{type}:{value}/events
    e.g.: /entities/host:dc01.corp.local/events
          /entities/ip:192.168.1.1/events
    """
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]

    # URL-decode in case the value contains encoded characters (e.g., backslash in usernames)
    decoded_key = unquote(entity_key)
    colon_pos = decoded_key.find(":")
    if colon_pos < 1:
        raise HTTPException(
            status_code=422,
            detail="entity_key must be in the format '{type}:{value}', e.g. 'host:dc01'",
        )

    entity_type = decoded_key[:colon_pos]
    entity_value = decoded_key[colon_pos + 1:]

    if entity_type not in _VALID_ENTITY_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid entity type '{entity_type}'. Must be one of: {sorted(_VALID_ENTITY_TYPES)}",
        )
    if not entity_value:
        raise HTTPException(status_code=422, detail="Entity value cannot be empty")

    return await EventSearchService.entity_events(
        db,
        m.tenant_id,
        entity_type=entity_type,
        entity_value=entity_value,
        from_ts=from_ts,
        to_ts=to_ts,
        cursor=cursor,
        limit=limit,
    )

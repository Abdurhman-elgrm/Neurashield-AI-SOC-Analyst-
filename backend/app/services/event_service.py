from __future__ import annotations

import base64
from datetime import datetime
from uuid import UUID

import structlog
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event, EventCategory
from app.schemas.event import EventFilterParams

logger = structlog.get_logger(__name__)


class EventService:
    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        event_id: UUID,
    ) -> Event | None:
        result = await db.execute(
            select(Event).where(
                Event.id == event_id,
                Event.tenant_id == tenant_id,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def list_events(
        db: AsyncSession,
        tenant_id: UUID,
        params: EventFilterParams,
    ) -> tuple[list[Event], str | None]:
        """Returns (events, next_cursor).  Cursor is opaque — encodes event timestamp+id."""
        conditions = [Event.tenant_id == tenant_id]

        if params.category:
            try:
                conditions.append(Event.category == EventCategory(params.category))
            except ValueError:
                pass

        if params.severity_min is not None:
            conditions.append(Event.severity >= params.severity_min)

        if params.host_name:
            conditions.append(Event.host_name == params.host_name)

        if params.agent_id:
            conditions.append(Event.agent_id == params.agent_id)

        if params.from_ts:
            conditions.append(Event.event_timestamp >= params.from_ts)

        if params.to_ts:
            conditions.append(Event.event_timestamp <= params.to_ts)

        if params.cursor:
            try:
                ts_str, id_str = _decode_cursor(params.cursor)
                ts = datetime.fromisoformat(ts_str)
                conditions.append(
                    and_(
                        Event.event_timestamp <= ts,
                        Event.id < UUID(id_str),
                    )
                )
            except Exception:
                pass  # bad cursor — ignore and start from beginning

        limit = min(params.limit, 200)

        result = await db.execute(
            select(Event)
            .where(*conditions)
            .order_by(Event.event_timestamp.desc(), Event.id.desc())
            .limit(limit + 1)
        )
        events = list(result.scalars().all())

        next_cursor: str | None = None
        if len(events) > limit:
            last = events[limit - 1]
            next_cursor = _encode_cursor(last.event_timestamp.isoformat(), str(last.id))
            events = events[:limit]

        return events, next_cursor


def _encode_cursor(ts: str, id_str: str) -> str:
    raw = f"{ts}|{id_str}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[str, str]:
    raw = base64.urlsafe_b64decode(cursor.encode()).decode()
    ts, _, id_str = raw.partition("|")
    return ts, id_str

from __future__ import annotations

"""
Events Explorer search service.

Provides:
  - search()           Full-text + filter search with cursor pagination
  - timeline()         Chronological event stream + histogram buckets
  - get_context()      Prev/next/same-host/user/ip/session/process/correlation events
  - entity_events()    Events scoped to a single entity (host, user, ip, process)
  - export_stream()    Async generator for streaming CSV/JSON/NDJSON export
"""

import csv
import io
import json
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.events.pagination import (
    CursorError,
    decode_simple_cursor,
    encode_cursor,
    encode_simple_cursor,
)
from app.events.query_builder import build_search_query
from app.events.schemas import (
    EntityEventsResponse,
    EntityType,
    EventContextResponse,
    EventSearchRequest,
    EventSearchResponse,
    ExportFormat,
    ExportRequest,
    SortDirection,
    SortField,
    TimelineBucket,
    TimelineResponse,
)
from app.models.event import Event, EventCategory
from app.schemas.event import EventResponse

logger = structlog.get_logger(__name__)

_CONTEXT_LIMIT = 10  # events returned per context section
_TIMELINE_BUCKET_COUNT = 50  # histogram buckets in timeline view


class EventSearchService:
    # ─── Search ───────────────────────────────────────────────────────────────

    @staticmethod
    async def search(
        db: AsyncSession,
        tenant_id: UUID,
        req: EventSearchRequest,
    ) -> EventSearchResponse:
        limit = min(req.limit, 500)
        stmt = build_search_query(tenant_id, req).limit(limit + 1)

        result = await db.execute(stmt)
        events = list(result.scalars().all())

        has_more = len(events) > limit
        if has_more:
            events = events[:limit]

        next_cursor: str | None = None
        if has_more and events:
            last = events[-1]
            ts_val = getattr(last, req.sort_by.value)
            if isinstance(ts_val, datetime):
                next_cursor = encode_cursor(ts_val, last.id, req.sort_by.value, req.sort_dir.value)
            else:
                # For non-datetime sort fields, fall back to timestamp for cursor
                next_cursor = encode_cursor(
                    last.event_timestamp, last.id, req.sort_by.value, req.sort_dir.value
                )

        items = [EventResponse.model_validate(e) for e in events]
        return EventSearchResponse(
            items=items,
            next_cursor=next_cursor,
            prev_cursor=None,
            has_more=has_more,
            total_estimate=None,
        )

    # ─── Timeline ─────────────────────────────────────────────────────────────

    @staticmethod
    async def timeline(
        db: AsyncSession,
        tenant_id: UUID,
        from_ts: datetime | None,
        to_ts: datetime | None,
        categories: list[str] | None,
        severity_min: int | None,
        host_names: list[str] | None,
        cursor: str | None,
        limit: int = 50,
    ) -> TimelineResponse:
        limit = min(limit, 500)
        conditions = [Event.tenant_id == tenant_id]

        effective_from = from_ts
        effective_to = to_ts

        if effective_from:
            conditions.append(Event.event_timestamp >= effective_from)
        if effective_to:
            conditions.append(Event.event_timestamp <= effective_to)

        if categories:
            valid_cats = [
                EventCategory(c) for c in categories if c in EventCategory._value2member_map_
            ]
            if valid_cats:
                conditions.append(Event.category.in_(valid_cats))

        if severity_min is not None:
            conditions.append(Event.severity >= severity_min)

        if host_names:
            conditions.append(Event.host_name.in_(host_names))

        if cursor:
            try:
                cur_ts, cur_id = decode_simple_cursor(cursor)
                conditions.append(
                    or_(
                        Event.event_timestamp < cur_ts,
                        and_(Event.event_timestamp == cur_ts, Event.id < cur_id),
                    )
                )
            except CursorError:
                pass

        stmt = (
            select(Event)
            .where(and_(*conditions))
            .order_by(Event.event_timestamp.desc(), Event.id.desc())
            .limit(limit + 1)
        )
        result = await db.execute(stmt)
        events = list(result.scalars().all())

        has_more = len(events) > limit
        if has_more:
            events = events[:limit]

        next_cursor: str | None = None
        if has_more and events:
            last = events[-1]
            next_cursor = encode_simple_cursor(last.event_timestamp, last.id)

        # Build histogram buckets
        buckets = await EventSearchService._build_timeline_buckets(
            db,
            tenant_id,
            effective_from,
            effective_to,
            conditions[1:],  # skip tenant_id (already in outer query)
        )

        items = [EventResponse.model_validate(e) for e in events]
        return TimelineResponse(
            items=items,
            buckets=buckets,
            next_cursor=next_cursor,
            has_more=has_more,
            from_ts=effective_from,
            to_ts=effective_to,
        )

    @staticmethod
    async def _build_timeline_buckets(
        db: AsyncSession,
        tenant_id: UUID,
        from_ts: datetime | None,
        to_ts: datetime | None,
        extra_conditions: list,
    ) -> list[TimelineBucket]:
        # Only compute buckets when a bounded time range is provided
        if not from_ts or not to_ts:
            return []

        span = (to_ts - from_ts).total_seconds()
        if span <= 0:
            return []

        bucket_seconds = span / _TIMELINE_BUCKET_COUNT
        if bucket_seconds < 1:
            bucket_seconds = 1.0

        # Use PostgreSQL date_bin for equal-width buckets
        bucket_expr = func.date_bin(
            text(f"'{int(bucket_seconds)} seconds'"),
            Event.event_timestamp,
            text("TIMESTAMP WITH TIME ZONE 'epoch'"),
        ).label("bucket")

        stmt = (
            select(
                bucket_expr,
                func.count().label("cnt"),
                Event.severity,
                Event.category,
            )
            .where(
                Event.tenant_id == tenant_id,
                Event.event_timestamp >= from_ts,
                Event.event_timestamp <= to_ts,
                *extra_conditions,
            )
            .group_by(bucket_expr, Event.severity, Event.category)
            .order_by(bucket_expr)
        )

        result = await db.execute(stmt)
        rows = result.all()

        # Aggregate rows into bucket objects
        bucket_map: dict[datetime, dict] = {}
        for row in rows:
            bt: datetime = row.bucket
            if bt not in bucket_map:
                bucket_end = datetime.fromtimestamp(bt.timestamp() + bucket_seconds, tz=UTC)
                bucket_map[bt] = {
                    "bucket_start": bt,
                    "bucket_end": bucket_end,
                    "count": 0,
                    "severity_breakdown": {},
                    "category_breakdown": {},
                }
            b = bucket_map[bt]
            b["count"] += row.cnt
            sev_key = str(row.severity)
            b["severity_breakdown"][sev_key] = b["severity_breakdown"].get(sev_key, 0) + row.cnt
            cat_key = row.category.value if hasattr(row.category, "value") else str(row.category)
            b["category_breakdown"][cat_key] = b["category_breakdown"].get(cat_key, 0) + row.cnt

        return [
            TimelineBucket(**v)
            for v in sorted(bucket_map.values(), key=lambda x: x["bucket_start"])
        ]

    # ─── Event context ────────────────────────────────────────────────────────

    @staticmethod
    async def get_context(
        db: AsyncSession,
        tenant_id: UUID,
        event_id: UUID,
    ) -> EventContextResponse | None:
        event = await db.scalar(
            select(Event).where(Event.id == event_id, Event.tenant_id == tenant_id)
        )
        if event is None:
            return None

        prev_event, next_event = await EventSearchService._get_adjacent(db, tenant_id, event)
        same_host = await EventSearchService._context_events(
            db,
            tenant_id,
            event_id,
            Event.host_name == event.host_name if event.host_name else None,
        )
        same_user = await EventSearchService._context_events(
            db,
            tenant_id,
            event_id,
            Event.username == event.username if event.username else None,
        )
        same_ip = await EventSearchService._context_events(
            db,
            tenant_id,
            event_id,
            or_(Event.source_ip == event.source_ip, Event.dest_ip == event.source_ip)
            if event.source_ip
            else None,
        )
        same_session = await EventSearchService._context_events(
            db,
            tenant_id,
            event_id,
            Event.session_id == event.session_id  # type: ignore[attr-defined]
            if getattr(event, "session_id", None)
            else None,
        )
        same_process = await EventSearchService._context_events(
            db,
            tenant_id,
            event_id,
            Event.process_tree_id == event.process_tree_id  # type: ignore[attr-defined]
            if getattr(event, "process_tree_id", None)
            else None,
        )
        correlated = await EventSearchService._context_events(
            db,
            tenant_id,
            event_id,
            Event.correlation_id == event.correlation_id  # type: ignore[attr-defined]
            if getattr(event, "correlation_id", None)
            else None,
        )

        def _to_resp(e: Event | None) -> EventResponse | None:
            return EventResponse.model_validate(e) if e else None

        return EventContextResponse(
            event=EventResponse.model_validate(event),
            prev_event=_to_resp(prev_event),
            next_event=_to_resp(next_event),
            same_host_events=[EventResponse.model_validate(e) for e in same_host],
            same_user_events=[EventResponse.model_validate(e) for e in same_user],
            same_ip_events=[EventResponse.model_validate(e) for e in same_ip],
            same_session_events=[EventResponse.model_validate(e) for e in same_session],
            same_process_events=[EventResponse.model_validate(e) for e in same_process],
            correlated_events=[EventResponse.model_validate(e) for e in correlated],
        )

    @staticmethod
    async def _get_adjacent(
        db: AsyncSession,
        tenant_id: UUID,
        event: Event,
    ) -> tuple[Event | None, Event | None]:
        ts = event.event_timestamp

        prev_result = await db.execute(
            select(Event)
            .where(
                Event.tenant_id == tenant_id,
                or_(
                    Event.event_timestamp < ts,
                    and_(Event.event_timestamp == ts, Event.id < event.id),
                ),
            )
            .order_by(Event.event_timestamp.desc(), Event.id.desc())
            .limit(1)
        )
        prev_event = prev_result.scalar_one_or_none()

        next_result = await db.execute(
            select(Event)
            .where(
                Event.tenant_id == tenant_id,
                or_(
                    Event.event_timestamp > ts,
                    and_(Event.event_timestamp == ts, Event.id > event.id),
                ),
            )
            .order_by(Event.event_timestamp.asc(), Event.id.asc())
            .limit(1)
        )
        next_event = next_result.scalar_one_or_none()
        return prev_event, next_event

    @staticmethod
    async def _context_events(
        db: AsyncSession,
        tenant_id: UUID,
        exclude_id: UUID,
        extra_condition,
    ) -> list[Event]:
        if extra_condition is None:
            return []
        result = await db.execute(
            select(Event)
            .where(
                Event.tenant_id == tenant_id,
                Event.id != exclude_id,
                extra_condition,
            )
            .order_by(Event.event_timestamp.desc())
            .limit(_CONTEXT_LIMIT)
        )
        return list(result.scalars().all())

    # ─── Entity-centric events ────────────────────────────────────────────────

    @staticmethod
    async def entity_events(
        db: AsyncSession,
        tenant_id: UUID,
        entity_type: str,
        entity_value: str,
        from_ts: datetime | None,
        to_ts: datetime | None,
        cursor: str | None,
        limit: int = 50,
    ) -> EntityEventsResponse:
        limit = min(limit, 500)

        entity_condition = EventSearchService._entity_condition(entity_type, entity_value)
        if entity_condition is None:
            return EntityEventsResponse(
                entity_type=entity_type,
                entity_value=entity_value,
                items=[],
                next_cursor=None,
                has_more=False,
                total_events=0,
            )

        base_conditions = [Event.tenant_id == tenant_id, entity_condition]
        if from_ts:
            base_conditions.append(Event.event_timestamp >= from_ts)
        if to_ts:
            base_conditions.append(Event.event_timestamp <= to_ts)

        if cursor:
            try:
                cur_ts, cur_id = decode_simple_cursor(cursor)
                base_conditions.append(
                    or_(
                        Event.event_timestamp < cur_ts,
                        and_(Event.event_timestamp == cur_ts, Event.id < cur_id),
                    )
                )
            except CursorError:
                pass

        count_result = await db.execute(
            select(func.count()).where(Event.tenant_id == tenant_id, entity_condition)
        )
        total = count_result.scalar_one() or 0

        result = await db.execute(
            select(Event)
            .where(and_(*base_conditions))
            .order_by(Event.event_timestamp.desc(), Event.id.desc())
            .limit(limit + 1)
        )
        events = list(result.scalars().all())

        has_more = len(events) > limit
        if has_more:
            events = events[:limit]

        next_cursor: str | None = None
        if has_more and events:
            last = events[-1]
            next_cursor = encode_simple_cursor(last.event_timestamp, last.id)

        return EntityEventsResponse(
            entity_type=entity_type,
            entity_value=entity_value,
            items=[EventResponse.model_validate(e) for e in events],
            next_cursor=next_cursor,
            has_more=has_more,
            total_events=total,
        )

    @staticmethod
    def _entity_condition(entity_type: str, entity_value: str):
        if entity_type == EntityType.HOST.value:
            return Event.host_name == entity_value
        if entity_type == EntityType.USER.value:
            return Event.username == entity_value
        if entity_type == EntityType.IP.value:
            return or_(Event.source_ip == entity_value, Event.dest_ip == entity_value)
        if entity_type == EntityType.PROCESS.value:
            return Event.process_name == entity_value
        return None

    # ─── Streaming export ─────────────────────────────────────────────────────

    @staticmethod
    async def export_stream(
        db: AsyncSession,
        tenant_id: UUID,
        req: ExportRequest,
    ) -> AsyncGenerator[str | bytes, None]:
        """
        Async generator that yields chunks suitable for StreamingResponse.
        Fetches in pages of 1000 to avoid loading all rows into memory.
        """
        from app.events.schemas import EventSearchRequest

        search_req = EventSearchRequest(
            query=req.query,
            categories=req.categories,
            severity_min=req.severity_min,
            severity_max=req.severity_max,
            host_names=req.host_names,
            usernames=req.usernames,
            source_ips=req.source_ips,
            dest_ips=req.dest_ips,
            process_names=req.process_names,
            agent_ids=req.agent_ids,
            tags=req.tags,
            correlation_id=req.correlation_id,
            session_id=req.session_id,
            from_ts=req.from_ts,
            to_ts=req.to_ts,
            filter_groups=req.filter_groups,
            sort_by=SortField.EVENT_TIMESTAMP,
            sort_dir=SortDirection.DESC,
            limit=1000,
        )

        exported = 0
        max_rows = req.max_rows

        if req.format == ExportFormat.CSV:
            # CSV header
            output = io.StringIO()
            writer = csv.DictWriter(
                output,
                fieldnames=_csv_fields(req.fields),
                extrasaction="ignore",
            )
            writer.writeheader()
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

        elif req.format == ExportFormat.JSON:
            yield "["

        cursor: str | None = None
        first_json = True

        while exported < max_rows:
            search_req.cursor = cursor
            search_req.limit = min(1000, max_rows - exported)

            stmt = build_search_query(tenant_id, search_req).limit(search_req.limit + 1)
            result = await db.execute(stmt)
            batch = list(result.scalars().all())

            has_more = len(batch) > search_req.limit
            if has_more:
                batch = batch[: search_req.limit]

            for event in batch:
                row = _event_to_dict(event, req.fields)

                if req.format == ExportFormat.NDJSON:
                    yield json.dumps(row, default=str) + "\n"
                elif req.format == ExportFormat.CSV:
                    output = io.StringIO()
                    writer = csv.DictWriter(
                        output,
                        fieldnames=_csv_fields(req.fields),
                        extrasaction="ignore",
                    )
                    writer.writerow(row)
                    yield output.getvalue()
                elif req.format == ExportFormat.JSON:
                    prefix = "" if first_json else ","
                    first_json = False
                    yield prefix + json.dumps(row, default=str)

            exported += len(batch)

            if not has_more or not batch:
                break

            last = batch[-1]
            cursor = encode_cursor(
                last.event_timestamp,
                last.id,
                SortField.EVENT_TIMESTAMP.value,
                SortDirection.DESC.value,
            )

        if req.format == ExportFormat.JSON:
            yield "]"


# ─── Export helpers ───────────────────────────────────────────────────────────

_ALL_EXPORT_FIELDS = [
    "id",
    "tenant_id",
    "agent_id",
    "category",
    "severity",
    "event_timestamp",
    "ingested_at",
    "host_name",
    "source_ip",
    "dest_ip",
    "process_name",
    "username",
    "correlation_id",
    "session_id",
    "process_tree_id",
    "event_chain_id",
    "tags",
    "raw_id",
]


def _csv_fields(fields: list[str] | None) -> list[str]:
    return fields if fields else _ALL_EXPORT_FIELDS


def _event_to_dict(event: Event, fields: list[str] | None) -> dict[str, Any]:
    chosen = fields if fields else _ALL_EXPORT_FIELDS
    row: dict[str, Any] = {}
    for f in chosen:
        val = getattr(event, f, None)
        if isinstance(val, datetime):
            row[f] = val.isoformat()
        elif hasattr(val, "value"):
            row[f] = val.value
        else:
            row[f] = val
    return row

from __future__ import annotations

"""
SQLAlchemy query builder for EventSearchRequest.

All conditions are composed through SQLAlchemy parameter binding —
no raw SQL strings or f-string interpolation into queries.
"""

from uuid import UUID

from sqlalchemy import and_, func, or_, select
from sqlalchemy.sql import Select

from app.events.filters import build_filter_groups
from app.events.pagination import CursorError, decode_cursor
from app.events.schemas import EventSearchRequest, SortDirection, SortField
from app.models.event import Event, EventCategory

# ─── Allowed sort columns ─────────────────────────────────────────────────────

_SORT_COLUMN = {
    SortField.EVENT_TIMESTAMP: Event.event_timestamp,
    SortField.INGESTED_AT: Event.ingested_at,
    SortField.SEVERITY: Event.severity,
    SortField.HOST_NAME: Event.host_name,
}


# ─── Full-text search helper ──────────────────────────────────────────────────


def _fts_clause(query_text: str):  # type: ignore[return]
    """
    PostgreSQL full-text search across denormalized fields.
    Uses plainto_tsquery (safe — no special operator syntax) and
    a to_tsvector expression matching the GIN functional index.
    """
    ts_vector = func.to_tsvector(
        "english",
        func.coalesce(Event.host_name, "")
        + " "
        + func.coalesce(Event.username, "")
        + " "
        + func.coalesce(Event.process_name, "")
        + " "
        + func.coalesce(Event.source_ip, "")
        + " "
        + func.coalesce(Event.dest_ip, ""),
    )
    ts_query = func.plainto_tsquery("english", query_text)
    return ts_vector.op("@@")(ts_query)


def build_search_query(
    tenant_id: UUID,
    req: EventSearchRequest,
) -> Select:
    """Build the main search SELECT (without LIMIT) from EventSearchRequest."""
    conditions = [Event.tenant_id == tenant_id]

    # ── Full-text search ──────────────────────────────────────────────────────
    if req.query:
        conditions.append(_fts_clause(req.query))

    # ── Quick filters ─────────────────────────────────────────────────────────
    if req.categories:
        valid_cats = []
        for c in req.categories:
            try:
                valid_cats.append(EventCategory(c))
            except ValueError:
                pass
        if valid_cats:
            conditions.append(Event.category.in_(valid_cats))

    if req.severity_min is not None:
        conditions.append(Event.severity >= req.severity_min)
    if req.severity_max is not None:
        conditions.append(Event.severity <= req.severity_max)

    if req.host_names:
        conditions.append(Event.host_name.in_(req.host_names))
    if req.usernames:
        conditions.append(Event.username.in_(req.usernames))
    if req.source_ips:
        conditions.append(Event.source_ip.in_(req.source_ips))
    if req.dest_ips:
        conditions.append(Event.dest_ip.in_(req.dest_ips))
    if req.process_names:
        conditions.append(Event.process_name.in_(req.process_names))
    if req.agent_ids:
        conditions.append(Event.agent_id.in_(req.agent_ids))

    if req.tags:
        # All provided tags must appear in the event's tags array
        for tag in req.tags:
            conditions.append(Event.tags.contains([tag]))  # type: ignore[attr-defined]

    if req.correlation_id:
        conditions.append(Event.correlation_id == req.correlation_id)  # type: ignore[attr-defined]
    if req.session_id:
        conditions.append(Event.session_id == req.session_id)  # type: ignore[attr-defined]
    if req.process_tree_id:
        conditions.append(Event.process_tree_id == req.process_tree_id)  # type: ignore[attr-defined]
    if req.event_chain_id:
        conditions.append(Event.event_chain_id == req.event_chain_id)  # type: ignore[attr-defined]

    # ── Time range ────────────────────────────────────────────────────────────
    if req.from_ts:
        conditions.append(Event.event_timestamp >= req.from_ts)
    if req.to_ts:
        conditions.append(Event.event_timestamp <= req.to_ts)

    # ── Advanced filter groups ────────────────────────────────────────────────
    if req.filter_groups:
        advanced = build_filter_groups(req.filter_groups)
        conditions.extend(advanced)

    # ── Cursor (sort-stable seek) ─────────────────────────────────────────────
    sort_col = _SORT_COLUMN[req.sort_by]
    if req.cursor:
        try:
            cur_ts, cur_id, cur_sf, cur_dir = decode_cursor(req.cursor)
            # For timestamp DESC: next page is ts < cursor_ts OR (ts == cursor_ts AND id < cursor_id)
            if req.sort_dir == SortDirection.DESC:
                conditions.append(
                    or_(
                        sort_col < cur_ts,
                        and_(sort_col == cur_ts, Event.id < cur_id),
                    )
                )
            else:
                conditions.append(
                    or_(
                        sort_col > cur_ts,
                        and_(sort_col == cur_ts, Event.id > cur_id),
                    )
                )
        except CursorError:
            pass  # bad cursor — ignore and start from beginning

    # ── Build SELECT ──────────────────────────────────────────────────────────
    stmt = select(Event).where(and_(*conditions))

    if req.sort_dir == SortDirection.DESC:
        stmt = stmt.order_by(sort_col.desc(), Event.id.desc())
    else:
        stmt = stmt.order_by(sort_col.asc(), Event.id.asc())

    return stmt

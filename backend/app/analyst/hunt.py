from __future__ import annotations

"""
Threat hunting engine.

Investigation Hunt  — queries the investigations table (aggregated view).
Event Hunt          — queries the raw events table (true threat hunting on
                      individual normalized events with indexed entity fields).

All DB queries use parameterized SQLAlchemy ORM expressions.
No raw SQL string interpolation.
"""

import base64
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import and_, cast, func, or_, select
from sqlalchemy.dialects.postgresql import JSONB as PgJSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.models.analyst import SavedHunt
from app.models.event import Event
from app.models.investigation import Investigation
from app.analyst.schemas import (
    EventHuntFilter,
    EventHuntQuery,
    EventHuntResult,
    EventHuntResultEntry,
    EventHuntSummary,
    HuntFilter,
    HuntQuery,
    HuntResult,
    HuntResultEntry,
    SavedHuntCreate,
    SavedHuntOut,
)

logger = structlog.get_logger(__name__)

# Fields that can be directly filtered on the investigations ORM model
_DIRECT_FIELDS: dict[str, Any] = {
    "status":      Investigation.status,
    "confidence":  Investigation.confidence,
    "verdict":     Investigation.verdict,
}

# Numeric fields
_NUMERIC_FIELDS: dict[str, Any] = {
    "threat_score": Investigation.threat_score,
}

# Text fields (ILIKE)
_TEXT_FIELDS: dict[str, Any] = {
    "title":             Investigation.title,
    "executive_summary": Investigation.executive_summary,
    "technical_summary": Investigation.technical_summary,
}


class HuntEngine:

    @staticmethod
    async def run_query(
        db: AsyncSession,
        tenant_id: UUID,
        query: HuntQuery,
    ) -> HuntResult:
        conditions = [Investigation.tenant_id == tenant_id]

        # ── Time range ─────────────────────────────────────────────────────────
        if query.from_ts is not None:
            conditions.append(Investigation.created_at >= query.from_ts)
        if query.to_ts is not None:
            conditions.append(Investigation.created_at <= query.to_ts)

        # ── Score range ────────────────────────────────────────────────────────
        if query.min_score is not None:
            conditions.append(Investigation.threat_score >= query.min_score)
        if query.max_score is not None:
            conditions.append(Investigation.threat_score <= query.max_score)

        # ── Status ─────────────────────────────────────────────────────────────
        if query.status:
            conditions.append(Investigation.status == query.status)

        # ── Field-level filters ────────────────────────────────────────────────
        filter_clauses = _build_filter_clauses(query.filters)
        if filter_clauses:
            if query.logic == "or":
                conditions.append(or_(*filter_clauses))
            else:
                conditions.extend(filter_clauses)

        # ── Cursor ────────────────────────────────────────────────────────────
        if query.cursor:
            try:
                ts_str, id_str = _decode_cursor(query.cursor)
                ts = datetime.fromisoformat(ts_str)
                if query.sort == "desc":
                    conditions.append(
                        and_(
                            Investigation.created_at <= ts,
                            Investigation.id < UUID(id_str),
                        )
                    )
                else:
                    conditions.append(
                        and_(
                            Investigation.created_at >= ts,
                            Investigation.id > UUID(id_str),
                        )
                    )
            except Exception:
                pass

        limit = min(query.limit, 200)
        order = (
            Investigation.created_at.desc()
            if query.sort == "desc"
            else Investigation.created_at.asc()
        )

        stmt = (
            select(Investigation)
            .where(*conditions)
            .order_by(order, Investigation.id)
            .limit(limit + 1)
        )
        result = await db.execute(stmt)
        rows = list(result.scalars().all())

        # ── Post-filter for MITRE tactics and rule matches (JSONB) ─────────────
        if query.mitre_tactics or query.rule_matches:
            rows = [r for r in rows if _matches_jsonb_filters(r, query)]

        next_cursor: str | None = None
        has_more = len(rows) > limit
        if has_more:
            last = rows[limit - 1]
            next_cursor = _encode_cursor(
                last.created_at.isoformat(), str(last.id)
            )
            rows = rows[:limit]

        # Build match reasons per row
        entries = [
            HuntResultEntry(
                investigation_id=str(r.investigation_group_id),
                tenant_id=str(r.tenant_id),
                threat_score=r.threat_score,
                confidence=r.confidence,
                status=r.status,
                verdict=r.verdict,
                assigned_to=r.assigned_to,
                executive_summary=r.executive_summary,
                created_at=r.created_at,
                match_reasons=_build_match_reasons(r, query),
            )
            for r in rows
        ]

        return HuntResult(
            entries=entries,
            total=len(entries),
            next_cursor=next_cursor,
            has_more=has_more,
        )

    @staticmethod
    async def save_hunt(
        db: AsyncSession,
        tenant_id: UUID,
        analyst_id: UUID,
        payload: SavedHuntCreate,
    ) -> SavedHunt:
        hunt = SavedHunt(
            tenant_id=tenant_id,
            analyst_id=analyst_id,
            name=payload.name,
            description=payload.description,
            query_params=payload.query_params,
        )
        db.add(hunt)
        await db.flush([hunt])
        logger.info(
            "hunt_saved",
            hunt_id=str(hunt.id),
            name=payload.name,
            tenant_id=str(tenant_id),
        )
        return hunt

    @staticmethod
    async def list_saved_hunts(
        db: AsyncSession,
        tenant_id: UUID,
        analyst_id: UUID | None = None,
    ) -> list[SavedHunt]:
        conditions = [SavedHunt.tenant_id == tenant_id]
        if analyst_id:
            conditions.append(SavedHunt.analyst_id == analyst_id)
        result = await db.execute(
            select(SavedHunt)
            .where(*conditions)
            .order_by(SavedHunt.updated_at.desc())
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_saved_hunt(
        db: AsyncSession,
        tenant_id: UUID,
        hunt_id: UUID,
    ) -> SavedHunt:
        result = await db.execute(
            select(SavedHunt).where(
                SavedHunt.id == hunt_id,
                SavedHunt.tenant_id == tenant_id,
            )
        )
        hunt = result.scalar_one_or_none()
        if hunt is None:
            raise NotFoundError(f"Saved hunt {hunt_id} not found")
        return hunt

    @staticmethod
    async def delete_saved_hunt(
        db: AsyncSession,
        tenant_id: UUID,
        hunt_id: UUID,
    ) -> None:
        hunt = await HuntEngine.get_saved_hunt(db, tenant_id, hunt_id)
        await db.delete(hunt)
        await db.flush()

    @staticmethod
    async def increment_run_count(
        db: AsyncSession,
        tenant_id: UUID,
        hunt_id: UUID,
    ) -> None:
        hunt = await HuntEngine.get_saved_hunt(db, tenant_id, hunt_id)
        hunt.run_count = (hunt.run_count or 0) + 1
        hunt.updated_at = datetime.now(tz=timezone.utc)
        await db.flush([hunt])


# ─── Filter building ──────────────────────────────────────────────────────────

def _build_filter_clauses(filters: list[HuntFilter]) -> list[Any]:
    clauses: list[Any] = []
    for f in filters:
        col = _resolve_column(f.field)
        if col is None:
            continue
        clause = _apply_operator(col, f.value, f.operator)
        if clause is not None:
            clauses.append(clause)
    return clauses


def _resolve_column(field: str) -> Any:
    if field in _DIRECT_FIELDS:
        return _DIRECT_FIELDS[field]
    if field in _TEXT_FIELDS:
        return _TEXT_FIELDS[field]
    if field in _NUMERIC_FIELDS:
        return _NUMERIC_FIELDS[field]
    return None


def _apply_operator(col: Any, value: str, operator: str) -> Any:
    try:
        if operator == "eq":
            return col == value
        elif operator == "contains":
            return col.ilike(f"%{value}%")
        elif operator == "startswith":
            return col.ilike(f"{value}%")
        elif operator == "endswith":
            return col.ilike(f"%{value}")
        elif operator == "gt":
            return col > int(value)
        elif operator == "lt":
            return col < int(value)
        elif operator == "gte":
            return col >= int(value)
        elif operator == "lte":
            return col <= int(value)
    except (ValueError, TypeError):
        pass
    return None


def _matches_jsonb_filters(row: Investigation, query: HuntQuery) -> bool:
    if query.mitre_tactics:
        behaviors: dict[str, Any] = row.behaviors_json or {}
        detected = behaviors.get("detected_behaviors") or []
        row_tactics: set[str] = set()
        for b in detected:
            row_tactics.update(b.get("mitre_tactics") or [])
        if not any(t in row_tactics for t in query.mitre_tactics):
            return False

    if query.rule_matches:
        timeline: dict[str, Any] = row.timeline_json or {}
        entries = timeline.get("entries") or []
        row_rules: set[str] = set()
        for e in entries:
            row_rules.update(e.get("rule_match") or [])
        if not any(r in row_rules for r in query.rule_matches):
            return False

    return True


def _build_match_reasons(row: Investigation, query: HuntQuery) -> list[str]:
    reasons: list[str] = []
    if query.min_score is not None and row.threat_score >= query.min_score:
        reasons.append(f"threat_score={row.threat_score}")
    if query.mitre_tactics:
        behaviors: dict[str, Any] = row.behaviors_json or {}
        detected = behaviors.get("detected_behaviors") or []
        matched = [
            b["behavior_name"] for b in detected
            if any(t in (b.get("mitre_tactics") or []) for t in query.mitre_tactics)
        ]
        if matched:
            reasons.append(f"behaviors: {', '.join(matched)}")
    for f in query.filters:
        if f.field in ("executive_summary", "technical_summary") and f.operator == "contains":
            reasons.append(f"text match: {f.field} contains '{f.value}'")
    return reasons


# ─── Cursor helpers ───────────────────────────────────────────────────────────

def _encode_cursor(ts: str, id_str: str) -> str:
    return base64.urlsafe_b64encode(f"{ts}|{id_str}".encode()).decode()


def _decode_cursor(cursor: str) -> tuple[str, str]:
    raw = base64.urlsafe_b64decode(cursor.encode()).decode()
    ts, _, id_str = raw.partition("|")
    return ts, id_str


# ─── Event Hunt ───────────────────────────────────────────────────────────────

# Indexed text columns on the Event model — safe to ILIKE without full table scan
_EVENT_TEXT_FIELDS: dict[str, Any] = {
    "host_name":      Event.host_name,
    "username":       Event.username,
    "process_name":   Event.process_name,
    "source_ip":      Event.source_ip,
    "dest_ip":        Event.dest_ip,
    "correlation_id": Event.correlation_id,
    "session_id":     Event.session_id,
    "geo_country":    Event.geo_country,
    "geo_city":       Event.geo_city,
}

_EVENT_NUMERIC_FIELDS: dict[str, Any] = {
    "severity":     Event.severity,
    "anomaly_score": Event.anomaly_score,
}


def _build_event_filter_clauses(filters: list[EventHuntFilter]) -> list[Any]:
    clauses: list[Any] = []
    for f in filters:
        if not f.value.strip():
            continue
        col = _EVENT_TEXT_FIELDS.get(f.field) or _EVENT_NUMERIC_FIELDS.get(f.field)
        if col is None:
            continue
        clause = _apply_event_operator(col, f.field, f.value, f.operator)
        if clause is not None:
            clauses.append(clause)
    return clauses


def _apply_event_operator(col: Any, field: str, value: str, operator: str) -> Any:
    is_numeric = field in _EVENT_NUMERIC_FIELDS
    try:
        if operator == "eq":
            return col == (int(value) if is_numeric else value)
        elif operator == "contains" and not is_numeric:
            return col.ilike(f"%{value}%")
        elif operator == "startswith" and not is_numeric:
            return col.ilike(f"{value}%")
        elif operator == "endswith" and not is_numeric:
            return col.ilike(f"%{value}")
        elif operator == "gt":
            return col > (int(value) if is_numeric else value)
        elif operator == "lt":
            return col < (int(value) if is_numeric else value)
        elif operator == "gte":
            return col >= (int(value) if is_numeric else value)
        elif operator == "lte":
            return col <= (int(value) if is_numeric else value)
    except (ValueError, TypeError):
        pass
    return None


def _build_event_match_reasons(row: Event, query: EventHuntQuery) -> list[str]:
    reasons: list[str] = []
    for f in query.filters:
        if not f.value.strip():
            continue
        val = getattr(row, f.field, None)
        if val is not None:
            reasons.append(f"{f.field} {f.operator} '{f.value}'")
    for flag in query.ueba_flags:
        if flag in (row.ueba_flags or []):
            reasons.append(f"ueba_flag={flag}")
    for tag in query.tags:
        if tag in (row.tags or []):
            reasons.append(f"tag={tag}")
    if query.is_anomaly and row.is_anomaly:
        reasons.append(f"anomaly_score={row.anomaly_score:.2f}")
    if query.is_threat_ip and row.is_threat_ip:
        reasons.append("threat_ip=true")
    return reasons


class EventHuntEngine:
    """
    True threat hunting against raw normalized events.

    Queries the `events` table which has indexed denormalized fields
    (host_name, username, process_name, source_ip, dest_ip, category, severity)
    enabling fast, precise hunts across the event log without JSONB full-scans.
    """

    @staticmethod
    async def run_query(
        db: AsyncSession,
        tenant_id: UUID,
        query: EventHuntQuery,
    ) -> EventHuntResult:
        conditions: list[Any] = [Event.tenant_id == tenant_id]

        # ── Time range ─────────────────────────────────────────────────────────
        if query.from_ts:
            conditions.append(Event.event_timestamp >= query.from_ts)
        if query.to_ts:
            conditions.append(Event.event_timestamp <= query.to_ts)

        # ── Quick indexed filters ──────────────────────────────────────────────
        if query.category:
            conditions.append(Event.category.in_(query.category))
        if query.min_severity is not None:
            conditions.append(Event.severity >= query.min_severity)
        if query.is_anomaly is not None:
            conditions.append(Event.is_anomaly == query.is_anomaly)
        if query.is_threat_ip is not None:
            conditions.append(Event.is_threat_ip == query.is_threat_ip)

        # ── JSONB containment (GIN-indexed after migration 024) ────────────────
        for flag in query.ueba_flags:
            conditions.append(
                Event.ueba_flags.op("@>")(cast([flag], PgJSONB))
            )
        for tag in query.tags:
            conditions.append(
                Event.tags.op("@>")(cast([tag], PgJSONB))
            )

        # ── Field-level text / numeric filters ─────────────────────────────────
        filter_clauses = _build_event_filter_clauses(query.filters)
        if filter_clauses:
            if query.logic == "or":
                conditions.append(or_(*filter_clauses))
            else:
                conditions.extend(filter_clauses)

        # ── Cursor pagination ──────────────────────────────────────────────────
        if query.cursor:
            try:
                ts_str, id_str = _decode_cursor(query.cursor)
                ts = datetime.fromisoformat(ts_str)
                if query.sort == "desc":
                    conditions.append(
                        and_(Event.event_timestamp <= ts, Event.id < UUID(id_str))
                    )
                else:
                    conditions.append(
                        and_(Event.event_timestamp >= ts, Event.id > UUID(id_str))
                    )
            except Exception:
                pass

        limit = min(query.limit, 200)
        order = (
            Event.event_timestamp.desc()
            if query.sort == "desc"
            else Event.event_timestamp.asc()
        )

        stmt = (
            select(Event)
            .where(and_(*conditions))
            .order_by(order, Event.id)
            .limit(limit + 1)
        )
        result = await db.execute(stmt)
        rows = list(result.scalars().all())

        has_more = len(rows) > limit
        next_cursor: str | None = None
        if has_more:
            last = rows[limit - 1]
            next_cursor = _encode_cursor(
                last.event_timestamp.isoformat(), str(last.id)
            )
            rows = rows[:limit]

        # ── Page-level summary stats ───────────────────────────────────────────
        unique_hosts    = len({r.host_name    for r in rows if r.host_name})
        unique_users    = len({r.username     for r in rows if r.username})
        unique_ips      = len({r.source_ip    for r in rows if r.source_ip})
        total_anomalies = sum(1 for r in rows if r.is_anomaly)
        total_threat_ips = sum(1 for r in rows if r.is_threat_ip)

        entries = [
            EventHuntResultEntry(
                event_id=str(r.id),
                timestamp=r.event_timestamp.isoformat(),
                host_name=r.host_name,
                username=r.username,
                source_ip=r.source_ip,
                dest_ip=r.dest_ip,
                process_name=r.process_name,
                category=(
                    r.category.value
                    if hasattr(r.category, "value")
                    else str(r.category)
                ),
                severity=r.severity,
                is_anomaly=r.is_anomaly,
                is_threat_ip=r.is_threat_ip,
                anomaly_score=float(r.anomaly_score or 0),
                ueba_flags=list(r.ueba_flags or []),
                tags=list(r.tags or []),
                match_reasons=_build_event_match_reasons(r, query),
                correlation_id=r.correlation_id,
                geo_country=r.geo_country,
            )
            for r in rows
        ]

        return EventHuntResult(
            entries=entries,
            total=len(entries),
            next_cursor=next_cursor,
            has_more=has_more,
            summary=EventHuntSummary(
                unique_hosts=unique_hosts,
                unique_users=unique_users,
                unique_ips=unique_ips,
                total_anomalies=total_anomalies,
                total_threat_ips=total_threat_ips,
            ),
        )

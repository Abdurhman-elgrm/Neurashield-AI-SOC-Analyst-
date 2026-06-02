from __future__ import annotations

"""
Threat hunting engine — query investigations by structured filters.

Supports:
  - Field-level filters with AND/OR logic
  - Score ranges, severity, time ranges
  - MITRE tactic filtering (via behaviors_json JSONB)
  - Matched-rule filtering
  - Saved hunt templates
  - Cursor-based pagination

All DB queries use parameterized SQLAlchemy ORM expressions.
No raw SQL string interpolation.
"""

import base64
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.models.analyst import SavedHunt
from app.models.investigation import Investigation
from app.analyst.schemas import (
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

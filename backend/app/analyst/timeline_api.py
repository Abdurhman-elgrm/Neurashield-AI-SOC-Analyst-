from __future__ import annotations

"""
Timeline API service — paginated, filterable timeline for an investigation.

Data source: `investigations.timeline_json` (populated by the worker).
Falls back to an empty timeline if the JSON is not yet available.

Filtering:
  - from_ts / to_ts    — epoch float range
  - severity_min       — minimum severity (1-10)
  - entity_filter      — entity key substring match
  - category           — exact category match
  - sort               — "asc" | "desc" by timestamp

Pagination: cursor-based (base64 encoded "timestamp|index").
"""

import base64
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyst.schemas import TimelineEntryOut, TimelineFilter, TimelineResponse
from app.core.exceptions import NotFoundError
from app.models.investigation import Investigation

logger = structlog.get_logger(__name__)


class TimelineService:
    @staticmethod
    async def get_timeline(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        filters: TimelineFilter,
    ) -> TimelineResponse:
        inv = await _require_investigation(db, tenant_id, investigation_id)

        raw: dict[str, Any] = inv.timeline_json or {}
        all_entries: list[dict[str, Any]] = raw.get("entries") or []
        total_events: int = raw.get("total_events") or len(all_entries)
        first_seen: float = raw.get("first_seen") or 0.0
        last_seen: float = raw.get("last_seen") or 0.0

        # ── Apply filters ──────────────────────────────────────────────────────
        filtered = _apply_timeline_filters(all_entries, filters)

        # ── Sort ───────────────────────────────────────────────────────────────
        reverse = filters.sort == "desc"
        filtered.sort(key=lambda e: e.get("timestamp", 0.0), reverse=reverse)

        filtered_count = len(filtered)

        # ── Cursor-based pagination ────────────────────────────────────────────
        start_idx = 0
        if filters.cursor:
            try:
                start_idx = _decode_timeline_cursor(filters.cursor)
            except Exception:
                start_idx = 0

        limit = min(filters.limit, 200)
        page_slice = filtered[start_idx : start_idx + limit]

        next_cursor: str | None = None
        has_more = (start_idx + limit) < filtered_count
        if has_more:
            next_cursor = _encode_timeline_cursor(start_idx + limit)

        entries_out = [
            TimelineEntryOut(
                event_id=e.get("event_id", ""),
                timestamp=float(e.get("timestamp", 0.0)),
                hostname=e.get("hostname", ""),
                username=e.get("username"),
                process=e.get("process"),
                action=e.get("action", ""),
                outcome=e.get("outcome", ""),
                rule_match=e.get("rule_match") or [],
                severity=int(e.get("severity", 1)),
                category=e.get("category", ""),
                entity_keys=e.get("entity_keys") or [],
            )
            for e in page_slice
        ]

        return TimelineResponse(
            investigation_id=investigation_id,
            entries=entries_out,
            total_events=total_events,
            filtered_count=filtered_count,
            first_seen=first_seen,
            last_seen=last_seen,
            next_cursor=next_cursor,
            has_more=has_more,
        )


# ─── Filter logic ─────────────────────────────────────────────────────────────


def _apply_timeline_filters(
    entries: list[dict[str, Any]],
    f: TimelineFilter,
) -> list[dict[str, Any]]:
    result = entries

    if f.from_ts is not None:
        from_epoch = f.from_ts.timestamp()
        result = [e for e in result if float(e.get("timestamp", 0)) >= from_epoch]

    if f.to_ts is not None:
        to_epoch = f.to_ts.timestamp()
        result = [e for e in result if float(e.get("timestamp", 0)) <= to_epoch]

    if f.severity_min is not None:
        result = [e for e in result if int(e.get("severity", 1)) >= f.severity_min]

    if f.category:
        cat = f.category.lower()
        result = [e for e in result if e.get("category", "").lower() == cat]

    if f.entity_filter:
        ef = f.entity_filter.lower()
        result = [
            e
            for e in result
            if any(ef in str(k).lower() for k in (e.get("entity_keys") or []))
            or ef in e.get("hostname", "").lower()
        ]

    return result


# ─── Cursor helpers ───────────────────────────────────────────────────────────


def _encode_timeline_cursor(index: int) -> str:
    return base64.urlsafe_b64encode(str(index).encode()).decode()


def _decode_timeline_cursor(cursor: str) -> int:
    return int(base64.urlsafe_b64decode(cursor.encode()).decode())


# ─── Shared helper ────────────────────────────────────────────────────────────


async def _require_investigation(
    db: AsyncSession,
    tenant_id: UUID,
    investigation_id: str,
) -> Investigation:
    result = await db.execute(
        select(Investigation).where(
            Investigation.investigation_group_id == investigation_id,
            Investigation.tenant_id == tenant_id,
        )
    )
    inv = result.scalar_one_or_none()
    if inv is None:
        raise NotFoundError(f"Investigation {investigation_id} not found")
    return inv

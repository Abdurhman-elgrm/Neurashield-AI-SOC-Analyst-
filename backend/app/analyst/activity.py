from __future__ import annotations

"""
Activity audit service — append-only log of every analyst action.

Every mutation in the analyst workspace calls ActivityService.log().
Reads support cursor-based pagination.
"""

import base64
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analyst import InvestigationActivity

logger = structlog.get_logger(__name__)


# Canonical action strings used across the workspace
class AnalystAction:
    OPENED_INVESTIGATION = "investigation.opened"
    CLOSED_INVESTIGATION = "investigation.closed"
    STATUS_CHANGED = "investigation.status_changed"
    VERDICT_SET = "investigation.verdict_set"
    NOTE_ADDED = "investigation.note_added"
    NOTE_EDITED = "investigation.note_edited"
    NOTE_DELETED = "investigation.note_deleted"
    NOTE_PINNED = "investigation.note_pinned"
    ASSIGNED = "investigation.assigned"
    UNASSIGNED = "investigation.unassigned"
    ESCALATED = "investigation.escalated"
    TRANSFERRED = "investigation.transferred"
    EVIDENCE_ATTACHED = "investigation.evidence_attached"
    EVIDENCE_DETACHED = "investigation.evidence_detached"
    HUNT_RUN = "investigation.hunt_run"
    HUNT_EVENT_RUN = "investigation.hunt_event_run"
    PIVOT_QUERY = "investigation.pivot_query"
    MERGED = "investigation.merged"
    SPLIT = "investigation.split"
    REOPENED = "investigation.reopened"
    TIMELINE_VIEWED = "investigation.timeline_viewed"
    GRAPH_VIEWED = "investigation.graph_viewed"


class ActivityService:
    @staticmethod
    async def log(
        db: AsyncSession,
        *,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        action: str,
        target_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> InvestigationActivity:
        """Append one activity record. Errors are logged but never raised."""
        try:
            entry = InvestigationActivity(
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                analyst_id=analyst_id,
                action=action,
                target_id=target_id,
                action_data=metadata or {},
            )
            db.add(entry)
            await db.flush([entry])
            logger.debug(
                "analyst_activity_logged",
                action=action,
                investigation_id=investigation_id,
                tenant_id=str(tenant_id),
            )
            return entry
        except Exception as exc:
            logger.error("analyst_activity_log_failed", action=action, error=str(exc))
            raise

    @staticmethod
    async def list_activity(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        cursor: str | None = None,
        limit: int = 50,
    ) -> tuple[list[InvestigationActivity], str | None]:
        """Return activity entries newest-first with cursor pagination."""
        limit = min(limit, 200)
        conditions = [
            InvestigationActivity.tenant_id == tenant_id,
            InvestigationActivity.investigation_id == investigation_id,
        ]
        if cursor:
            try:
                ts_str, id_str = _decode_cursor(cursor)
                from datetime import datetime

                ts = datetime.fromisoformat(ts_str)
                conditions.append(
                    and_(
                        InvestigationActivity.created_at <= ts,
                        InvestigationActivity.id < UUID(id_str),
                    )
                )
            except Exception:
                pass

        result = await db.execute(
            select(InvestigationActivity)
            .where(*conditions)
            .order_by(
                InvestigationActivity.created_at.desc(),
                InvestigationActivity.id.desc(),
            )
            .limit(limit + 1)
        )
        rows = list(result.scalars().all())

        next_cursor: str | None = None
        if len(rows) > limit:
            last = rows[limit - 1]
            next_cursor = _encode_cursor(last.created_at.isoformat(), str(last.id))
            rows = rows[:limit]

        return rows, next_cursor

    @staticmethod
    async def list_tenant_activity(
        db: AsyncSession,
        tenant_id: UUID,
        cursor: str | None = None,
        limit: int = 50,
    ) -> tuple[list[InvestigationActivity], str | None]:
        """All activity for a tenant (for audit overview)."""
        limit = min(limit, 200)
        conditions = [InvestigationActivity.tenant_id == tenant_id]
        if cursor:
            try:
                ts_str, id_str = _decode_cursor(cursor)
                from datetime import datetime

                ts = datetime.fromisoformat(ts_str)
                conditions.append(
                    and_(
                        InvestigationActivity.created_at <= ts,
                        InvestigationActivity.id < UUID(id_str),
                    )
                )
            except Exception:
                pass

        result = await db.execute(
            select(InvestigationActivity)
            .where(*conditions)
            .order_by(
                InvestigationActivity.created_at.desc(),
                InvestigationActivity.id.desc(),
            )
            .limit(limit + 1)
        )
        rows = list(result.scalars().all())

        next_cursor: str | None = None
        if len(rows) > limit:
            last = rows[limit - 1]
            next_cursor = _encode_cursor(last.created_at.isoformat(), str(last.id))
            rows = rows[:limit]

        return rows, next_cursor


# ─── Cursor helpers ───────────────────────────────────────────────────────────


def _encode_cursor(ts: str, id_str: str) -> str:
    return base64.urlsafe_b64encode(f"{ts}|{id_str}".encode()).decode()


def _decode_cursor(cursor: str) -> tuple[str, str]:
    raw = base64.urlsafe_b64decode(cursor.encode()).decode()
    ts, _, id_str = raw.partition("|")
    return ts, id_str

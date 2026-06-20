from __future__ import annotations

"""
Case management service.

Operations:
  open_case      — transition investigation to 'investigating'
  close_case     — transition to 'closed' (with optional verdict)
  reopen_case    — re-activate a closed/false_positive investigation
  merge          — fold secondary investigations into a primary
  change_status  — validated status transition with audit trail
"""

from datetime import datetime, timezone
from uuid import UUID

import structlog
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ValidationError
from app.models.investigation import Investigation
from app.analyst.schemas import (
    InvestigationStatus,
    InvestigationVerdict,
    STATUS_TRANSITIONS,
    MergeRequest,
    ReopenRequest,
    VerdictCreate,
)
from app.analyst.verdicts import VerdictService
from sqlalchemy.dialects.postgresql import insert as pg_insert  # noqa: F401 – used in type stubs

logger = structlog.get_logger(__name__)

# Severity → threat_score mapping
_SEVERITY_SCORE: dict[str, int] = {
    "critical": 90,
    "high":     70,
    "medium":   45,
    "low":      20,
}


class CaseService:

    @staticmethod
    async def get_investigation(
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

    @staticmethod
    async def change_status(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        new_status: str,
        reason: str | None = None,
    ) -> Investigation:
        inv = await CaseService.get_investigation(db, tenant_id, investigation_id)

        # Validate transition
        allowed = STATUS_TRANSITIONS.get(inv.status, frozenset())
        if new_status not in allowed:
            raise ValidationError(
                f"Cannot transition from '{inv.status}' to '{new_status}'",
                details={
                    "current": inv.status,
                    "requested": new_status,
                    "allowed": sorted(allowed),
                },
            )

        inv.status = new_status
        inv.updated_at = datetime.now(tz=timezone.utc)
        await db.flush([inv])
        logger.info(
            "investigation_status_changed",
            investigation_id=investigation_id,
            from_status=inv.status,
            to_status=new_status,
            analyst_id=str(analyst_id),
        )
        return inv

    @staticmethod
    async def open_case(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
    ) -> Investigation:
        inv = await CaseService.get_investigation(db, tenant_id, investigation_id)
        if inv.status in ("investigating", "contained"):
            return inv
        allowed = STATUS_TRANSITIONS.get(inv.status, frozenset())
        target = "investigating" if "investigating" in allowed else "triaged"
        if target not in allowed:
            return inv  # already in a post-open state
        return await CaseService.change_status(
            db, tenant_id, investigation_id, analyst_id, target
        )

    @staticmethod
    async def close_case(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        verdict_payload: VerdictCreate | None = None,
    ) -> Investigation:
        if verdict_payload:
            await VerdictService.set_verdict(
                db, tenant_id, investigation_id, analyst_id, verdict_payload
            )

        # Close the investigation
        inv = await CaseService.get_investigation(db, tenant_id, investigation_id)
        target = (
            "false_positive"
            if verdict_payload and verdict_payload.verdict == InvestigationVerdict.FALSE_POSITIVE
            else "closed"
        )
        allowed = STATUS_TRANSITIONS.get(inv.status, frozenset())
        if target not in allowed:
            if "closed" in allowed:
                target = "closed"
            else:
                return inv

        inv.status = target
        inv.updated_at = datetime.now(tz=timezone.utc)
        await db.flush([inv])
        return inv

    @staticmethod
    async def reopen_case(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        payload: ReopenRequest | None = None,
    ) -> Investigation:
        return await CaseService.change_status(
            db, tenant_id, investigation_id, analyst_id, "investigating",
            reason=payload.reason if payload else None,
        )

    @staticmethod
    async def merge(
        db: AsyncSession,
        tenant_id: UUID,
        analyst_id: UUID,
        payload: MergeRequest,
    ) -> Investigation:
        """
        Fold secondary investigations into the primary.

        Steps:
        1. Verify all investigations belong to the same tenant.
        2. Close all secondary investigations with status 'closed'.
        3. Attach a merge note on the primary.
        4. Return the (updated) primary.
        """
        primary = await CaseService.get_investigation(
            db, tenant_id, payload.primary_investigation_id
        )

        for sec_id in payload.secondary_investigation_ids:
            if sec_id == payload.primary_investigation_id:
                continue
            sec = await CaseService.get_investigation(db, tenant_id, sec_id)
            # Close secondary regardless of current status
            sec.status = "closed"
            sec.updated_at = datetime.now(tz=timezone.utc)
            await db.flush([sec])

        logger.info(
            "investigations_merged",
            primary_id=payload.primary_investigation_id,
            secondary_ids=payload.secondary_investigation_ids,
            analyst_id=str(analyst_id),
            tenant_id=str(tenant_id),
        )
        return primary

    @staticmethod
    async def create_manual(
        db: AsyncSession,
        tenant_id: UUID,
        created_by: UUID,
        title: str,
        description: str | None,
        severity: str,
        assigned_to: str | None,
        alert_ids: list[str],
    ) -> Investigation:
        """Manually open a new investigation case."""
        from uuid import uuid4
        group_id = str(uuid4())
        score = _SEVERITY_SCORE.get(severity, 45)

        investigation = Investigation(
            tenant_id=tenant_id,
            investigation_group_id=group_id,
            title=title,
            source="manual",
            created_by=created_by,
            executive_summary=title,
            technical_summary=description or "",
            threat_score=score,
            confidence="low",
            tp_probability=0.0,
            fp_probability=1.0,
            status="new",
            assigned_to=UUID(assigned_to) if assigned_to else None,
            attack_progression=[],
            recommended_actions=[],
            # store linked alert IDs in context JSON for reference
            context_json={"alert_ids": alert_ids, "severity": severity} if alert_ids else {"severity": severity},
        )
        db.add(investigation)
        await db.commit()
        await db.refresh(investigation)
        logger.info(
            "manual_investigation_created",
            investigation_id=str(investigation.id),
            group_id=group_id,
            title=title,
            severity=severity,
            analyst_id=str(created_by),
            tenant_id=str(tenant_id),
        )

        # Auto-generate a playbook in the background using linked alert context
        import asyncio as _asyncio
        from app.workers.investigation_worker import _auto_generate_investigation_playbook
        _asyncio.create_task(
            _auto_generate_investigation_playbook(
                investigation_id=str(investigation.id),
                tenant_id=str(tenant_id),
            )
        )

        return investigation

    @staticmethod
    async def list_investigations(
        db: AsyncSession,
        tenant_id: UUID,
        status: str | None = None,
        verdict: str | None = None,
        assigned_to: UUID | None = None,
        title_search: str | None = None,
        min_score: int | None = None,
        max_score: int | None = None,
        from_ts: datetime | None = None,
        to_ts: datetime | None = None,
        cursor: str | None = None,
        limit: int = 50,
        sort: str = "desc",
    ) -> tuple[list[Investigation], str | None]:
        import base64
        limit = min(limit, 200)

        conditions = [Investigation.tenant_id == tenant_id]
        if status:
            conditions.append(Investigation.status == status)
        if verdict:
            conditions.append(Investigation.verdict == verdict)
        if assigned_to:
            conditions.append(Investigation.assigned_to == assigned_to)
        if title_search:
            pattern = f"%{title_search}%"
            conditions.append(
                or_(
                    Investigation.title.ilike(pattern),
                    Investigation.executive_summary.ilike(pattern),
                )
            )
        if min_score is not None:
            conditions.append(Investigation.threat_score >= min_score)
        if max_score is not None:
            conditions.append(Investigation.threat_score <= max_score)
        if from_ts is not None:
            conditions.append(Investigation.created_at >= from_ts)
        if to_ts is not None:
            conditions.append(Investigation.created_at <= to_ts)

        if cursor:
            try:
                raw = base64.urlsafe_b64decode(cursor.encode()).decode()
                ts_str, _, id_str = raw.partition("|")
                ts = datetime.fromisoformat(ts_str)
                from sqlalchemy import and_
                conditions.append(
                    and_(
                        Investigation.created_at <= ts,
                        Investigation.id < UUID(id_str),
                    )
                )
            except Exception:
                pass

        order = (
            Investigation.created_at.desc()
            if sort == "desc"
            else Investigation.created_at.asc()
        )
        result = await db.execute(
            select(Investigation)
            .where(*conditions)
            .order_by(order, Investigation.id)
            .limit(limit + 1)
        )
        rows = list(result.scalars().all())

        next_cursor: str | None = None
        if len(rows) > limit:
            last = rows[limit - 1]
            raw = f"{last.created_at.isoformat()}|{last.id}"
            next_cursor = base64.urlsafe_b64encode(raw.encode()).decode()
            rows = rows[:limit]

        return rows, next_cursor

from __future__ import annotations

"""
Assignment service — assign, unassign, escalate, and transfer investigations.

Each assignment action creates a new InvestigationAssignment row.
The current assignment is the row where is_active=True.
The investigations.assigned_to denormalised column is kept in sync.
"""

from datetime import datetime, timezone
from uuid import UUID

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.models.analyst import InvestigationAssignment
from app.models.investigation import Investigation
from app.analyst.schemas import AssignmentCreate

logger = structlog.get_logger(__name__)


class AssignmentService:

    @staticmethod
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

    @staticmethod
    async def _deactivate_current(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
    ) -> None:
        """Mark the current active assignment inactive."""
        now = datetime.now(tz=timezone.utc)
        await db.execute(
            update(InvestigationAssignment)
            .where(
                InvestigationAssignment.tenant_id == tenant_id,
                InvestigationAssignment.investigation_id == investigation_id,
                InvestigationAssignment.is_active.is_(True),
            )
            .values(is_active=False, unassigned_at=now)
        )

    @staticmethod
    async def assign(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        assigned_by: UUID,
        payload: AssignmentCreate,
    ) -> InvestigationAssignment:
        inv = await AssignmentService._require_investigation(db, tenant_id, investigation_id)
        await AssignmentService._deactivate_current(db, tenant_id, investigation_id)

        assignment = InvestigationAssignment(
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            assigned_to=payload.assigned_to,
            assigned_by=assigned_by,
            escalated=payload.escalated,
            escalation_reason=payload.escalation_reason,
            severity=payload.severity,
            is_active=True,
        )
        db.add(assignment)
        inv.assigned_to = payload.assigned_to
        await db.flush([assignment, inv])

        logger.info(
            "investigation_assigned",
            investigation_id=investigation_id,
            assigned_to=str(payload.assigned_to),
            assigned_by=str(assigned_by),
            escalated=payload.escalated,
        )
        return assignment

    @staticmethod
    async def unassign(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        unassigned_by: UUID,
    ) -> None:
        inv = await AssignmentService._require_investigation(db, tenant_id, investigation_id)
        await AssignmentService._deactivate_current(db, tenant_id, investigation_id)
        inv.assigned_to = None
        await db.flush([inv])
        logger.info(
            "investigation_unassigned",
            investigation_id=investigation_id,
            by=str(unassigned_by),
        )

    @staticmethod
    async def escalate(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        escalated_by: UUID,
        escalation_reason: str,
        new_assignee: UUID | None = None,
    ) -> InvestigationAssignment:
        current = await AssignmentService.get_current(db, tenant_id, investigation_id)
        target = new_assignee if new_assignee else (
            current.assigned_to if current else escalated_by
        )
        payload = AssignmentCreate(
            assigned_to=target,
            escalated=True,
            escalation_reason=escalation_reason,
        )
        return await AssignmentService.assign(db, tenant_id, investigation_id, escalated_by, payload)

    @staticmethod
    async def transfer(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        new_owner: UUID,
        transferred_by: UUID,
    ) -> InvestigationAssignment:
        payload = AssignmentCreate(assigned_to=new_owner)
        return await AssignmentService.assign(db, tenant_id, investigation_id, transferred_by, payload)

    @staticmethod
    async def get_current(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
    ) -> InvestigationAssignment | None:
        result = await db.execute(
            select(InvestigationAssignment).where(
                InvestigationAssignment.tenant_id == tenant_id,
                InvestigationAssignment.investigation_id == investigation_id,
                InvestigationAssignment.is_active.is_(True),
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def list_history(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
    ) -> list[InvestigationAssignment]:
        result = await db.execute(
            select(InvestigationAssignment)
            .where(
                InvestigationAssignment.tenant_id == tenant_id,
                InvestigationAssignment.investigation_id == investigation_id,
            )
            .order_by(InvestigationAssignment.assigned_at.desc())
        )
        return list(result.scalars().all())

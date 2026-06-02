from __future__ import annotations

"""
Evidence service — attach and retrieve investigation artefacts.

Evidence types:
  raw_event, correlated_group, screenshot_meta,
  file_ref, ioc_ref, note_ref
"""

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.models.analyst import InvestigationEvidence
from app.analyst.schemas import EvidenceCreate, EvidenceType

logger = structlog.get_logger(__name__)

_VALID_TYPES: frozenset[str] = frozenset(t.value for t in EvidenceType)


class EvidenceService:

    @staticmethod
    async def attach(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        payload: EvidenceCreate,
    ) -> InvestigationEvidence:
        ev = InvestigationEvidence(
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            evidence_type=payload.evidence_type.value,
            reference_id=payload.reference_id,
            title=payload.title,
            description=payload.description,
            extra_data=payload.metadata,
        )
        db.add(ev)
        await db.flush([ev])
        logger.info(
            "evidence_attached",
            evidence_id=str(ev.id),
            investigation_id=investigation_id,
            evidence_type=payload.evidence_type.value,
            tenant_id=str(tenant_id),
        )
        return ev

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        evidence_id: UUID,
    ) -> InvestigationEvidence | None:
        result = await db.execute(
            select(InvestigationEvidence).where(
                InvestigationEvidence.id == evidence_id,
                InvestigationEvidence.tenant_id == tenant_id,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def require_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        evidence_id: UUID,
    ) -> InvestigationEvidence:
        ev = await EvidenceService.get_by_id(db, tenant_id, evidence_id)
        if ev is None:
            raise NotFoundError(f"Evidence {evidence_id} not found")
        return ev

    @staticmethod
    async def list_for_investigation(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        evidence_type: str | None = None,
    ) -> list[InvestigationEvidence]:
        conditions = [
            InvestigationEvidence.tenant_id == tenant_id,
            InvestigationEvidence.investigation_id == investigation_id,
        ]
        if evidence_type and evidence_type in _VALID_TYPES:
            conditions.append(InvestigationEvidence.evidence_type == evidence_type)

        result = await db.execute(
            select(InvestigationEvidence)
            .where(*conditions)
            .order_by(InvestigationEvidence.created_at.desc())
        )
        return list(result.scalars().all())

    @staticmethod
    async def detach(
        db: AsyncSession,
        tenant_id: UUID,
        evidence_id: UUID,
    ) -> None:
        ev = await EvidenceService.require_by_id(db, tenant_id, evidence_id)
        await db.delete(ev)
        await db.flush()
        logger.info(
            "evidence_detached",
            evidence_id=str(evidence_id),
            tenant_id=str(tenant_id),
        )

    @staticmethod
    async def count_for_investigation(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
    ) -> int:
        result = await db.execute(
            select(func.count()).select_from(InvestigationEvidence).where(
                InvestigationEvidence.tenant_id == tenant_id,
                InvestigationEvidence.investigation_id == investigation_id,
            )
        )
        return result.scalar_one()

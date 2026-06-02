from __future__ import annotations

"""
Verdict service — analyst TP/FP/Benign verdicts on investigations.

Each verdict change creates an immutable InvestigationVerdict row.
The denormalised investigations.verdict column is kept in sync.
"""

from datetime import datetime, timezone
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ValidationError
from app.models.analyst import InvestigationVerdict
from app.models.investigation import Investigation
from app.analyst.schemas import InvestigationVerdict as VerdictEnum, VerdictCreate

logger = structlog.get_logger(__name__)

_VALID_VERDICTS: frozenset[str] = frozenset(v.value for v in VerdictEnum)


class VerdictService:

    @staticmethod
    async def set_verdict(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        payload: VerdictCreate,
    ) -> InvestigationVerdict:
        if payload.verdict.value not in _VALID_VERDICTS:
            raise ValidationError(
                f"Invalid verdict: {payload.verdict}",
                details={"allowed": list(_VALID_VERDICTS)},
            )

        # Fetch investigation to get current verdict
        inv_result = await db.execute(
            select(Investigation).where(
                Investigation.investigation_group_id == investigation_id,
                Investigation.tenant_id == tenant_id,
            )
        )
        inv = inv_result.scalar_one_or_none()
        if inv is None:
            raise NotFoundError(f"Investigation {investigation_id} not found")

        previous = inv.verdict

        verdict_row = InvestigationVerdict(
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            previous_verdict=previous,
            new_verdict=payload.verdict.value,
            reasoning=payload.reasoning,
            containment_status=payload.containment_status,
        )
        db.add(verdict_row)

        now = datetime.now(tz=timezone.utc)
        inv.verdict = payload.verdict.value
        inv.verdict_set_at = now
        inv.verdict_set_by = analyst_id

        await db.flush([verdict_row, inv])
        logger.info(
            "verdict_set",
            investigation_id=investigation_id,
            verdict=payload.verdict.value,
            previous=previous,
            analyst_id=str(analyst_id),
        )
        return verdict_row

    @staticmethod
    async def get_current_verdict(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
    ) -> InvestigationVerdict | None:
        result = await db.execute(
            select(InvestigationVerdict)
            .where(
                InvestigationVerdict.tenant_id == tenant_id,
                InvestigationVerdict.investigation_id == investigation_id,
            )
            .order_by(InvestigationVerdict.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_verdict_history(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
    ) -> list[InvestigationVerdict]:
        result = await db.execute(
            select(InvestigationVerdict)
            .where(
                InvestigationVerdict.tenant_id == tenant_id,
                InvestigationVerdict.investigation_id == investigation_id,
            )
            .order_by(InvestigationVerdict.created_at.desc())
        )
        return list(result.scalars().all())

    @staticmethod
    def is_valid_verdict(value: str) -> bool:
        return value in _VALID_VERDICTS

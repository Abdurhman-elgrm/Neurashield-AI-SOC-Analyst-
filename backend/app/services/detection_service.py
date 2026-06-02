from __future__ import annotations

from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.models.detection_rule import DetectionRule, RuleSeverity, RuleType
from app.schemas.detection import DetectionRuleCreateRequest, DetectionRuleUpdateRequest

logger = structlog.get_logger(__name__)


class DetectionService:

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        rule_id: UUID,
    ) -> DetectionRule | None:
        result = await db.execute(
            select(DetectionRule).where(
                DetectionRule.id == rule_id,
                DetectionRule.tenant_id == tenant_id,
                DetectionRule.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def require_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        rule_id: UUID,
    ) -> DetectionRule:
        rule = await DetectionService.get_by_id(db, tenant_id, rule_id)
        if rule is None:
            raise NotFoundError(f"Detection rule {rule_id} not found")
        return rule

    @staticmethod
    async def list_rules(
        db: AsyncSession,
        tenant_id: UUID,
        page: int = 1,
        limit: int = 25,
        enabled_only: bool = False,
    ) -> tuple[list[DetectionRule], int]:
        offset = (page - 1) * limit
        filters = [
            DetectionRule.tenant_id == tenant_id,
            DetectionRule.deleted_at.is_(None),
        ]
        if enabled_only:
            filters.append(DetectionRule.enabled.is_(True))

        total = (await db.execute(select(func.count()).where(*filters))).scalar_one()
        result = await db.execute(
            select(DetectionRule)
            .where(*filters)
            .order_by(DetectionRule.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(result.scalars().all()), total

    @staticmethod
    async def create_rule(
        db: AsyncSession,
        tenant_id: UUID,
        payload: DetectionRuleCreateRequest,
        created_by_id: UUID,
    ) -> DetectionRule:
        conditions = payload.conditions
        if isinstance(conditions, list):
            cond_val = conditions  # type: ignore[assignment]
        else:
            cond_val = conditions  # type: ignore[assignment]

        rule = DetectionRule(
            tenant_id=tenant_id,
            name=payload.name,
            description=payload.description,
            rule_type=RuleType(payload.rule_type),
            severity=RuleSeverity(payload.severity),
            enabled=True,
            conditions=cond_val,
            mitre_tactics=payload.mitre_tactics,
            mitre_techniques=payload.mitre_techniques,
            suppression_window_secs=payload.suppression_window_secs,
            created_by_id=created_by_id,
            updated_by_id=created_by_id,
        )
        db.add(rule)
        await db.flush()
        logger.info("detection_rule_created", rule_id=str(rule.id), tenant_id=str(tenant_id))
        return rule

    @staticmethod
    async def update_rule(
        db: AsyncSession,
        tenant_id: UUID,
        rule_id: UUID,
        payload: DetectionRuleUpdateRequest,
        updated_by_id: UUID,
    ) -> DetectionRule:
        rule = await DetectionService.require_by_id(db, tenant_id, rule_id)

        if payload.name is not None:
            rule.name = payload.name
        if payload.description is not None:
            rule.description = payload.description
        if payload.severity is not None:
            rule.severity = RuleSeverity(payload.severity)
        if payload.enabled is not None:
            rule.enabled = payload.enabled
        if payload.conditions is not None:
            rule.conditions = payload.conditions  # type: ignore[assignment]
        if payload.mitre_tactics is not None:
            rule.mitre_tactics = payload.mitre_tactics  # type: ignore[assignment]
        if payload.mitre_techniques is not None:
            rule.mitre_techniques = payload.mitre_techniques  # type: ignore[assignment]
        if payload.suppression_window_secs is not None:
            rule.suppression_window_secs = payload.suppression_window_secs

        rule.updated_by_id = updated_by_id
        await db.flush()
        logger.info("detection_rule_updated", rule_id=str(rule_id), tenant_id=str(tenant_id))
        return rule

    @staticmethod
    async def delete_rule(
        db: AsyncSession,
        tenant_id: UUID,
        rule_id: UUID,
    ) -> None:
        rule = await DetectionService.require_by_id(db, tenant_id, rule_id)
        rule.soft_delete()
        await db.flush()
        logger.info("detection_rule_deleted", rule_id=str(rule_id), tenant_id=str(tenant_id))

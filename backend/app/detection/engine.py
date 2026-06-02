from __future__ import annotations

from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import TenantRedisClient
from app.detection.evaluator import RuleEvaluator
from app.models.alert import Alert
from app.models.detection_rule import DetectionRule
from app.normalization.models import NormalizedEvent
from app.pipeline.publisher import StreamPublisher

logger = structlog.get_logger(__name__)


class DetectionEngine:
    """
    Loads enabled rules for a tenant and evaluates them against a normalized event.
    Publishes any resulting alerts to the alert_events stream.
    """

    def __init__(
        self,
        db: AsyncSession,
        client: TenantRedisClient,
        tenant_id: UUID,
    ) -> None:
        self._db = db
        self._client = client
        self._tenant_id = tenant_id
        self._publisher = StreamPublisher(client)
        self._evaluator = RuleEvaluator(db, client)

    async def run(
        self,
        event: NormalizedEvent,
        event_db_id: UUID | None = None,
        stream_id: str | None = None,
    ) -> list[Alert]:
        rules = await self._load_enabled_rules()
        if not rules:
            return []

        alerts: list[Alert] = []
        for rule in rules:
            try:
                alert = await self._evaluator.evaluate(
                    rule, event, event_id=event_db_id, stream_id=stream_id
                )
                if alert:
                    alerts.append(alert)
            except Exception as exc:
                logger.error(
                    "rule_evaluation_error",
                    rule_id=str(rule.id),
                    error=str(exc),
                    exc_info=True,
                )

        return alerts

    async def _load_enabled_rules(self) -> list[DetectionRule]:
        result = await self._db.execute(
            select(DetectionRule).where(
                DetectionRule.tenant_id == self._tenant_id,
                DetectionRule.enabled.is_(True),
                DetectionRule.deleted_at.is_(None),
            )
        )
        return list(result.scalars().all())

    async def publish_alerts(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            try:
                await self._publisher.publish_alert({
                    "alert_id": str(alert.id),
                    "tenant_id": str(alert.tenant_id),
                    "rule_id": str(alert.rule_id) if alert.rule_id else None,
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "status": alert.status.value,
                    "source_host": alert.source_host,
                    "evidence": alert.evidence,
                    "mitre_tactics": alert.mitre_tactics,
                    "mitre_techniques": alert.mitre_techniques,
                    "created_at": alert.created_at.isoformat() if alert.created_at else None,
                })
            except Exception as exc:
                logger.error(
                    "alert_publish_failed",
                    alert_id=str(alert.id),
                    error=str(exc),
                )

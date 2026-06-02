from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import TenantRedisClient
from app.detection.grouping import build_alert_evidence, build_alert_title
from app.detection.patterns import evaluate_conditions
from app.detection.suppression import SuppressionStore, build_suppression_key
from app.detection.threshold import ThresholdEvaluator
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.detection_rule import DetectionRule, RuleType
from app.normalization.models import NormalizedEvent

logger = structlog.get_logger(__name__)


class RuleEvaluator:
    """
    Evaluates a single detection rule against a normalized event.
    Creates an Alert record if the rule fires and is not suppressed.
    """

    def __init__(self, db: AsyncSession, client: TenantRedisClient) -> None:
        self._db = db
        self._client = client
        self._suppression = SuppressionStore(client)
        self._threshold = ThresholdEvaluator(client)

    async def evaluate(
        self,
        rule: DetectionRule,
        event: NormalizedEvent,
        event_id: UUID | None = None,
        stream_id: str | None = None,
    ) -> Alert | None:
        """
        Returns an Alert if the rule fires, or None if it doesn't match or is suppressed.
        """
        fired: bool
        count: int | None = None

        if rule.rule_type == RuleType.PATTERN:
            conditions: list[dict[str, Any]] = rule.conditions if isinstance(rule.conditions, list) else []
            fired = evaluate_conditions(conditions, event)
        elif rule.rule_type == RuleType.THRESHOLD:
            fired, count = await self._threshold.evaluate(
                str(rule.id), rule.conditions, event
            )
        else:
            return None

        if not fired:
            return None

        # Suppression check
        suppress_key = build_suppression_key(
            str(rule.id),
            event.hostname,
            extra=str(count) if count is not None else "",
        )
        if await self._suppression.check_and_suppress(suppress_key, rule.suppression_window_secs):
            logger.debug("rule_suppressed", rule_id=str(rule.id), hostname=event.hostname)
            return None

        # Map rule severity to alert severity
        try:
            severity = AlertSeverity(rule.severity.value)
        except ValueError:
            severity = AlertSeverity.MEDIUM

        alert = Alert(
            tenant_id=rule.tenant_id,
            rule_id=rule.id,
            triggering_event_id=event_id,
            status=AlertStatus.OPEN,
            severity=severity,
            title=build_alert_title(rule.name, event),
            description=rule.description,
            source_host=event.hostname or None,
            evidence=build_alert_evidence(event, stream_id=stream_id, count=count),
            mitre_tactics=rule.mitre_tactics,
            mitre_techniques=rule.mitre_techniques,
            suppression_key=suppress_key,
        )

        self._db.add(alert)
        await self._db.flush()

        logger.info(
            "alert_created",
            alert_id=str(alert.id),
            rule_id=str(rule.id),
            severity=severity.value,
            hostname=event.hostname,
        )

        return alert

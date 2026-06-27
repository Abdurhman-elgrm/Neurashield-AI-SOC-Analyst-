from __future__ import annotations

import fnmatch
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import TenantRedisClient
from app.detection.evaluator import RuleEvaluator
from app.models.alert import Alert
from app.models.detection_rule import DetectionRule
from app.models.suppression_rule import SuppressionRule
from app.normalization.models import NormalizedEvent
from app.pipeline.publisher import StreamPublisher

logger = structlog.get_logger(__name__)

_MAX_ALERTS_PER_EVENT = 10
_RULE_RATE_LIMIT_DEFAULT = 20
_RULE_RATE_LIMIT_WINDOW = 60  # seconds

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


class DetectionEngine:
    """
    Loads enabled rules for a tenant and evaluates them against a normalized event.
    Publishes any resulting alerts to the alert_events stream.

    Alert deduplication:
      When multiple rules fire on the same event (e.g. "3 failed logins" and
      "5 failed logins" both fire simultaneously) only the highest-severity
      alert per unique (category, hostname, username) entity key is emitted.
      Lower-severity duplicates are suppressed within this event evaluation.
      Hard cap of _MAX_ALERTS_PER_EVENT prevents storms from runaway rules.
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

        # Load user-defined suppression rules once per event evaluation
        suppression_rules = await self._load_suppression_rules()

        raw_alerts: list[Alert] = []
        for rule in rules:
            try:
                if await self._is_rate_limited(rule):
                    continue

                alert = await self._evaluator.evaluate(
                    rule, event, event_id=event_db_id, stream_id=stream_id
                )
                if alert:
                    if suppression_rules and _is_suppressed(alert, event, suppression_rules):
                        logger.debug(
                            "alert_suppressed_by_rule",
                            rule_id=str(rule.id),
                            hostname=event.hostname,
                        )
                        # Remove alert from session since it was flushed but shouldn't be committed
                        await self._db.delete(alert)
                        continue
                    raw_alerts.append(alert)
            except Exception as exc:
                logger.error(
                    "rule_evaluation_error",
                    rule_id=str(rule.id),
                    error=str(exc),
                    exc_info=True,
                )

        alerts = _deduplicate_alerts(raw_alerts)
        if len(alerts) > _MAX_ALERTS_PER_EVENT:
            logger.warning(
                "alert_storm_capped",
                event_id=str(event_db_id),
                raw_count=len(raw_alerts),
                cap=_MAX_ALERTS_PER_EVENT,
            )
            alerts = alerts[:_MAX_ALERTS_PER_EVENT]

        return alerts

    async def _is_rate_limited(self, rule: DetectionRule) -> bool:
        conditions = rule.conditions if isinstance(rule.conditions, dict) else {}
        max_per_min = int(conditions.get("max_alerts_per_minute", _RULE_RATE_LIMIT_DEFAULT))

        full_key = self._client._key(f"rl:{rule.id}")
        pipe = self._client.pipeline()
        pipe.incr(full_key)
        pipe.expire(full_key, _RULE_RATE_LIMIT_WINDOW)
        results = await pipe.execute()
        count = int(results[0])

        if count > max_per_min:
            logger.warning(
                "rule_rate_limited",
                rule_id=str(rule.id),
                count=count,
                limit=max_per_min,
            )
            return True
        return False

    async def _load_enabled_rules(self) -> list[DetectionRule]:
        result = await self._db.execute(
            select(DetectionRule).where(
                DetectionRule.tenant_id == self._tenant_id,
                DetectionRule.enabled.is_(True),
                DetectionRule.deleted_at.is_(None),
            )
        )
        return list(result.scalars().all())

    async def _load_suppression_rules(self) -> list[SuppressionRule]:
        now = datetime.now(tz=UTC)
        result = await self._db.execute(
            select(SuppressionRule).where(
                SuppressionRule.tenant_id == self._tenant_id,
                SuppressionRule.enabled.is_(True),
                SuppressionRule.deleted_at.is_(None),
                # NULL expires_at means the rule never expires (permanent suppression).
                # A bare `> now` would exclude NULL rows, silently dropping all permanent rules.
                or_(
                    SuppressionRule.expires_at.is_(None),
                    SuppressionRule.expires_at > now,
                ),
            )
        )
        return list(result.scalars().all())

    async def publish_alerts(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            try:
                await self._publisher.publish_alert(
                    {
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
                    }
                )
            except Exception as exc:
                logger.error(
                    "alert_publish_failed",
                    alert_id=str(alert.id),
                    error=str(exc),
                )


# ─── Suppression check ────────────────────────────────────────────────────────


def _is_suppressed(
    alert: Alert,
    event: NormalizedEvent,
    rules: list[SuppressionRule],
) -> bool:
    """Return True if the alert matches any active suppression rule."""
    for rule in rules:
        if _matches_suppression(alert, event, rule):
            logger.info(
                "alert_suppressed",
                alert_rule_id=str(alert.rule_id),
                suppression_rule=rule.name,
                hostname=alert.source_host,
            )
            return True
    return False


def _matches_suppression(
    alert: Alert,
    event: NormalizedEvent,
    rule: SuppressionRule,
) -> bool:
    """Return True if ALL non-null criteria of the suppression rule match."""
    # Detection rule filter
    if rule.detection_rule_id is not None:
        if str(rule.detection_rule_id) != str(alert.rule_id):
            return False

    # Hostname wildcard match (fnmatch: * matches any sequence, ? matches one char)
    if rule.hostname_pattern is not None:
        hostname = alert.source_host or ""
        if not fnmatch.fnmatch(hostname.lower(), rule.hostname_pattern.lower()):
            return False

    # Category filter
    if rule.category is not None:
        if event.category != rule.category:
            return False

    # Severity threshold (suppress only if alert severity >= min_severity)
    if rule.min_severity is not None:
        alert_rank = _SEVERITY_RANK.get(alert.severity.value, 0)
        min_rank = _SEVERITY_RANK.get(rule.min_severity, 0)
        if alert_rank < min_rank:
            return False

    return True


# ─── Deduplication helpers ────────────────────────────────────────────────────


def _alert_entity_key(alert: Alert) -> str:
    host = alert.source_host or ""
    tactic = (alert.mitre_tactics or [None])[0] or ""
    return f"{host}:{tactic}"


def _deduplicate_alerts(alerts: list[Alert]) -> list[Alert]:
    if len(alerts) <= 1:
        return alerts

    best: dict[str, Alert] = {}
    for alert in alerts:
        key = _alert_entity_key(alert)
        existing = best.get(key)
        if existing is None:
            best[key] = alert
        else:
            curr_rank = _SEVERITY_RANK.get(alert.severity.value, 0)
            prev_rank = _SEVERITY_RANK.get(existing.severity.value, 0)
            if curr_rank > prev_rank:
                best[key] = alert

    deduplicated = list(best.values())

    if len(deduplicated) < len(alerts):
        logger.info(
            "alerts_deduplicated",
            original_count=len(alerts),
            deduplicated_count=len(deduplicated),
        )

    return deduplicated

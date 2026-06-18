from __future__ import annotations

from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import TenantRedisClient
from app.detection.evaluator import RuleEvaluator
from app.models.alert import Alert, AlertSeverity
from app.models.detection_rule import DetectionRule, RuleType
from app.normalization.models import NormalizedEvent
from app.pipeline.publisher import StreamPublisher

logger = structlog.get_logger(__name__)

# Maximum alerts emitted per single event.  Protects against rule storms where
# dozens of overlapping threshold rules all fire on the same event.
_MAX_ALERTS_PER_EVENT = 10

# Per-rule rate limiting: max alerts a single rule can emit per minute.
# Prevents a misconfigured or overly-sensitive rule from flooding the alert queue.
# Individual rules may override this via conditions["max_alerts_per_minute"].
_RULE_RATE_LIMIT_DEFAULT = 20
_RULE_RATE_LIMIT_WINDOW  = 60  # seconds


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

        raw_alerts: list[Alert] = []
        for rule in rules:
            try:
                # Per-rule rate limit: skip evaluation entirely if the rule has
                # already fired too many times this minute.
                if await self._is_rate_limited(rule):
                    continue

                alert = await self._evaluator.evaluate(
                    rule, event, event_id=event_db_id, stream_id=stream_id
                )
                if alert:
                    raw_alerts.append(alert)
            except Exception as exc:
                logger.error(
                    "rule_evaluation_error",
                    rule_id=str(rule.id),
                    error=str(exc),
                    exc_info=True,
                )

        # ── Deduplication ─────────────────────────────────────────────────────
        # Group alerts by entity key (host + category).  Keep only the
        # highest-severity alert per group.  Apply hard cap last.
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
        """
        Returns True if this rule has exceeded its per-minute alert cap.
        Uses a simple INCR/EXPIRE counter — acceptable race condition (soft limit).
        """
        conditions = rule.conditions if isinstance(rule.conditions, dict) else {}
        max_per_min = int(conditions.get("max_alerts_per_minute", _RULE_RATE_LIMIT_DEFAULT))

        rl_key = self._client._key(f"rl:{rule.id}")
        count = await self._client.incr(rl_key)
        if count == 1:
            await self._client.expire(rl_key, _RULE_RATE_LIMIT_WINDOW)

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


# ─── Deduplication helpers ────────────────────────────────────────────────────

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
}


def _alert_entity_key(alert: Alert) -> str:
    """
    Stable key that identifies the security entity this alert is about.
    Two alerts with the same entity key are considered duplicates when
    they fire on the same event; only the higher-severity one is kept.
    """
    host = alert.source_host or ""
    # Use the first MITRE tactic as the alert "category" for dedup grouping.
    # Falls back to empty string so tactical alerts group with each other.
    tactic = (alert.mitre_tactics or [None])[0] or ""
    return f"{host}:{tactic}"


def _deduplicate_alerts(alerts: list[Alert]) -> list[Alert]:
    """
    Within a single event evaluation, suppress lower-severity alerts that
    describe the same entity as a higher-severity alert.

    Example: "3 failed logins → medium" and "5 failed logins → high" both fire
    on the same event for the same host.  Only the high-severity one is emitted.
    """
    if len(alerts) <= 1:
        return alerts

    best: dict[str, Alert] = {}
    for alert in alerts:
        key = _alert_entity_key(alert)
        existing = best.get(key)
        if existing is None:
            best[key] = alert
        else:
            # Keep the higher-severity alert.
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

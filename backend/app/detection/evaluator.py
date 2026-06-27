from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.metrics import ALERTS_CREATED_TOTAL
from app.core.redis import TenantRedisClient
from app.core.utils import create_task_safe
from app.detection.grouping import build_alert_evidence, build_alert_title
from app.detection.patterns import evaluate_conditions
from app.detection.suppression import SuppressionStore, build_suppression_key
from app.detection.threshold import ThresholdEvaluator
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.detection_rule import DetectionRule, RuleSeverity, RuleType
from app.normalization.models import NormalizedEvent

logger = structlog.get_logger(__name__)

_SEVERITY_RANK_AUTO = {"critical": 4, "high": 3, "medium": 2, "low": 1}


async def _maybe_auto_playbook(
    tenant_id: UUID,
    alert_id: UUID,
    alert_title: str,
    severity: str,
    source_host: str | None,
    mitre_techniques: list[str],
    mitre_tactics: list[str],
    evidence: dict,
) -> None:
    """Background task: generate a playbook automatically if tenant config allows it.

    Receives snapshot values (not a session-bound ORM object) so it is safe to
    run in a fire-and-forget task after the caller's session has been closed.
    """
    try:
        from sqlalchemy import select

        from app.core.database import database_manager
        from app.models.playbook import PlaybookAutoConfig
        from app.models.tenant import Tenant
        from app.services.playbook_service import PlaybookGeneratorService

        async with database_manager.session() as db:
            cfg_result = await db.execute(
                select(PlaybookAutoConfig).where(PlaybookAutoConfig.tenant_id == tenant_id)
            )
            cfg = cfg_result.scalar_one_or_none()
            if cfg is None or not cfg.enabled:
                return

            alert_rank = _SEVERITY_RANK_AUTO.get(severity, 0)
            min_rank = _SEVERITY_RANK_AUTO.get(cfg.min_severity, 4)
            if alert_rank < min_rank:
                return

            tenant_result = await db.execute(select(Tenant.name).where(Tenant.id == tenant_id))
            company_name = tenant_result.scalar_one_or_none() or "Your Organization"

            playbook = await PlaybookGeneratorService.generate(
                db=db,
                tenant_id=tenant_id,
                alert_id=alert_id,
                alert_title=alert_title,
                severity=severity,
                source_host=source_host,
                mitre_techniques=mitre_techniques,
                mitre_tactics=mitre_tactics,
                evidence=evidence,
                company_name=company_name,
                created_by_id=None,
            )
            await db.commit()
            logger.info(
                "auto_playbook_generated",
                playbook_id=str(playbook.id),
                alert_id=str(alert_id),
                severity=severity,
            )
    except Exception as exc:
        logger.warning("auto_playbook_failed", alert_id=str(alert_id), error=str(exc)[:200])


# ─── Context-aware severity escalation ────────────────────────────────────────

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}
_RANK_TO_SEVERITY: dict[int, AlertSeverity] = {
    4: AlertSeverity.CRITICAL,
    3: AlertSeverity.HIGH,
    2: AlertSeverity.MEDIUM,
    1: AlertSeverity.LOW,
    0: AlertSeverity.LOW,
}

# UEBA flags that represent high-confidence attack chain activity.
# Any alert triggered alongside these flags is locked to at least HIGH.
_CRITICAL_CHAIN_FLAGS = frozenset(
    {
        "impossible_travel",
        "brute_force_success",
        "lateral_movement_xdomain",
    }
)


def _compute_alert_severity(
    rule_severity: RuleSeverity,
    event: NormalizedEvent,
) -> tuple[AlertSeverity, list[str]]:
    """
    Compute final alert severity using the rule's base severity enriched with
    threat intelligence and UEBA behavioral context.

    Returns (final_severity, escalation_reasons).  Reasons are stored in the
    alert evidence so analysts know exactly why a severity was elevated.

    Escalation tiers:
      +1  Suspicious IP (AbuseIPDB ≥ 25 or is_threat_ip flag from any source)
      +2  Confirmed malicious IP (AbuseIPDB ≥ 75)
      +1  Moderate UEBA behavioral anomaly (score ≥ 0.60)
      +1  Strong UEBA behavioral anomaly (score ≥ 0.80, stacks)
      +1  Compound: threat IP AND behavioral anomaly (score ≥ 0.50)
      →3  Floor at HIGH for critical attack chain flags (impossible travel, etc.)
    All escalations cap at CRITICAL (4).
    """
    base_rank = _SEVERITY_RANK.get(rule_severity.value, 2)
    escalation_reasons: list[str] = []

    # Boost 1: Threat Intel — suspicious / malicious source IP
    if event.abuse_confidence >= 75:
        base_rank = min(base_rank + 2, 4)
        escalation_reasons.append("threat_ip_confirmed_malicious")
    elif event.is_threat_ip or event.abuse_confidence >= 25:
        base_rank = min(base_rank + 1, 4)
        escalation_reasons.append("threat_ip_suspicious")

    # Boost 2: UEBA behavioral anomaly
    if event.ueba_score >= 0.80:
        base_rank = min(base_rank + 1, 4)
        escalation_reasons.append("ueba_strong_anomaly")
    elif event.ueba_score >= 0.60:
        base_rank = min(base_rank + 1, 4)
        escalation_reasons.append("ueba_moderate_anomaly")

    # Boost 3: Compound threat — both threat intel AND behavioral anomaly
    if event.is_threat_ip and event.ueba_score >= 0.50:
        base_rank = min(base_rank + 1, 4)
        escalation_reasons.append("compound_threat_intel_and_ueba")

    # Floor: critical attack-chain flags → lock to at least HIGH
    if any(f in event.ueba_flags for f in _CRITICAL_CHAIN_FLAGS):
        if base_rank < 3:
            base_rank = 3
            escalation_reasons.append("critical_attack_chain_detected")

    return _RANK_TO_SEVERITY[base_rank], escalation_reasons


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
        window_event_ids: list[str] = []

        if rule.rule_type == RuleType.PATTERN:
            conditions: list[dict[str, Any]] = (
                rule.conditions if isinstance(rule.conditions, list) else []
            )
            fired = evaluate_conditions(conditions, event)
        elif rule.rule_type == RuleType.THRESHOLD:
            fired, count, window_event_ids = await self._threshold.evaluate(
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

        # Context-aware severity: rule base + threat intel + UEBA boosts
        severity, escalation_reasons = _compute_alert_severity(rule.severity, event)

        evidence = build_alert_evidence(
            event,
            stream_id=stream_id,
            count=count,
            window_event_ids=window_event_ids or None,
            rule_name=rule.name,
        )

        # Attach risk context so analysts can audit why severity was (or wasn't) elevated
        evidence["risk_context"] = {
            "rule_base_severity": rule.severity.value,
            "final_severity": severity.value,
            "severity_escalated": severity.value != rule.severity.value,
            "escalation_reasons": escalation_reasons,
            "ueba_score": round(event.ueba_score, 4),
            "ueba_flags": list(event.ueba_flags),
            "is_threat_ip": event.is_threat_ip,
            "abuse_confidence": event.abuse_confidence,
            "threat_intel_flags": list(event.threat_intel_flags),
        }

        alert = Alert(
            tenant_id=rule.tenant_id,
            rule_id=rule.id,
            triggering_event_id=event_id,
            status=AlertStatus.OPEN,
            severity=severity,
            title=build_alert_title(rule.name, event),
            description=rule.description,
            source_host=event.hostname or None,
            evidence=evidence,
            mitre_tactics=rule.mitre_tactics,
            mitre_techniques=rule.mitre_techniques,
            suppression_key=suppress_key,
        )

        self._db.add(alert)
        await self._db.flush()

        ALERTS_CREATED_TOTAL.labels(
            tenant_id=str(alert.tenant_id),
            severity=severity.value,
        ).inc()

        # Fire-and-forget: auto-generate playbook if tenant has it enabled.
        # Snapshot primitive values now so the task is independent of this session.
        create_task_safe(
            _maybe_auto_playbook(
                tenant_id=alert.tenant_id,
                alert_id=alert.id,
                alert_title=alert.title or "",
                severity=alert.severity.value,
                source_host=alert.source_host,
                mitre_techniques=list(alert.mitre_techniques or []),
                mitre_tactics=list(alert.mitre_tactics or []),
                evidence=dict(alert.evidence or {}),
            )
        )

        logger.info(
            "alert_created",
            alert_id=str(alert.id),
            rule_id=str(rule.id),
            rule_base_severity=rule.severity.value,
            final_severity=severity.value,
            severity_escalated=severity.value != rule.severity.value,
            escalation_reasons=escalation_reasons,
            ueba_score=round(event.ueba_score, 4),
            is_threat_ip=event.is_threat_ip,
            hostname=event.hostname,
        )

        return alert

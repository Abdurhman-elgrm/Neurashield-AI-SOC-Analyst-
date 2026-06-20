from __future__ import annotations

import asyncio
import dataclasses
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog

from app.core.database import database_manager
from app.core.redis import TenantRedisClient, redis_manager
from app.detection.engine import DetectionEngine
from app.normalization.models import NormalizedEvent, NormalizedProcess, NormalizedNetwork, NormalizedFile, NormalizedUser
from app.pipeline import stream_names
from app.pipeline.consumer import StreamConsumer
from app.realtime.broadcaster import publish_to_tenant_ws
from app.realtime.events import alert_created_msg

logger = structlog.get_logger(__name__)


class DetectionWorker:
    """
    Reads normalized events from `normalized_events` stream, runs the detection
    engine, and publishes resulting alerts to the alert_events stream and
    the WebSocket pub/sub channel.
    """

    def __init__(self, tenant_id: str, consumer_name: str) -> None:
        self._tenant_id = tenant_id
        self._consumer_name = consumer_name

    async def run(self, stop_event: asyncio.Event) -> None:
        redis = redis_manager.get_client()
        pipeline_client = TenantRedisClient(redis, self._tenant_id, stream_names.SUBSYSTEM)

        consumer = StreamConsumer(
            pipeline_client,
            stream_names.NORMALIZED_EVENTS,
            stream_names.GROUP_DETECT,
            self._consumer_name,
        )

        await consumer.run(self._handle_message, stop_event)

    async def _handle_message(self, msg_id: str, payload: dict[str, Any]) -> None:
        tenant_id_str = payload.get("tenant_id", self._tenant_id)
        event_db_id_str = payload.pop("event_db_id", None)
        stream_id = payload.pop("stream_id", None)

        event = _dict_to_normalized_event(payload)

        event_db_id: UUID | None = None
        if event_db_id_str:
            try:
                event_db_id = UUID(event_db_id_str)
            except ValueError:
                pass

        try:
            tenant_uuid = UUID(tenant_id_str)
        except ValueError:
            logger.error("invalid_tenant_id_in_detection_worker", tenant_id=tenant_id_str)
            return

        redis = redis_manager.get_client()
        detect_client = TenantRedisClient(redis, tenant_id_str, "detect")

        async with database_manager.session() as db:
            engine = DetectionEngine(db, detect_client, tenant_uuid)
            alerts = await engine.run(event, event_db_id=event_db_id, stream_id=stream_id)

            if alerts:
                await engine.publish_alerts(alerts)

                # Run AI analysis for each alert — failure must never block the pipeline
                for alert in alerts:
                    try:
                        from app.ai.analyzer import get_analyzer
                        analyzer = get_analyzer()
                        result = await analyzer.analyze(event)
                        alert.ai_metadata = {**(alert.ai_metadata or {}), "ai_analysis": result.to_dict()}
                        await db.flush()
                        logger.info(
                            "ai_analysis_complete",
                            alert_id=str(alert.id),
                            severity=result.severity_assessment,
                            technique=result.mitre_technique,
                        )
                    except Exception:
                        logger.warning("ai_analysis_failed", exc_info=True)

                await db.commit()

                # Email notifications for HIGH/CRITICAL alerts — non-blocking
                from app.models.alert import AlertSeverity
                from app.services.notification_service import notify_alert_email
                from app.services.outbound_notification_service import dispatch_alert_to_channels

                for alert in alerts:
                    if alert.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
                        # Email to opted-in tenant members
                        asyncio.create_task(notify_alert_email(
                            alert_id=str(alert.id),
                            tenant_id=tenant_uuid,
                            alert_title=alert.title or "Security Alert",
                            severity=alert.severity.value,
                            source_host=alert.source_host,
                            ai_metadata=alert.ai_metadata,
                        ))
                        # Outbound channels (Slack, Teams, webhook, PagerDuty, email lists)
                        asyncio.create_task(dispatch_alert_to_channels(
                            tenant_id=tenant_uuid,
                            alert_id=str(alert.id),
                            title=alert.title or "Security Alert",
                            severity=alert.severity.value,
                            source_host=alert.source_host,
                            mitre_techniques=alert.mitre_techniques,
                            created_at=alert.created_at,
                        ))
                        # Auto-generate IR playbook — non-blocking, failure never affects pipeline
                        asyncio.create_task(_auto_generate_playbook(
                            alert_id=alert.id,
                            tenant_id=tenant_uuid,
                            alert_title=alert.title or "Security Alert",
                            severity=alert.severity.value,
                            source_host=alert.source_host,
                            mitre_techniques=list(alert.mitre_techniques or []),
                            mitre_tactics=list(alert.mitre_tactics or []),
                            evidence=dict(alert.evidence or {}),
                        ))

                # Fan out to WebSocket clients
                ws_client = TenantRedisClient(redis, tenant_id_str, "pipeline")
                for alert in alerts:
                    msg = alert_created_msg(
                        tenant_id_str,
                        {
                            "alert_id": str(alert.id),
                            "severity": alert.severity.value,
                            "title": alert.title,
                            "source_host": alert.source_host,
                            "status": alert.status.value,
                            "created_at": alert.created_at.isoformat() if alert.created_at else None,
                        },
                    )
                    await publish_to_tenant_ws(ws_client, stream_names.ALERTS_PUBSUB_CHANNEL, msg.to_json())
            else:
                await db.commit()


async def _auto_generate_playbook(
    alert_id: UUID,
    tenant_id: UUID,
    alert_title: str,
    severity: str,
    source_host: str | None,
    mitre_techniques: list[str],
    mitre_tactics: list[str],
    evidence: dict,
) -> None:
    try:
        from app.core.database import database_manager
        from app.models.tenant import Tenant
        from app.services.playbook_service import PlaybookGeneratorService
        from sqlalchemy import select

        async with database_manager.session() as db:
            tenant_result = await db.execute(
                select(Tenant.name).where(Tenant.id == tenant_id)
            )
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
            )
            await db.commit()
            logger.info(
                "playbook_auto_generated",
                playbook_id=str(playbook.id),
                alert_id=str(alert_id),
                incident_id=playbook.incident_id,
                generated_by=playbook.generated_by,
            )
    except Exception:
        logger.warning("playbook_auto_generate_failed", alert_id=str(alert_id), exc_info=True)


def _dict_to_normalized_event(payload: dict[str, Any]) -> NormalizedEvent:
    ts_raw = payload.get("timestamp")
    try:
        if isinstance(ts_raw, str):
            ts = datetime.fromisoformat(ts_raw)
        else:
            ts = datetime.now(tz=timezone.utc)
    except Exception:
        ts = datetime.now(tz=timezone.utc)

    def _build(cls: type, d: dict[str, Any] | None) -> object | None:
        if not d or not isinstance(d, dict):
            return None
        fields = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in fields})

    return NormalizedEvent(
        event_id=str(payload.get("event_id", "")),
        timestamp=ts,
        category=str(payload.get("category", "other")),
        severity=int(payload.get("severity", 1)),
        hostname=str(payload.get("hostname", "")),
        os_type=str(payload.get("os_type", "")),
        agent_id=str(payload.get("agent_id", "")),
        tenant_id=str(payload.get("tenant_id", "")),
        process=_build(NormalizedProcess, payload.get("process")),  # type: ignore[arg-type]
        network=_build(NormalizedNetwork, payload.get("network")),  # type: ignore[arg-type]
        file=_build(NormalizedFile, payload.get("file")),  # type: ignore[arg-type]
        user=_build(NormalizedUser, payload.get("user")),  # type: ignore[arg-type]
        registry=payload.get("registry"),
        tags=payload.get("tags", []),
        raw=payload.get("raw", {}),
        # Enrichment + UEBA context forwarded from NormalizationWorker.
        # Used by the detection evaluator for context-aware severity escalation.
        is_threat_ip=bool(payload.get("is_threat_ip", False)),
        abuse_confidence=int(payload.get("abuse_confidence", 0)),
        threat_intel_flags=list(payload.get("threat_intel_flags") or []),
        ueba_score=float(payload.get("ueba_score", 0.0)),
        ueba_is_anomaly=bool(payload.get("ueba_is_anomaly", False)),
        ueba_flags=list(payload.get("ueba_flags") or []),
    )

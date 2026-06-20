from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Any
from uuid import UUID

import structlog

from app.core.database import database_manager
from app.core.redis import TenantRedisClient, redis_manager
from app.correlation.extractor import extract_entities
from app.correlation.enrichment import enrich_normalized_payload, entity_counts
from app.normalization.mapper import compute_security_severity
from app.normalization.service import NormalizationService
from app.pipeline import stream_names
from app.pipeline.consumer import StreamConsumer
from app.threat_intel.service import ThreatIntelService
from app.ueba.service import UEBAService

logger = structlog.get_logger(__name__)

# Reject events timestamped more than this far into the future (clock skew tolerance).
_MAX_FUTURE_SECS = 3600          # 1 hour
# Warn (but do NOT reject) on events older than this — old events are still
# valid for re-ingestion and historical analysis.
_WARN_PAST_DAYS = 7


class NormalizationWorker:
    """
    Reads raw events from `raw_events` stream, normalizes them,
    persists to the events table, then publishes to `normalized_events`.
    One worker instance handles one tenant's stream.
    """

    def __init__(self, tenant_id: str, consumer_name: str) -> None:
        self._tenant_id = tenant_id
        self._consumer_name = consumer_name

    async def run(self, stop_event: asyncio.Event) -> None:
        redis = redis_manager.get_client()
        pipeline_client = TenantRedisClient(redis, self._tenant_id, stream_names.SUBSYSTEM)

        consumer = StreamConsumer(
            pipeline_client,
            stream_names.RAW_EVENTS,
            stream_names.GROUP_NORMALIZE,
            self._consumer_name,
        )

        await consumer.run(self._handle_message, stop_event)

    async def _handle_message(self, msg_id: str, payload: dict[str, Any]) -> None:
        tenant_id_str = payload.get("tenant_id", self._tenant_id)

        async with database_manager.session() as db:
            try:
                normalized = NormalizationService.normalize(payload)

                # ── Timestamp validation ──────────────────────────────────────
                now = datetime.now(tz=timezone.utc)
                if normalized.timestamp:
                    future_delta = (normalized.timestamp - now).total_seconds()
                    if future_delta > _MAX_FUTURE_SECS:
                        logger.warning(
                            "event_timestamp_too_far_in_future",
                            msg_id=msg_id,
                            event_ts=normalized.timestamp.isoformat(),
                            delta_secs=future_delta,
                        )
                        # Clamp to current time — don't discard the event, but
                        # don't let a rogue agent poison UEBA/correlation windows.
                        normalized.timestamp = now

                    past_delta = (now - normalized.timestamp).total_seconds()
                    if past_delta > _WARN_PAST_DAYS * 86400:
                        logger.warning(
                            "event_timestamp_very_old",
                            msg_id=msg_id,
                            event_ts=normalized.timestamp.isoformat(),
                            age_days=past_delta / 86400,
                        )
                        # Allow old events through (re-ingestion / backfill use case)
                        # but log so ops can investigate if this is unexpected.

                # Enrich source IP with GeoIP + Threat Intel (non-blocking, cached)
                redis = redis_manager.get_client()
                enrichment = await ThreatIntelService.enrich_ip(normalized.source_ip, redis)

                # UEBA behavioral analysis (never raises)
                ueba_result = await UEBAService.analyze(
                    normalized, enrichment, redis, tenant_id_str
                )

                # ── Security severity computation ─────────────────────────────
                # Replace the naive agent-reported severity with a context-aware
                # security severity derived from category, threat intel, and UEBA.
                # Operational severity (e.g. "system: critical") ≠ security severity.
                agent_severity = normalized.severity
                normalized.severity = compute_security_severity(
                    category=normalized.category,
                    agent_severity=agent_severity,
                    is_threat_ip=enrichment.is_threat_ip,
                    abuse_confidence=enrichment.abuse_confidence,
                    ueba_score=ueba_result.anomaly_score,
                    ueba_flags=ueba_result.ueba_flags,
                )

                # ── Embed enrichment + UEBA context into the normalized event ─
                # These are forwarded through the normalized_events stream so the
                # DetectionWorker can apply context-aware alert severity without
                # repeating expensive GeoIP/ThreatIntel/UEBA lookups.
                normalized.is_threat_ip = enrichment.is_threat_ip
                normalized.abuse_confidence = enrichment.abuse_confidence
                normalized.threat_intel_flags = list(enrichment.threat_intel_flags)
                normalized.ueba_score = ueba_result.anomaly_score
                normalized.ueba_is_anomaly = ueba_result.is_anomaly
                normalized.ueba_flags = list(ueba_result.ueba_flags)

                event = await NormalizationService.persist_event(
                    db, normalized, stream_id=msg_id,
                    enrichment=enrichment, ueba_result=ueba_result,
                )

                pipeline_client = TenantRedisClient(redis, tenant_id_str, stream_names.SUBSYSTEM)

                from app.pipeline.publisher import StreamPublisher
                publisher = StreamPublisher(pipeline_client)
                norm_payload: dict[str, Any] = normalized.to_dict()
                norm_payload["event_db_id"] = str(event.id)
                norm_payload["stream_id"] = msg_id

                # Entity extraction + correlation metadata — runs synchronously,
                # no DB access required; fault-tolerant (never raises).
                extraction = extract_entities(normalized, event_db_id=str(event.id))
                enrich_normalized_payload(norm_payload, extraction)

                await publisher.publish_normalized_event(norm_payload)

                await db.commit()

            except Exception:
                # Explicit rollback ensures the DB session is clean even if the
                # context manager's __aexit__ doesn't call rollback on all
                # exception types.  Without this, a partially-written event row
                # can be left in the session and committed by a later call.
                await db.rollback()
                raise

        logger.debug(
            "event_normalized",
            msg_id=msg_id,
            tenant_id=tenant_id_str,
            category=normalized.category,
            **entity_counts(extraction),
        )

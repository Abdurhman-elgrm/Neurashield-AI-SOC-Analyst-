from __future__ import annotations

import asyncio
from typing import Any

import structlog

from app.core.database import database_manager
from app.core.redis import TenantRedisClient, redis_manager
from app.correlation.grouping import CorrelationGrouper
from app.investigation.engine import InvestigationEngine
from app.pipeline import stream_names
from app.pipeline.consumer import StreamConsumer
from app.pipeline.publisher import StreamPublisher

logger = structlog.get_logger(__name__)

_CORR_SUBSYSTEM = "corr"


class InvestigationWorker:
    """
    Reads from the correlated_events stream (GROUP_INVESTIGATE consumer group),
    fetches all event snapshots for the investigation group from Redis,
    runs the InvestigationEngine, persists to DB, and publishes results.

    One instance per tenant.
    """

    def __init__(self, tenant_id: str, consumer_name: str) -> None:
        self._tenant_id = tenant_id
        self._consumer_name = consumer_name
        self._engine: InvestigationEngine | None = None
        self._grouper: CorrelationGrouper | None = None
        self._pipeline_client: TenantRedisClient | None = None

    async def run(self, stop_event: asyncio.Event) -> None:
        redis = redis_manager.get_client()
        pipeline_client = TenantRedisClient(redis, self._tenant_id, stream_names.SUBSYSTEM)
        corr_client     = TenantRedisClient(redis, self._tenant_id, _CORR_SUBSYSTEM)

        self._engine         = InvestigationEngine(self._tenant_id)
        self._grouper        = CorrelationGrouper(client=corr_client, tenant_id=self._tenant_id)
        self._pipeline_client = pipeline_client

        consumer = StreamConsumer(
            pipeline_client,
            stream_names.CORRELATED_EVENTS,
            stream_names.GROUP_INVESTIGATE,
            self._consumer_name,
        )

        await consumer.run(self._handle_message, stop_event)

    async def _handle_message(self, msg_id: str, payload: dict[str, Any]) -> None:
        assert self._engine is not None
        assert self._grouper is not None
        assert self._pipeline_client is not None

        investigation_id = payload.get("investigation_id")
        if not investigation_id:
            logger.debug("investigation_worker_skipping_no_inv_id", msg_id=msg_id)
            return

        # Fetch all event snapshots for this investigation group.
        snapshots = await self._grouper.get_event_snapshots(investigation_id)

        if not snapshots:
            logger.debug(
                "investigation_worker_no_snapshots",
                investigation_id=investigation_id,
            )
            return

        # Fetch group metadata for correlation score / matched_rules.
        group_meta_obj = await self._grouper.get_group(investigation_id)
        group_meta: dict[str, Any] = {}
        if group_meta_obj:
            group_meta = {
                "score":         group_meta_obj.score,
                "confidence":    group_meta_obj.confidence,
                "matched_rules": group_meta_obj.matched_rules,
                "entity_keys":   group_meta_obj.entity_keys,
            }

        # Run the full investigation pipeline.
        result = await self._engine.process_group(
            investigation_id=investigation_id,
            snapshots=snapshots,
            group_meta=group_meta,
        )

        # Persist to DB.
        is_new_investigation = False
        try:
            async with database_manager.session() as db:
                # Determine if this is a brand-new investigation before upserting
                from sqlalchemy import text as _text
                _check = await db.execute(
                    _text("SELECT 1 FROM investigations WHERE id = CAST(:id AS uuid)"),
                    {"id": investigation_id},
                )
                is_new_investigation = _check.first() is None

                await self._engine.persist(result, db)
                await self._persist_full_result(result, db)
                await self._populate_triggering_alerts(investigation_id, snapshots, db)
                await db.commit()
        except Exception as exc:
            logger.error(
                "investigation_persist_failed",
                investigation_id=investigation_id,
                error=str(exc),
            )

        # Email notification for new investigations — non-blocking
        if is_new_investigation:
            try:
                from app.services.notification_service import notify_investigation_email
                asyncio.create_task(notify_investigation_email(
                    investigation_id=investigation_id,
                    tenant_id=self._tenant_id,
                    title=result.summary.executive_summary[:100] if result.summary else "New Investigation",
                    threat_score=result.score.threat_score,
                    verdict_suggestion=None,  # AI analysis runs later
                ))
            except Exception:
                logger.warning("investigation_email_notify_failed", exc_info=True)

        # Auto-generate playbook for new investigations above threshold — non-blocking
        if is_new_investigation and result.score.threat_score >= 45:
            asyncio.create_task(
                _auto_generate_investigation_playbook(
                    investigation_id=investigation_id,
                    tenant_id=self._tenant_id,
                )
            )

        # AI Analysis — only for high-confidence or high-severity investigations
        should_analyze = (
            result.score.threat_score >= 60
            or result.score.confidence == "high"
        )
        if should_analyze:
            try:
                from app.ai.investigation_analyzer import get_investigation_analyzer
                analyzer = get_investigation_analyzer()
                investigation_data = {
                    "id":             result.investigation_id,
                    "title":          (result.summary.executive_summary or "")[:200],
                    "threat_score":   result.score.threat_score,
                    "confidence":     result.score.confidence,
                    "behaviors_json": result.behaviors.model_dump(),
                    "timeline_json":  result.timeline.model_dump(),
                    "context_json":   result.context.model_dump(),
                    "graph_json":     result.graph.model_dump(),
                }
                async with database_manager.session() as ai_db:
                    analysis = await analyzer.analyze(ai_db, investigation_data)
                    await self._persist_ai_analysis(
                        result.investigation_id, analysis.to_dict(), ai_db
                    )
                    await ai_db.commit()
                logger.info(
                    "investigation_ai_analysis_complete",
                    investigation_id=result.investigation_id,
                    verdict=analysis.verdict_suggestion,
                    kill_chain=analysis.kill_chain_stage,
                    confidence=analysis.verdict_confidence,
                )
            except Exception:
                logger.warning("investigation_ai_analysis_failed", exc_info=True)
                # Never block the pipeline

        # Publish investigation result to stream.
        publisher = StreamPublisher(self._pipeline_client)
        try:
            await publisher.publish_investigation_result(result.to_dict())
        except Exception as exc:
            logger.error(
                "investigation_publish_failed",
                investigation_id=investigation_id,
                error=str(exc),
            )

        logger.info(
            "investigation_complete",
            msg_id=msg_id,
            tenant_id=self._tenant_id,
            investigation_id=investigation_id,
            threat_score=result.score.threat_score,
            confidence=result.score.confidence,
            behavior_count=result.behaviors.behavior_count,
        )

    async def _populate_triggering_alerts(
        self, investigation_id: str, snapshots: list[dict[str, Any]], db: Any
    ) -> None:
        """Write alert IDs linked to these events into investigations.triggering_alert_ids."""
        import json
        from sqlalchemy import text
        try:
            raw_event_ids = [s.get("event_id") for s in snapshots if s.get("event_id")]
            if not raw_event_ids:
                return
            # Filter to valid UUID strings only
            valid_ids: list[str] = []
            for eid in raw_event_ids:
                try:
                    from uuid import UUID as _UUID
                    _UUID(str(eid))
                    valid_ids.append(str(eid))
                except (ValueError, AttributeError):
                    pass
            if not valid_ids:
                return
            placeholders = ", ".join(f"CAST(:eid_{i} AS uuid)" for i in range(len(valid_ids)))
            params: dict[str, Any] = {f"eid_{i}": eid for i, eid in enumerate(valid_ids)}
            params["tid"] = self._tenant_id
            rows = await db.execute(
                text(
                    f"SELECT id::text FROM alerts "
                    f"WHERE triggering_event_id IN ({placeholders}) "
                    f"AND tenant_id = CAST(:tid AS uuid) "
                    f"AND deleted_at IS NULL"
                ),
                params,
            )
            alert_ids = [row[0] for row in rows.fetchall()]
            if alert_ids:
                await db.execute(
                    text(
                        "UPDATE investigations SET "
                        "triggering_alert_ids = CAST(:ids AS jsonb), updated_at = NOW() "
                        "WHERE id = CAST(:inv_id AS uuid)"
                    ),
                    {"ids": json.dumps(alert_ids), "inv_id": investigation_id},
                )
        except Exception as exc:
            logger.warning("triggering_alerts_populate_failed", error=str(exc))

    async def _persist_ai_analysis(
        self, investigation_id: str, ai_analysis: dict, db: Any
    ) -> None:
        """Write ai_analysis_json to the investigations row — best-effort."""
        import json
        from sqlalchemy import text
        try:
            await db.execute(
                text(
                    """
                    UPDATE investigations SET
                        ai_analysis_json = CAST(:ai_json AS jsonb),
                        updated_at       = NOW()
                    WHERE id        = CAST(:inv_id AS uuid)
                      AND tenant_id = CAST(:tid AS uuid)
                    """
                ),
                {
                    "inv_id":  investigation_id,
                    "tid":     self._tenant_id,
                    "ai_json": json.dumps(ai_analysis),
                },
            )
        except Exception as exc:
            logger.warning("ai_analysis_persist_failed", error=str(exc))

    async def _persist_full_result(self, result: Any, db: Any) -> None:
        """Persist timeline/graph/behaviors/context JSONB columns — best-effort."""
        import json
        from sqlalchemy import text
        try:
            await db.execute(
                text(
                    """
                    UPDATE investigations SET
                        timeline_json   = CAST(:tl  AS jsonb),
                        graph_json      = CAST(:gr  AS jsonb),
                        behaviors_json  = CAST(:bh  AS jsonb),
                        context_json    = CAST(:ctx AS jsonb),
                        updated_at      = NOW()
                    WHERE id = CAST(:inv_id AS uuid) AND tenant_id = CAST(:tid AS uuid)
                    """
                ),
                {
                    "inv_id": result.investigation_id,
                    "tid":    result.tenant_id,
                    "tl":     json.dumps(result.timeline.model_dump()),
                    "gr":     json.dumps(result.graph.model_dump()),
                    "bh":     json.dumps(result.behaviors.model_dump()),
                    "ctx":    json.dumps(result.context.model_dump()),
                },
            )
        except Exception as exc:
            logger.warning("full_result_persist_failed", error=str(exc))


# ── Module-level background task: auto-generate playbook for investigation ────

async def _auto_generate_investigation_playbook(
    investigation_id: str,
    tenant_id: str,
) -> None:
    """
    Background task: generates a playbook for a new investigation.
    Uses the first linked alert for technique/severity/host context.
    Skips silently if a playbook already exists for this investigation.
    """
    import asyncio as _asyncio
    from uuid import UUID as _UUID
    from sqlalchemy import text as _text, select as _select

    # Small delay so triggering_alert_ids commit propagates
    await _asyncio.sleep(3)

    try:
        async with database_manager.session() as db:
            # Check if a playbook already exists for this investigation
            existing = await db.execute(
                _text(
                    "SELECT 1 FROM playbooks WHERE investigation_id = CAST(:inv_id AS uuid) "
                    "AND deleted_at IS NULL LIMIT 1"
                ),
                {"inv_id": investigation_id},
            )
            if existing.first() is not None:
                logger.debug(
                    "investigation_playbook_already_exists",
                    investigation_id=investigation_id,
                )
                return

            # Load investigation to get triggering_alert_ids
            from app.models.investigation import Investigation as _Investigation
            inv_result = await db.execute(
                _select(_Investigation).where(
                    _Investigation.id == _UUID(investigation_id),
                    _Investigation.tenant_id == _UUID(tenant_id),
                )
            )
            inv = inv_result.scalar_one_or_none()
            if inv is None:
                return

            alert_ids: list[str] = inv.triggering_alert_ids or []

            # Get company name for substitution variables
            company_row = await db.execute(
                _text("SELECT name FROM tenants WHERE id = CAST(:tid AS uuid)"),
                {"tid": tenant_id},
            )
            company_row_result = company_row.first()
            company_name = company_row_result[0] if company_row_result else "Your Organization"

            # Build context from the first linked alert (highest severity preferred)
            alert_title = inv.title or inv.executive_summary or "Security Incident"
            severity = "high"
            source_host: str | None = None
            mitre_techniques: list[str] = []
            mitre_tactics: list[str] = []
            evidence: dict = {}

            if alert_ids:
                from app.models.alert import Alert as _Alert
                alert_result = await db.execute(
                    _select(_Alert).where(
                        _Alert.id.in_([_UUID(aid) for aid in alert_ids[:5]]),
                        _Alert.tenant_id == _UUID(tenant_id),
                    ).order_by(_Alert.severity.desc())
                )
                alerts_list = list(alert_result.scalars().all())
                if alerts_list:
                    primary = alerts_list[0]
                    alert_title = primary.title
                    severity = primary.severity.value if hasattr(primary.severity, "value") else str(primary.severity)
                    source_host = primary.source_host
                    mitre_techniques = list(primary.mitre_techniques or [])
                    mitre_tactics = list(primary.mitre_tactics or [])
                    evidence = dict(primary.evidence or {})

            from app.services.playbook_service import PlaybookGeneratorService
            playbook = await PlaybookGeneratorService.generate(
                db=db,
                tenant_id=_UUID(tenant_id),
                alert_id=_UUID(alert_ids[0]) if alert_ids else None,
                alert_title=alert_title,
                severity=severity,
                source_host=source_host,
                mitre_techniques=mitre_techniques,
                mitre_tactics=mitre_tactics,
                evidence=evidence,
                company_name=company_name,
                investigation_id=_UUID(investigation_id),
                created_by_id=None,  # system-generated
            )
            await db.commit()
            logger.info(
                "investigation_playbook_auto_generated",
                investigation_id=investigation_id,
                playbook_id=str(playbook.id),
                severity=severity,
                steps=len(playbook.steps or []),
            )
    except Exception:
        logger.warning(
            "investigation_playbook_auto_generate_failed",
            investigation_id=investigation_id,
            exc_info=True,
        )

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
        try:
            async with database_manager.session() as db:
                await self._engine.persist(result, db)
                await self._persist_full_result(result, db)
                await db.commit()
        except Exception as exc:
            logger.error(
                "investigation_persist_failed",
                investigation_id=investigation_id,
                error=str(exc),
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

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from app.core.redis import TenantRedisClient, redis_manager
from app.correlation.engine import CorrelationEngine
from app.correlation.grouping import CorrelationGrouper
from app.pipeline import stream_names
from app.pipeline.consumer import StreamConsumer
from app.pipeline.publisher import StreamPublisher

logger = structlog.get_logger(__name__)

_CORR_SUBSYSTEM = "corr"


class CorrelationWorker:
    """
    Reads from the normalized_events stream (GROUP_CORRELATE consumer group),
    runs the correlation engine, and publishes results to correlated_events.
    One instance per tenant.
    """

    def __init__(self, tenant_id: str, consumer_name: str) -> None:
        self._tenant_id = tenant_id
        self._consumer_name = consumer_name
        self._engine: CorrelationEngine | None = None
        self._grouper: CorrelationGrouper | None = None

    async def run(self, stop_event: asyncio.Event) -> None:
        redis = redis_manager.get_client()
        pipeline_client = TenantRedisClient(redis, self._tenant_id, stream_names.SUBSYSTEM)
        corr_client = TenantRedisClient(redis, self._tenant_id, _CORR_SUBSYSTEM)

        self._engine = CorrelationEngine(self._tenant_id, corr_client)
        self._grouper = CorrelationGrouper(client=corr_client, tenant_id=self._tenant_id)
        self._pipeline_client = pipeline_client

        consumer = StreamConsumer(
            pipeline_client,
            stream_names.NORMALIZED_EVENTS,
            stream_names.GROUP_CORRELATE,
            self._consumer_name,
            tenant_id=self._tenant_id,
        )

        await consumer.run(self._handle_message, stop_event)

    async def _handle_message(self, msg_id: str, payload: dict[str, Any]) -> None:
        assert self._engine is not None
        assert self._grouper is not None

        payload.setdefault("tenant_id", self._tenant_id)

        result = await self._engine.process_event(payload)

        if result.is_significant and result.investigation_id:
            # Store event snapshot for the investigation engine.
            event_id = payload.get("event_id") or payload.get("event_db_id") or msg_id
            snapshot: dict[str, Any] = {
                "event_id": event_id,
                "tenant_id": self._tenant_id,
                "timestamp": payload.get("timestamp"),
                "hostname": payload.get("hostname"),
                "category": payload.get("category"),
                "severity": payload.get("severity"),
                "process": payload.get("process"),
                "network": payload.get("network"),
                "user": payload.get("user"),
                "raw": payload.get("raw"),
                "correlation_id": payload.get("correlation_id"),
                "session_id": payload.get("session_id"),
                "process_tree_id": payload.get("process_tree_id"),
                "event_chain_id": payload.get("event_chain_id"),
                "related_entity_keys": payload.get("related_entity_keys"),
                "entities": payload.get("entities"),
                "matched_rules": result.matched_rules,
                "investigation_id": result.investigation_id,
            }
            await self._grouper.store_event_snapshot(
                result.investigation_id, str(event_id), snapshot
            )

            publisher = StreamPublisher(self._pipeline_client)
            out: dict[str, Any] = result.to_dict()
            out["source_stream_id"] = msg_id
            await publisher.publish_correlated_event(out)

        logger.debug(
            "correlation_handled",
            msg_id=msg_id,
            tenant_id=self._tenant_id,
            score=result.score,
            investigation_id=result.investigation_id,
        )

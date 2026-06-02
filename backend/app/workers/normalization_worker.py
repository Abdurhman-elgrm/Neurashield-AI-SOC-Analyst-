from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

import structlog

from app.core.database import database_manager
from app.core.redis import TenantRedisClient, redis_manager
from app.correlation.extractor import extract_entities
from app.correlation.enrichment import enrich_normalized_payload, entity_counts
from app.normalization.service import NormalizationService
from app.pipeline import stream_names
from app.pipeline.consumer import StreamConsumer

logger = structlog.get_logger(__name__)


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
            normalized = NormalizationService.normalize(payload)

            event = await NormalizationService.persist_event(db, normalized, stream_id=msg_id)

            redis = redis_manager.get_client()
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

        logger.debug(
            "event_normalized",
            msg_id=msg_id,
            tenant_id=tenant_id_str,
            category=normalized.category,
            **entity_counts(extraction),
        )

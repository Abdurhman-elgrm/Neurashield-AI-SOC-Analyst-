from __future__ import annotations

"""
RealtimeWorker — bridges pipeline Redis streams to the realtime WebSocket
broadcast system.

Consumes two pipeline streams per tenant using the GROUP_REALTIME consumer group:
  alert_events           → broadcasts realtime alert.created events
  investigation_results  → broadcasts realtime investigation.created events

One instance runs per tenant per backend process.
"""

import asyncio
from typing import Any

import structlog

from app.core.redis import TenantRedisClient, redis_manager
from app.pipeline import stream_names
from app.pipeline.consumer import StreamConsumer
from app.realtime import channels as ch
from app.realtime import events as ev
from app.realtime.broadcast import RealtimeBroadcaster

logger = structlog.get_logger(__name__)


class RealtimeWorker:
    """
    Reads from ALERT_EVENTS and INVESTIGATION_RESULTS streams and publishes
    the corresponding realtime events to the WebSocket broadcast layer.
    """

    def __init__(self, tenant_id: str, consumer_name: str) -> None:
        self._tenant_id = tenant_id
        self._consumer_name = consumer_name
        self._rt_client: TenantRedisClient | None = None

    async def run(self, stop_event: asyncio.Event) -> None:
        redis = redis_manager.get_client()
        pipeline_client = TenantRedisClient(redis, self._tenant_id, stream_names.SUBSYSTEM)
        self._rt_client = TenantRedisClient(redis, self._tenant_id, ch.REALTIME_SUBSYSTEM)

        alert_consumer = StreamConsumer(
            pipeline_client,
            stream_names.ALERT_EVENTS,
            ch.GROUP_REALTIME,
            self._consumer_name,
            tenant_id=self._tenant_id,
        )
        inv_consumer = StreamConsumer(
            pipeline_client,
            stream_names.INVESTIGATION_RESULTS,
            ch.GROUP_REALTIME,
            self._consumer_name,
            tenant_id=self._tenant_id,
        )

        logger.info(
            "realtime_worker_started",
            tenant_id=self._tenant_id,
            consumer=self._consumer_name,
        )

        await asyncio.gather(
            alert_consumer.run(self._handle_alert, stop_event),
            inv_consumer.run(self._handle_investigation_result, stop_event),
        )

        logger.info("realtime_worker_stopped", tenant_id=self._tenant_id)

    async def _handle_alert(self, msg_id: str, payload: dict[str, Any]) -> None:
        assert self._rt_client is not None
        tenant_id = payload.get("tenant_id", self._tenant_id)
        try:
            event = ev.realtime_alert_created(tenant_id, "system", payload)
            await RealtimeBroadcaster.broadcast_event(self._rt_client, event)
        except Exception as exc:
            logger.error(
                "realtime_alert_broadcast_failed",
                tenant_id=tenant_id,
                msg_id=msg_id,
                error=str(exc),
            )

    async def _handle_investigation_result(self, msg_id: str, payload: dict[str, Any]) -> None:
        assert self._rt_client is not None
        tenant_id = payload.get("tenant_id", self._tenant_id)
        try:
            investigation_id = payload.get("investigation_id", "")
            score = payload.get("score", {}) or {}
            threat_score = int(score.get("threat_score", 0)) if isinstance(score, dict) else 0
            confidence = str(payload.get("confidence", "unknown"))
            status = str(payload.get("status", "open"))

            event = ev.realtime_investigation_created(
                tenant_id,
                "system",
                investigation_id,
                threat_score,
                confidence,
                status,
            )
            await RealtimeBroadcaster.broadcast_event(self._rt_client, event)
        except Exception as exc:
            logger.error(
                "realtime_investigation_broadcast_failed",
                tenant_id=tenant_id,
                msg_id=msg_id,
                error=str(exc),
            )

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
                await db.commit()

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
    )

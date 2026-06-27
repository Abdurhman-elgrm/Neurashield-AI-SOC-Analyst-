from __future__ import annotations

from typing import Any

import orjson
import structlog

from app.core.logging import get_request_id
from app.core.redis import TenantRedisClient
from app.pipeline import stream_names

logger = structlog.get_logger(__name__)


def _inject_trace_id(payload: dict[str, Any]) -> dict[str, Any]:
    """Stamp the current request_id into the payload for end-to-end correlation."""
    rid = get_request_id()
    if rid and "request_id" not in payload:
        return {**payload, "request_id": rid}
    return payload


class StreamPublisher:
    """
    Publishes messages to Redis Streams on behalf of a specific tenant.
    All fields serialized as JSON strings (Redis Streams values are strings).
    """

    def __init__(self, client: TenantRedisClient) -> None:
        self._client = client

    async def publish_raw_event(self, payload: dict[str, Any]) -> str:
        """Publish an agent raw event to the raw_events stream."""
        stream_id = await self._client.xadd(
            stream_names.RAW_EVENTS,
            {"data": orjson.dumps(_inject_trace_id(payload)).decode()},
            maxlen=stream_names.RAW_STREAM_MAX_LEN,
        )
        logger.debug(
            "raw_event_published",
            stream_id=stream_id,
            agent_id=payload.get("agent_id"),
        )
        return stream_id

    async def publish_normalized_event(self, payload: dict[str, Any]) -> str:
        """Publish a normalized event to the normalized_events stream."""
        stream_id = await self._client.xadd(
            stream_names.NORMALIZED_EVENTS,
            {"data": orjson.dumps(payload).decode()},
            maxlen=stream_names.NORMALIZED_STREAM_MAX_LEN,
        )
        return stream_id

    async def publish_correlated_event(self, payload: dict[str, Any]) -> str:
        """Publish a correlation result to the correlated_events stream."""
        stream_id = await self._client.xadd(
            stream_names.CORRELATED_EVENTS,
            {"data": orjson.dumps(payload).decode()},
            maxlen=stream_names.CORRELATED_STREAM_MAX_LEN,
        )
        return stream_id

    async def publish_investigation_result(self, payload: dict[str, Any]) -> str:
        """Publish a full investigation result to the investigation_results stream."""
        stream_id = await self._client.xadd(
            stream_names.INVESTIGATION_RESULTS,
            {"data": orjson.dumps(payload, default=str).decode()},
            maxlen=stream_names.INVESTIGATION_STREAM_MAX_LEN,
        )
        logger.info(
            "investigation_result_published",
            stream_id=stream_id,
            investigation_id=payload.get("investigation_id"),
            threat_score=payload.get("score", {}).get("threat_score")
            if isinstance(payload.get("score"), dict)
            else None,
        )
        return stream_id

    async def publish_alert(self, payload: dict[str, Any]) -> str:
        """Publish an alert event to the alert_events stream."""
        stream_id = await self._client.xadd(
            stream_names.ALERT_EVENTS,
            {"data": orjson.dumps(payload).decode()},
            maxlen=stream_names.ALERT_STREAM_MAX_LEN,
        )
        logger.info(
            "alert_published",
            stream_id=stream_id,
            rule_id=payload.get("rule_id"),
            severity=payload.get("severity"),
        )
        return stream_id

    async def publish_realtime_event(self, payload: dict[str, Any]) -> str:
        """Publish a pre-formed realtime event to the realtime events stream."""
        from app.realtime import channels as ch

        stream_id = await self._client.xadd(
            ch.REALTIME_EVENTS_STREAM,
            {"data": orjson.dumps(payload, default=str).decode()},
            maxlen=stream_names.REALTIME_STREAM_MAX_LEN,
        )
        return stream_id

    async def ensure_consumer_groups(self) -> None:
        """
        Idempotent: creates all consumer groups for this tenant's streams.
        Call once per tenant during worker startup.
        """
        from app.realtime import channels as ch

        pairs = [
            (stream_names.RAW_EVENTS, stream_names.GROUP_NORMALIZE),
            (stream_names.NORMALIZED_EVENTS, stream_names.GROUP_DETECT),
            (stream_names.NORMALIZED_EVENTS, stream_names.GROUP_CORRELATE),
            (stream_names.CORRELATED_EVENTS, stream_names.GROUP_INVESTIGATE),
            (stream_names.ALERT_EVENTS, stream_names.GROUP_ALERT_FAN),
            (stream_names.ALERT_EVENTS, ch.GROUP_REALTIME),
            (stream_names.INVESTIGATION_RESULTS, ch.GROUP_REALTIME),
        ]
        for stream, group in pairs:
            created = await self._client.xgroup_create(stream, group, id="$", mkstream=True)
            if created:
                logger.info("consumer_group_created", stream=stream, group=group)

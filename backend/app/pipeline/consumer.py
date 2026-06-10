from __future__ import annotations

import asyncio
from typing import Any, AsyncGenerator, Callable, Awaitable

import orjson
import structlog

from app.core.redis import TenantRedisClient
from app.pipeline import stream_names

logger = structlog.get_logger(__name__)

# How long XREADGROUP blocks waiting for new messages (ms)
BLOCK_MS = 2000
# Batch size per poll
BATCH_SIZE = 100
# After this many ms a PEL message is reclaimed
AUTOCLAIM_IDLE_MS = 60_000


MessageHandler = Callable[[str, dict[str, Any]], Awaitable[None]]


class StreamConsumer:
    """
    Reads messages from a Redis Stream consumer group, dispatches to a handler,
    and ACKs on success.  Handles stuck messages via XAUTOCLAIM.

    Usage:
        consumer = StreamConsumer(client, stream_names.RAW_EVENTS,
                                  stream_names.GROUP_NORMALIZE, "worker-1")
        await consumer.run(handler_fn, stop_event)
    """

    def __init__(
        self,
        client: TenantRedisClient,
        stream: str,
        group: str,
        consumer_name: str,
    ) -> None:
        self._client = client
        self._stream = stream
        self._group = group
        self._consumer_name = consumer_name

    async def run(
        self,
        handler: MessageHandler,
        stop_event: asyncio.Event,
    ) -> None:
        logger.info(
            "stream_consumer_started",
            stream=self._stream,
            group=self._group,
            consumer=self._consumer_name,
        )
        while not stop_event.is_set():
            await self._reclaim_stuck(handler)
            await self._poll(handler, stop_event)

        logger.info("stream_consumer_stopped", stream=self._stream)

    async def _poll(
        self,
        handler: MessageHandler,
        stop_event: asyncio.Event,
    ) -> None:
        try:
            results = await self._client.xreadgroup(
                group=self._group,
                consumer=self._consumer_name,
                streams={self._stream: ">"},
                count=BATCH_SIZE,
                block=BLOCK_MS,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("xreadgroup_error", stream=self._stream, error=str(exc))
            await asyncio.sleep(1)
            return

        if not results:
            return

        for _stream_name, messages in results:
            for msg_id, fields in messages:
                await self._process(msg_id, fields, handler)

    async def _reclaim_stuck(self, handler: MessageHandler) -> None:
        try:
            result = await self._client.xautoclaim(
                stream=self._stream,
                group=self._group,
                consumer=self._consumer_name,
                min_idle_time=AUTOCLAIM_IDLE_MS,
                start_id="0-0",
                count=BATCH_SIZE,
            )
            # Redis 7+ returns (next_id, messages, deleted_ids); older returns (next_id, messages)
            _next_id, messages = result[0], result[1]
        except Exception as exc:
            logger.warning("xautoclaim_error", stream=self._stream, error=str(exc))
            return

        for msg_id, fields in messages:
            logger.warning(
                "reclaiming_stuck_message",
                stream=self._stream,
                msg_id=msg_id,
            )
            await self._process(msg_id, fields, handler)

    async def _process(
        self,
        msg_id: str,
        fields: dict[str, str],
        handler: MessageHandler,
    ) -> None:
        try:
            raw = fields.get("data", "{}")
            payload: dict[str, Any] = orjson.loads(raw)
            await handler(msg_id, payload)
            await self._client.xack(self._stream, self._group, msg_id)
        except Exception as exc:
            logger.error(
                "message_handler_error",
                stream=self._stream,
                msg_id=msg_id,
                error=str(exc),
                exc_info=True,
            )

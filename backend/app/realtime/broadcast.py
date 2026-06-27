from __future__ import annotations

"""
RealtimeBroadcaster — publishes events to Redis pub/sub and delivers them
to subscribed local WebSocket connections.

Architecture:
  Publisher side: broadcast_event() → Redis PUBLISH tenant:{tid}:realtime:{channel}
  Consumer side:  RealimeListener.run() → Redis SUBSCRIBE pattern → local delivery

Local delivery is filtered by SubscriptionManager so each connection only
receives events for channels it has explicitly subscribed to.

Slow-client protection: each connection gets a bounded asyncio.Queue (size
QUEUE_MAX_SIZE). If the queue is full the message is dropped for that client
and a warning is logged — the connection is not closed.

Cross-process fanout happens automatically via Redis pub/sub: every process
that has subscribed to the pattern will receive the message and deliver to its
local connections.
"""

import asyncio
from typing import Any

import structlog

from app.core.redis import TenantRedisClient
from app.realtime import channels as ch
from app.realtime.schemas import RealtimeEvent
from app.realtime.subscriptions import subscription_manager

logger = structlog.get_logger(__name__)

QUEUE_MAX_SIZE = 128  # per-connection backpressure limit


class RealtimeBroadcaster:
    """
    Publishes RealtimeEvent objects to Redis for cross-process fanout,
    AND delivers them locally to connections subscribed to the relevant channel.
    """

    @staticmethod
    async def broadcast_event(
        client: TenantRedisClient,
        event: RealtimeEvent,
    ) -> None:
        """
        Publish event to the channel's Redis pub/sub topic.
        All backend processes (including this one) receive it via their listener.
        """
        channel_suffix = ch.subscription_channel_suffix(event.channel)
        try:
            await client.publish(channel_suffix, event.to_json())
        except Exception as exc:
            logger.error(
                "broadcast_publish_failed",
                channel=event.channel,
                tenant_id=event.tenant_id,
                error=str(exc),
            )

    @staticmethod
    async def deliver_local(
        tenant_id: str,
        channel: str,
        message_json: str,
    ) -> int:
        """
        Deliver a JSON message to all local connections subscribed to channel.
        Returns the number of connections successfully delivered to.
        """
        ws_ids = subscription_manager.subscribers_for_channel(tenant_id, channel)
        if not ws_ids:
            return 0

        delivered = 0
        for ws_id in ws_ids:
            queue = _connection_queues.get(ws_id)
            if queue is None:
                continue
            try:
                queue.put_nowait(message_json)
                delivered += 1
            except asyncio.QueueFull:
                logger.warning(
                    "broadcast_queue_full_dropped",
                    ws_id=ws_id,
                    channel=channel,
                    tenant_id=tenant_id,
                )
        return delivered

    @staticmethod
    async def broadcast_to_tenant(
        client: TenantRedisClient,
        tenant_id: str,
        event: RealtimeEvent,
    ) -> None:
        """Convenience: publish and also deliver to local connections."""
        await RealtimeBroadcaster.broadcast_event(client, event)


# ─── Per-connection send queues ───────────────────────────────────────────────

# ws_id → asyncio.Queue[str]
_connection_queues: dict[str, asyncio.Queue[str]] = {}


def register_connection_queue(ws_id: str) -> asyncio.Queue[str]:
    """Create and register a bounded send queue for a new connection."""
    q: asyncio.Queue[str] = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
    _connection_queues[ws_id] = q
    return q


def deregister_connection_queue(ws_id: str) -> None:
    """Remove a connection's queue (called on disconnect)."""
    _connection_queues.pop(ws_id, None)


def get_connection_queue(ws_id: str) -> asyncio.Queue[str] | None:
    return _connection_queues.get(ws_id)


def active_queue_count() -> int:
    return len(_connection_queues)


# ─── Redis pub/sub listener ───────────────────────────────────────────────────


class RealtimeListener:
    """
    Subscribes to the tenant:*:realtime:* Redis pub/sub pattern and delivers
    incoming messages to local WebSocket connections.

    One instance runs per backend process.
    """

    def __init__(self, redis: Any) -> None:
        self._redis = redis
        self._stop_event = asyncio.Event()

    async def run(self) -> None:
        async with self._redis.pubsub() as pubsub:
            await pubsub.psubscribe(ch.PUBSUB_PATTERN)
            logger.info("realtime_listener_started", pattern=ch.PUBSUB_PATTERN)

            while not self._stop_event.is_set():
                try:
                    msg = await asyncio.wait_for(
                        pubsub.get_message(ignore_subscribe_messages=True),
                        timeout=1.0,
                    )
                except TimeoutError:
                    continue
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.error("realtime_listener_error", error=str(exc))
                    await asyncio.sleep(1)
                    continue

                if msg is None:
                    continue

                full_channel: str = msg.get("channel", "")
                data: str = msg.get("data", "")
                if not full_channel or not data:
                    continue

                tenant_id = ch.extract_tenant_from_pubsub(full_channel)
                channel = ch.extract_channel_from_pubsub(full_channel)
                if not tenant_id or not channel:
                    continue

                await RealtimeBroadcaster.deliver_local(tenant_id, channel, data)

    async def stop(self) -> None:
        self._stop_event.set()

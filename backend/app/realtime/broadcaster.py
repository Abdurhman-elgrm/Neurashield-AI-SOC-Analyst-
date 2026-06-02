from __future__ import annotations

import asyncio

import structlog
from redis.asyncio import Redis

from app.core.redis import TenantRedisClient
from app.pipeline import stream_names
from app.realtime.manager import connection_manager

logger = structlog.get_logger(__name__)


class RedisBroadcaster:
    """
    Subscribes to Redis pub/sub channels and fans out messages
    to local WebSocket connections.

    Each backend instance runs one broadcaster.  When the detection worker
    publishes to a Redis channel, ALL instances receive it and deliver
    to their local clients — enabling horizontal scaling without sticky sessions.
    """

    def __init__(self, redis: "Redis[str]") -> None:  # type: ignore[type-arg]
        self._redis = redis
        self._stop_event = asyncio.Event()

    async def run(self) -> None:
        """
        Starts the pub/sub listener.  Blocks until stop() is called.
        Subscribes to the wildcard pattern `tenant:*:ws:*`.
        """
        async with self._redis.pubsub() as pubsub:
            await pubsub.psubscribe("tenant:*:ws:*")
            logger.info("broadcaster_started", pattern="tenant:*:ws:*")

            while not self._stop_event.is_set():
                try:
                    message = await asyncio.wait_for(pubsub.get_message(ignore_subscribe_messages=True), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.error("broadcaster_error", error=str(exc))
                    await asyncio.sleep(1)
                    continue

                if message is None:
                    continue

                channel: str = message.get("channel", "")
                data: str = message.get("data", "")

                if not channel or not data:
                    continue

                # channel pattern: tenant:{tenant_id}:ws:alerts or ws:events
                parts = channel.split(":")
                if len(parts) >= 2:
                    tenant_id = parts[1]
                    await connection_manager.broadcast_to_tenant(tenant_id, data)

    async def stop(self) -> None:
        self._stop_event.set()
        logger.info("broadcaster_stopping")


async def publish_to_tenant_ws(
    client: TenantRedisClient,
    channel_suffix: str,
    message_json: str,
) -> None:
    """
    Publishes a JSON message to the tenant's WebSocket pub/sub channel.
    channel_suffix: e.g. "ws:alerts" or "ws:events"
    """
    await client.publish(channel_suffix, message_json)

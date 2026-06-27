from __future__ import annotations

"""
In-memory subscription registry — tracks which WebSocket connections are
subscribed to which channels within a tenant.

Each WebSocket connection is identified by a unique ws_id (UUID string)
assigned at connect time.

Data structures:
  _by_ws:      ws_id → set of channel names the connection wants
  _by_channel: (tenant_id, channel) → set of ws_ids subscribed

These are per-process; Redis pub/sub handles cross-process fanout.
All mutation methods are lock-protected for async safety.
"""


import asyncio
from collections import defaultdict

import structlog

from app.realtime import channels as ch

logger = structlog.get_logger(__name__)


class SubscriptionManager:
    """
    Thread/coroutine-safe in-memory subscription table.

    ws_id should be unique per connection (e.g. str(uuid4())).
    """

    def __init__(self) -> None:
        # ws_id → set of channel names
        self._by_ws: dict[str, set[str]] = defaultdict(set)
        # (tenant_id, channel) → set of ws_ids
        self._by_channel: dict[tuple[str, str], set[str]] = defaultdict(set)
        # ws_id → tenant_id (for cleanup)
        self._tenant_map: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def subscribe(
        self,
        ws_id: str,
        tenant_id: str,
        channel: str,
    ) -> bool:
        """
        Subscribe ws_id to channel within tenant_id.
        Returns True if the subscription is new, False if already subscribed.
        Only accepts known channel names; silently ignores unknown ones.
        """
        if not ch.is_valid_channel(channel):
            logger.debug("subscribe_unknown_channel", channel=channel, ws_id=ws_id)
            return False

        async with self._lock:
            self._tenant_map[ws_id] = tenant_id
            if channel in self._by_ws[ws_id]:
                return False
            self._by_ws[ws_id].add(channel)
            self._by_channel[(tenant_id, channel)].add(ws_id)

        logger.debug("ws_subscribed", ws_id=ws_id, channel=channel, tenant_id=tenant_id)
        return True

    async def unsubscribe(
        self,
        ws_id: str,
        channel: str,
    ) -> bool:
        """Remove ws_id from channel. Returns True if it was subscribed."""
        async with self._lock:
            tenant_id = self._tenant_map.get(ws_id)
            if channel not in self._by_ws[ws_id]:
                return False
            self._by_ws[ws_id].discard(channel)
            if tenant_id:
                self._by_channel[(tenant_id, channel)].discard(ws_id)

        return True

    async def subscribe_all(self, ws_id: str, tenant_id: str) -> None:
        """Subscribe ws_id to every known channel (wildcard subscription)."""
        for channel in ch.ALL_CHANNELS:
            await self.subscribe(ws_id, tenant_id, channel)

    async def cleanup(self, ws_id: str) -> set[str]:
        """
        Remove all subscriptions for ws_id on disconnect.
        Returns the set of channels it was subscribed to.
        """
        async with self._lock:
            channels = set(self._by_ws.pop(ws_id, set()))
            tenant_id = self._tenant_map.pop(ws_id, None)
            if tenant_id:
                for channel in channels:
                    self._by_channel[(tenant_id, channel)].discard(ws_id)

        if channels:
            logger.debug("ws_subscriptions_cleaned", ws_id=ws_id, count=len(channels))
        return channels

    def is_subscribed(self, ws_id: str, channel: str) -> bool:
        """Non-locking read — safe for hot-path checks."""
        return channel in self._by_ws.get(ws_id, set())

    def get_subscriptions(self, ws_id: str) -> set[str]:
        """Return copy of channels ws_id is subscribed to."""
        return set(self._by_ws.get(ws_id, set()))

    def subscribers_for_channel(self, tenant_id: str, channel: str) -> set[str]:
        """Return ws_ids subscribed to channel in tenant_id."""
        return set(self._by_channel.get((tenant_id, channel), set()))

    def connection_count(self) -> int:
        return len(self._by_ws)

    def channel_subscriber_count(self, tenant_id: str, channel: str) -> int:
        return len(self._by_channel.get((tenant_id, channel), set()))


# ─── Singleton ────────────────────────────────────────────────────────────────
subscription_manager = SubscriptionManager()

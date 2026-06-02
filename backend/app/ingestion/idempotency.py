from __future__ import annotations

import structlog

from app.core.redis import TenantRedisClient

logger = structlog.get_logger(__name__)

# Key: idempotency:event:{event_id}  Value: stream_id
# TTL: 24 hours — agents must deduplicate within this window
_TTL_SECS = 86_400
_PREFIX = "idempotency:event"


class IdempotencyStore:
    """
    Redis-backed idempotency check for agent events.
    An event_id is considered a duplicate if it was seen within the last 24 hours.
    """

    def __init__(self, client: TenantRedisClient) -> None:
        self._client = client

    async def is_duplicate(self, event_id: str) -> bool:
        return await self._client.exists(f"{_PREFIX}:{event_id}")

    async def mark_seen(self, event_id: str, stream_id: str) -> None:
        await self._client.set(
            f"{_PREFIX}:{event_id}",
            stream_id,
            ex=_TTL_SECS,
        )

    async def check_and_mark(self, event_id: str, stream_id: str) -> bool:
        """
        Returns True (is duplicate) or False (new, marked as seen).
        Uses SET NX so the check+mark is atomic.
        """
        result = await self._client.set(
            f"{_PREFIX}:{event_id}",
            stream_id,
            ex=_TTL_SECS,
            nx=True,
        )
        # SET NX returns None when key already existed
        return result is None

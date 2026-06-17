from __future__ import annotations

import hashlib

import structlog

from app.core.redis import TenantRedisClient

logger = structlog.get_logger(__name__)

_SUPPRESS_PREFIX = "suppress"


def build_suppression_key(
    rule_id: str,
    hostname: str | None,
    extra: str = "",
) -> str:
    """
    Creates a stable dedup key for an alert.

    Uses the FULL SHA-256 digest (64 hex chars) to eliminate the collision
    risk that existed when only the first 16 chars were used.
    Two alerts from the same rule + host within the suppression window
    share the same key, so only the first one fires.
    """
    raw = f"{rule_id}:{hostname or ''}:{extra}"
    digest = hashlib.sha256(raw.encode()).hexdigest()  # full 64-char digest
    return f"{_SUPPRESS_PREFIX}:{digest}"


class SuppressionStore:
    """
    Redis-backed suppression window using a sliding model.

    Behaviour:
      - First alert for a (rule, host) pair fires and sets a suppression key with TTL.
      - Subsequent alerts within the window are suppressed AND reset the TTL
        (sliding window — the silence extends from each suppressed event).
      - Once the window expires without activity the next alert fires again.

    This prevents alert storms while guaranteeing eventual re-alerting after
    a sustained suppression period.
    """

    def __init__(self, client: TenantRedisClient) -> None:
        self._client = client

    async def is_suppressed(self, key: str) -> bool:
        return await self._client.exists(key)

    async def suppress(self, key: str, window_secs: int) -> None:
        await self._client.set(key, "1", ex=window_secs)

    async def check_and_suppress(self, key: str, window_secs: int) -> bool:
        """
        Returns True (suppressed — don't fire) or False (not suppressed — fire and mark).

        Sliding window: if the key already exists (we're in a suppression window),
        reset its TTL so the quiet period extends from this attempt.
        If the key doesn't exist, set it (alert fires) and return False.
        """
        result = await self._client.set(key, "1", ex=window_secs, nx=True)
        if result is None:
            # Key already existed — we're in suppression window.
            # Slide the window forward from this event.
            await self._client.expire(key, window_secs)
            logger.debug("alert_suppressed", key=key)
            return True
        # Key was just created — alert fires.
        return False

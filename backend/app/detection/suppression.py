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
    Two alerts from the same rule + host within the suppression window
    share the same key, so only the first one fires.
    """
    raw = f"{rule_id}:{hostname or ''}:{extra}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"{_SUPPRESS_PREFIX}:{digest}"


class SuppressionStore:
    """
    Redis-backed suppression window.
    An alert is suppressed if the same (rule, host) combination was seen
    within the configured window.
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
        Atomic SET NX.
        """
        result = await self._client.set(key, "1", ex=window_secs, nx=True)
        suppressed = result is None
        if suppressed:
            logger.debug("alert_suppressed", key=key)
        return suppressed

from __future__ import annotations

"""
Temporal window management backed by Redis Sorted Sets.

Each window is a ZSET keyed by:
    tenant:{tenant_id}:corr:win:{window_key}
Where score = unix timestamp (float) and member = event_id.

Windows are pruned lazily on every `add()` call.
"""

from dataclasses import dataclass

from app.core.redis import TenantRedisClient


# ─── Window size presets (seconds) ────────────────────────────────────────────

WINDOW_SHORT = 300     # 5 min  — burst / same-host
WINDOW_MEDIUM = 900    # 15 min — session / chain
WINDOW_LONG = 3600     # 1 hr   — process-tree / user cross-host


# ─── Config ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class WindowConfig:
    window_seconds: int
    max_events: int = 1000


_DEFAULT_CONFIGS: dict[int, WindowConfig] = {
    WINDOW_SHORT:  WindowConfig(WINDOW_SHORT,  max_events=500),
    WINDOW_MEDIUM: WindowConfig(WINDOW_MEDIUM, max_events=1000),
    WINDOW_LONG:   WindowConfig(WINDOW_LONG,   max_events=2000),
}


# ─── Manager ──────────────────────────────────────────────────────────────────

class TemporalWindowManager:
    """
    Manages sliding-window event sets in Redis ZSETs.
    All keys are already tenant-prefixed by TenantRedisClient.
    """

    _SUBSYSTEM = "corr"

    def __init__(self, client: TenantRedisClient) -> None:
        self._client = client

    # Internal key builder — client already adds tenant prefix.
    def _win_key(self, window_key: str, window_seconds: int) -> str:
        return f"win:{window_seconds}:{window_key}"

    async def add(
        self,
        window_key: str,
        event_id: str,
        event_ts: float,
        window_seconds: int,
    ) -> None:
        """
        Add event_id at timestamp event_ts to the window.
        Prunes events outside [event_ts - window_seconds, now] and trims
        to max_events from the front (oldest first).
        """
        key = self._win_key(window_key, window_seconds)
        cfg = _DEFAULT_CONFIGS.get(window_seconds, WindowConfig(window_seconds))

        # Add new entry.
        await self._client.zadd(key, {event_id: event_ts})

        # Prune expired entries (score < cutoff).
        cutoff = event_ts - window_seconds
        await self._client.zremrangebyscore(key, "-inf", cutoff)

        # Trim to max_events (remove oldest if over cap).
        count = await self._client.zcount(key, "-inf", "+inf")
        if count > cfg.max_events:
            excess = count - cfg.max_events
            await self._client.zremrangebyrank(key, 0, excess - 1)

    async def count_in_window(
        self,
        window_key: str,
        event_ts: float,
        window_seconds: int,
    ) -> int:
        """Return count of events in [event_ts - window_seconds, event_ts]."""
        key = self._win_key(window_key, window_seconds)
        cutoff = event_ts - window_seconds
        return await self._client.zcount(key, cutoff, event_ts)

    async def get_in_window(
        self,
        window_key: str,
        event_ts: float,
        window_seconds: int,
    ) -> list[str]:
        """Return event IDs in [event_ts - window_seconds, event_ts]."""
        key = self._win_key(window_key, window_seconds)
        cutoff = event_ts - window_seconds
        return await self._client.zrangebyscore(key, cutoff, event_ts)

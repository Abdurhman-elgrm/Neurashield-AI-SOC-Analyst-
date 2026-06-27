"""
Attack-chain detection using Redis sorted sets as time-windowed counters.

Patterns:
  brute_force              ≥N auth failures for same username in win_brute
  brute_force_success      brute_force followed by auth success (same user) in win_lateral
  credential_stuffing      ≥N distinct usernames targeted from same source IP in win_brute
  lateral_movement         auth success to ≥N distinct hosts by same user in win_lateral
  lateral_movement_xdomain auth success AS ≥N distinct usernames from same source IP
                           (Pass-the-Hash / credential reuse across accounts)

All thresholds and time windows are configurable via environment variables.
"""

from __future__ import annotations

import os
import time

from redis.asyncio import Redis

from app.core.redis import TenantRedisClient

# ─── Configurable thresholds ──────────────────────────────────────────────────
_WIN_BRUTE = int(os.getenv("UEBA_BRUTE_WINDOW_SECS", "300"))  # 5 min
_WIN_LATERAL = int(os.getenv("UEBA_LATERAL_WINDOW_SECS", "600"))  # 10 min
_WIN_XDOMAIN = int(os.getenv("UEBA_XDOMAIN_WINDOW_SECS", "900"))  # 15 min

_BRUTE_THRESHOLD = int(os.getenv("UEBA_BRUTE_THRESHOLD", "5"))
_LATERAL_THRESHOLD = int(os.getenv("UEBA_LATERAL_THRESHOLD", "3"))
_STUFFING_THRESHOLD = int(os.getenv("UEBA_STUFFING_THRESHOLD", "5"))


class AttackChainDetector:
    def __init__(self, redis: Redis, tenant_id: str) -> None:
        self._c = TenantRedisClient(redis, tenant_id, "ueba")

    async def evaluate(
        self,
        category: str,
        username: str | None,
        source_ip: str | None,
        hostname: str | None,
        is_auth_success: bool,
        is_auth_failure: bool,
    ) -> list[str]:
        if category not in ("auth", "network"):
            return []

        flags: list[str] = []
        now = time.time()

        if is_auth_failure and username:
            flags.extend(await self._brute_force(username, now))

        if is_auth_success and username:
            flags.extend(await self._brute_force_success(username, now))
            if hostname:
                flags.extend(await self._lateral_movement(username, hostname, now))

        if is_auth_failure and source_ip and username:
            flags.extend(await self._credential_stuffing(source_ip, username, now))

        # Cross-domain lateral movement: same source IP succeeds as multiple
        # different accounts — classic Pass-the-Hash / credential reuse pattern.
        if is_auth_success and source_ip and username:
            flags.extend(await self._lateral_movement_xdomain(source_ip, username, now))

        return flags

    async def _brute_force(self, username: str, now: float) -> list[str]:
        key = f"chain:brute:{username}:fails"
        cutoff = now - _WIN_BRUTE
        await self._c.zremrangebyscore(key, "-inf", cutoff)
        await self._c.zadd(key, {f"{now:.6f}": now})
        await self._c.expire(key, _WIN_BRUTE * 2)
        count = await self._c.zcount(key, cutoff, "+inf")
        return ["brute_force"] if count >= _BRUTE_THRESHOLD else []

    async def _brute_force_success(self, username: str, now: float) -> list[str]:
        key = f"chain:brute:{username}:fails"
        cutoff = now - _WIN_LATERAL
        count = await self._c.zcount(key, cutoff, "+inf")
        if count >= _BRUTE_THRESHOLD:
            # Clear failure window — attacker succeeded; reset so repeat attempts
            # don't immediately re-fire this flag.
            await self._c.zremrangebyscore(key, "-inf", "+inf")
            return ["brute_force_success"]
        return []

    async def _lateral_movement(self, username: str, hostname: str, now: float) -> list[str]:
        key = f"chain:lateral:{username}:hosts"
        cutoff = now - _WIN_LATERAL
        await self._c.zremrangebyscore(key, "-inf", cutoff)
        await self._c.zadd(key, {f"{hostname}:{now:.3f}": now})
        await self._c.expire(key, _WIN_LATERAL * 2)
        entries = await self._c.zrangebyscore(key, cutoff, "+inf")
        distinct = {e.rsplit(":", 1)[0] for e in entries}
        return ["lateral_movement"] if len(distinct) >= _LATERAL_THRESHOLD else []

    async def _credential_stuffing(self, source_ip: str, username: str, now: float) -> list[str]:
        key = f"chain:stuff:{source_ip}:users"
        cutoff = now - _WIN_BRUTE
        await self._c.zremrangebyscore(key, "-inf", cutoff)
        await self._c.zadd(key, {f"{username}:{now:.6f}": now})
        await self._c.expire(key, _WIN_BRUTE * 2)
        entries = await self._c.zrangebyscore(key, cutoff, "+inf")
        distinct = {e.rsplit(":", 1)[0] for e in entries}
        return ["credential_stuffing"] if len(distinct) >= _STUFFING_THRESHOLD else []

    async def _lateral_movement_xdomain(
        self, source_ip: str, username: str, now: float
    ) -> list[str]:
        """
        Detect the same source IP authenticating successfully as multiple
        distinct user accounts — indicative of Pass-the-Hash, Golden Ticket,
        or harvested credential reuse across domain accounts.
        """
        key = f"chain:xdomain:{source_ip}:users"
        cutoff = now - _WIN_XDOMAIN
        await self._c.zremrangebyscore(key, "-inf", cutoff)
        await self._c.zadd(key, {f"{username}:{now:.6f}": now})
        await self._c.expire(key, _WIN_XDOMAIN * 2)
        entries = await self._c.zrangebyscore(key, cutoff, "+inf")
        distinct = {e.rsplit(":", 1)[0] for e in entries}
        return ["lateral_movement_xdomain"] if len(distinct) >= _LATERAL_THRESHOLD else []

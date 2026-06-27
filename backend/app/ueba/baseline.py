"""
Behavioral baseline tracking using Redis for per-user and per-host patterns.

Tracks:
- New source IPs seen per user   (Set, 30-day TTL)
- New processes seen per host    (Set, 30-day TTL)
- Last known login location      (Hash, 7-day TTL) for impossible-travel check

After-hours configuration:
  The business hours window defaults to 05:00–23:00 UTC, which covers Egypt
  (UTC+2/+3) and most MENA/European timezones without false-positiving on
  legitimate morning/evening work.

  Set UEBA_BUSINESS_START_UTC and UEBA_BUSINESS_END_UTC environment variables
  to tune per deployment (e.g. 08–20 for strict 9-to-5 enforcement, or 00–24
  to disable entirely).

  Future: per-tenant timezone offset stored in tenant settings table.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis

from app.core.redis import TenantRedisClient

_TTL_30D = 86400 * 30
_TTL_7D = 86400 * 7

# Configurable business hours (UTC). Defaults cover UTC+2/+3 timezones.
_BIZ_START = int(os.getenv("UEBA_BUSINESS_START_UTC", "5"))  # 05:00 UTC
_BIZ_END = int(os.getenv("UEBA_BUSINESS_END_UTC", "23"))  # 23:00 UTC


@dataclass
class BaselineFlags:
    new_source_ip: bool = False
    new_process_on_host: bool = False
    after_hours: bool = False
    privileged_user: bool = False


class BehavioralBaseline:
    def __init__(self, redis: Redis, tenant_id: str) -> None:
        self._c = TenantRedisClient(redis, tenant_id, "ueba")

    async def evaluate(
        self,
        username: str | None,
        source_ip: str | None,
        process_name: str | None,
        hostname: str | None,
        hour_utc: int,
        is_privileged: bool = False,
    ) -> BaselineFlags:
        flags = BaselineFlags()

        # After-hours check uses configurable window (not hardcoded 06-22 UTC).
        flags.after_hours = hour_utc < _BIZ_START or hour_utc >= _BIZ_END
        flags.privileged_user = is_privileged

        # New source IP for this user (only tracked when both are known)
        if username and source_ip:
            key = f"user:{username}:seen_ips"
            if not await self._c.sismember(key, source_ip):
                flags.new_source_ip = True
                await self._c.sadd(key, source_ip)
                await self._c.expire(key, _TTL_30D)

        # New process seen on this host (only tracked when both are known)
        if hostname and process_name:
            key = f"host:{hostname}:seen_procs"
            if not await self._c.sismember(key, process_name):
                flags.new_process_on_host = True
                await self._c.sadd(key, process_name)
                await self._c.expire(key, _TTL_30D)

        return flags

    async def get_last_location(self, username: str) -> dict[str, Any] | None:
        raw = await self._c.hgetall(f"user:{username}:last_location")
        if not raw or "lat" not in raw:
            return None
        return {
            "lat": float(raw["lat"]),
            "lon": float(raw["lon"]),
            "ts": float(raw["ts"]),
        }

    async def set_last_location(self, username: str, lat: float, lon: float) -> None:
        key = f"user:{username}:last_location"
        await self._c.hset(key, {"lat": str(lat), "lon": str(lon), "ts": str(time.time())})
        await self._c.expire(key, _TTL_7D)

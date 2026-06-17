from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import httpx
import structlog

logger = structlog.get_logger(__name__)

_PRIVATE_RANGES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "::1", "fc", "fd",
)

_CACHE_TTL = 86400   # 24 hours
_LOCK_TTL  = 10      # seconds a single lookup may hold the lock
_LOCK_WAIT = 2.0     # seconds to wait when another process holds the lock


@dataclass
class GeoResult:
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    isp: str | None = None
    is_private: bool = False


def _is_private(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in _PRIVATE_RANGES)


class GeoIPService:
    """
    GeoIP lookup via ip-api.com (free, no key needed, 45 req/min limit).

    Cache strategy:
      1. Redis 24-hour cache — primary source.
      2. Per-IP Redis lock (SETNX) — cache-stampede protection.
         When 50 events with the same uncached IP arrive at once, only ONE
         outbound HTTP request is made; the other 49 wait up to _LOCK_WAIT
         seconds for the cache to be populated.
    """

    _FIELDS = "status,country,countryCode,city,lat,lon,isp,query"

    @staticmethod
    async def lookup(ip: str, redis: "Redis[str] | None" = None) -> GeoResult:  # type: ignore[name-defined]
        if not ip or _is_private(ip):
            return GeoResult(is_private=True)

        cache_key = f"geoip:{ip}"
        lock_key  = f"geoip:lock:{ip}"

        # ── 1. Try cache ───────────────────────────────────────────────────
        if redis is not None:
            try:
                cached = await redis.get(cache_key)
                if cached:
                    return GeoResult(**json.loads(cached))
            except Exception:
                pass

        # ── 2. Acquire per-IP lock (stampede protection) ───────────────────
        if redis is not None:
            try:
                acquired = await redis.set(lock_key, "1", nx=True, ex=_LOCK_TTL)
                if not acquired:
                    # Another coroutine/process is fetching this IP — wait briefly
                    await asyncio.sleep(_LOCK_WAIT)
                    try:
                        cached = await redis.get(cache_key)
                        if cached:
                            return GeoResult(**json.loads(cached))
                    except Exception:
                        pass
                    return GeoResult()  # give up — next event will retry
            except Exception:
                pass  # Redis error: proceed without lock

        # ── 3. External HTTP lookup ────────────────────────────────────────
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": GeoIPService._FIELDS},
                )
                resp.raise_for_status()
                data = resp.json()

            if data.get("status") != "success":
                return GeoResult()

            result = GeoResult(
                country=data.get("country"),
                country_code=data.get("countryCode"),
                city=data.get("city"),
                latitude=data.get("lat"),
                longitude=data.get("lon"),
                isp=data.get("isp"),
            )

            if redis is not None:
                try:
                    payload = {
                        "country": result.country,
                        "country_code": result.country_code,
                        "city": result.city,
                        "latitude": result.latitude,
                        "longitude": result.longitude,
                        "isp": result.isp,
                        "is_private": False,
                    }
                    await redis.set(cache_key, json.dumps(payload), ex=_CACHE_TTL)
                    await redis.delete(lock_key)
                except Exception:
                    pass

            return result

        except Exception as exc:
            logger.debug("geoip_lookup_failed", ip=ip, error=str(exc))
            if redis is not None:
                try:
                    await redis.delete(lock_key)
                except Exception:
                    pass
            return GeoResult()

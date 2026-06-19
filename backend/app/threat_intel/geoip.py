"""
GeoIP lookup service.

Lookup strategy (in order):

  1. Redis 24-hour cache       — shared across all coroutines.
  2. MaxMind GeoLite2 (local)  — offline, no rate limit, primary source when
                                  the .mmdb file is present.
                                  Set MAXMIND_DB_PATH env var to the file path.
                                  Download: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
  3. ip-api.com (HTTP)         — fallback when MaxMind DB is unavailable.
                                  Free tier: 45 requests / minute; no API key needed.
                                  ISP/AS data is only available via this path.

Cache-stampede protection (Redis lock):
  When many coroutines arrive for the same uncached IP simultaneously, only
  the first acquires the SETNX lock and makes the external request; the others
  wait _LOCK_WAIT seconds and then read from cache.
"""
from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import dataclass

import httpx
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)

# ─── Runtime knobs ────────────────────────────────────────────────────────────
_CACHE_TTL = 86400   # 24 hours
_LOCK_TTL  = 10      # seconds a single lookup may hold the Redis lock
_LOCK_WAIT = 2.0     # seconds to wait when another process holds the lock

# Resolved once at module import time from the central settings object.
# Override at runtime with MAXMIND_DB_PATH env var (picked up by Settings).
_MAXMIND_DB_PATH: str = settings.MAXMIND_DB_PATH

# ─── Private IP ranges ────────────────────────────────────────────────────────
_PRIVATE_RANGES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "::1", "fc", "fd",
)


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


# ─── MaxMind reader (lazy singleton, thread-safe) ────────────────────────────

try:
    import geoip2.database  # type: ignore[import-untyped]
    import geoip2.errors    # type: ignore[import-untyped]
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False

_maxmind_reader: "geoip2.database.Reader | None" = None
_maxmind_lock = threading.Lock()
_maxmind_init_attempted = False   # avoid repeated failing opens


def _get_maxmind_reader() -> "geoip2.database.Reader | None":
    """Returns the singleton MaxMind reader, initialising it on first call."""
    global _maxmind_reader, _maxmind_init_attempted

    if not _GEOIP2_AVAILABLE or not _MAXMIND_DB_PATH:
        return None
    if _maxmind_init_attempted:
        return _maxmind_reader   # may be None if init failed

    with _maxmind_lock:
        if not _maxmind_init_attempted:
            _maxmind_init_attempted = True
            try:
                _maxmind_reader = geoip2.database.Reader(_MAXMIND_DB_PATH)
                logger.info("maxmind_db_loaded", path=_MAXMIND_DB_PATH)
            except Exception as exc:
                logger.warning(
                    "maxmind_db_load_failed",
                    path=_MAXMIND_DB_PATH,
                    error=str(exc),
                )
                _maxmind_reader = None

    return _maxmind_reader


def _lookup_maxmind(ip: str) -> GeoResult | None:
    """
    Synchronous MaxMind city lookup.  Returns None on any error so the caller
    can transparently fall back to the HTTP API.
    """
    reader = _get_maxmind_reader()
    if reader is None:
        return None
    try:
        response = reader.city(ip)
        return GeoResult(
            country=response.country.name,
            country_code=response.country.iso_code,
            city=response.city.name,
            latitude=response.location.latitude,
            longitude=response.location.longitude,
            isp=None,   # ISP data requires the ASN or ISP database; see fallback
        )
    except Exception:
        # AddressNotFoundError, ValueError (invalid IP), etc.
        return None


# ─── Main service ─────────────────────────────────────────────────────────────

class GeoIPService:
    """
    GeoIP lookup with three-tier strategy: Redis cache → MaxMind local DB → ip-api.com.

    Usage:
        result = await GeoIPService.lookup("1.2.3.4", redis=redis_client)
    """

    _IP_API_FIELDS = "status,country,countryCode,city,lat,lon,isp,query"

    @staticmethod
    async def lookup(ip: str, redis: "Redis[str] | None" = None) -> GeoResult:  # type: ignore[name-defined]
        if not ip or _is_private(ip):
            return GeoResult(is_private=True)

        cache_key = f"geoip:{ip}"
        lock_key  = f"geoip:lock:{ip}"

        # ── 1. Redis cache ─────────────────────────────────────────────────
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
                    await asyncio.sleep(_LOCK_WAIT)
                    try:
                        cached = await redis.get(cache_key)
                        if cached:
                            return GeoResult(**json.loads(cached))
                    except Exception:
                        pass
                    return GeoResult()
            except Exception:
                pass  # Redis unavailable — proceed without lock

        # ── 3. MaxMind local DB (no network, no rate limit) ────────────────
        maxmind_result = _lookup_maxmind(ip)
        if maxmind_result is not None:
            # MaxMind doesn't provide ISP; we still cache and return.
            # Enrich with ISP asynchronously only if ip-api is available and
            # the caller needs ISP data — for now, cache the MaxMind result.
            await _cache_result(redis, cache_key, lock_key, maxmind_result)
            logger.debug("geoip_maxmind_hit", ip=ip, country=maxmind_result.country_code)
            return maxmind_result

        # ── 4. ip-api.com HTTP fallback ────────────────────────────────────
        return await GeoIPService._lookup_ipapi(ip, redis, cache_key, lock_key)

    @staticmethod
    async def _lookup_ipapi(
        ip: str,
        redis: "Redis[str] | None",
        cache_key: str,
        lock_key: str,
    ) -> GeoResult:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": GeoIPService._IP_API_FIELDS},
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
            await _cache_result(redis, cache_key, lock_key, result)
            logger.debug("geoip_ipapi_hit", ip=ip, country=result.country_code)
            return result

        except Exception as exc:
            logger.debug("geoip_lookup_failed", ip=ip, error=str(exc))
            if redis is not None:
                try:
                    await redis.delete(lock_key)
                except Exception:
                    pass
            return GeoResult()


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _cache_result(
    redis: "Redis[str] | None",  # type: ignore[name-defined]
    cache_key: str,
    lock_key: str,
    result: GeoResult,
) -> None:
    if redis is None:
        return
    try:
        payload = {
            "country": result.country,
            "country_code": result.country_code,
            "city": result.city,
            "latitude": result.latitude,
            "longitude": result.longitude,
            "isp": result.isp,
            "is_private": result.is_private,
        }
        await redis.set(cache_key, json.dumps(payload), ex=_CACHE_TTL)
        await redis.delete(lock_key)
    except Exception:
        pass

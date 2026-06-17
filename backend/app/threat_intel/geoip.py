from __future__ import annotations

import json
from dataclasses import dataclass, field

import httpx
import structlog

logger = structlog.get_logger(__name__)

_PRIVATE_RANGES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "::1", "fc", "fd",
)

_CACHE_TTL = 86400  # 24 hours — geo data rarely changes


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
    All results are cached in Redis for 24 hours to stay within rate limits.
    Fails silently — never raises, always returns GeoResult.
    """

    _FIELDS = "status,country,countryCode,city,lat,lon,isp,query"

    @staticmethod
    async def lookup(ip: str, redis: "Redis[str] | None" = None) -> GeoResult:  # type: ignore[name-defined]
        if not ip or _is_private(ip):
            return GeoResult(is_private=True)

        cache_key = f"geoip:{ip}"

        # ── Try cache first ────────────────────────────────────────────────
        if redis is not None:
            try:
                cached = await redis.get(cache_key)
                if cached:
                    data = json.loads(cached)
                    return GeoResult(**data)
            except Exception:
                pass

        # ── External lookup ────────────────────────────────────────────────
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
                except Exception:
                    pass

            return result

        except Exception as exc:
            logger.debug("geoip_lookup_failed", ip=ip, error=str(exc))
            return GeoResult()

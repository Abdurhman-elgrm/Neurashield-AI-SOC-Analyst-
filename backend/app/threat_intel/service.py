from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import structlog

from app.core.config import settings
from app.threat_intel.geoip import GeoIPService, GeoResult

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

_CACHE_TTL = 3600  # 1 hour for threat intel data


@dataclass
class ThreatIntelResult:
    abuse_confidence: int = 0          # 0-100 from AbuseIPDB
    is_threat_ip: bool = False
    threat_intel_flags: list[str] = field(default_factory=list)
    sources_checked: list[str] = field(default_factory=list)


@dataclass
class EnrichmentResult:
    """Combined GeoIP + ThreatIntel enrichment for a single IP."""
    # GeoIP
    geo_country: str | None = None
    geo_country_code: str | None = None
    geo_city: str | None = None
    geo_latitude: float | None = None
    geo_longitude: float | None = None
    geo_isp: str | None = None
    # Threat Intel
    abuse_confidence: int = 0
    is_threat_ip: bool = False
    threat_intel_flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "geo_country": self.geo_country,
            "geo_country_code": self.geo_country_code,
            "geo_city": self.geo_city,
            "geo_latitude": self.geo_latitude,
            "geo_longitude": self.geo_longitude,
            "geo_isp": self.geo_isp,
            "abuse_confidence": self.abuse_confidence,
            "is_threat_ip": self.is_threat_ip,
            "threat_intel_flags": self.threat_intel_flags,
        }


class ThreatIntelService:
    """
    Threat intelligence enrichment using AbuseIPDB, AlienVault OTX, and VirusTotal.
    All lookups are cached in Redis. Fails silently — never blocks event ingestion.
    """

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────

    @staticmethod
    async def _check_abuseipdb(ip: str, redis: "Redis[str] | None") -> ThreatIntelResult:
        if not settings.ABUSEIPDB_API_KEY:
            return ThreatIntelResult()

        cache_key = f"ti:abuse:{ip}"
        if redis is not None:
            try:
                cached = await redis.get(cache_key)
                if cached:
                    data = json.loads(cached)
                    return ThreatIntelResult(**data)
            except Exception:
                pass

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})

            confidence = data.get("abuseConfidenceScore", 0)
            flags: list[str] = []
            if confidence >= 25:
                flags.append("abuseipdb_reported")
            if confidence >= 75:
                flags.append("abuseipdb_high_confidence")
            if data.get("isWhitelisted"):
                flags = []
                confidence = 0

            result = ThreatIntelResult(
                abuse_confidence=confidence,
                is_threat_ip=confidence >= 25,
                threat_intel_flags=flags,
                sources_checked=["abuseipdb"],
            )

            if redis is not None:
                try:
                    payload = {
                        "abuse_confidence": result.abuse_confidence,
                        "is_threat_ip": result.is_threat_ip,
                        "threat_intel_flags": result.threat_intel_flags,
                        "sources_checked": result.sources_checked,
                    }
                    await redis.set(cache_key, json.dumps(payload), ex=_CACHE_TTL)
                except Exception:
                    pass

            return result

        except Exception as exc:
            logger.debug("abuseipdb_lookup_failed", ip=ip, error=str(exc))
            return ThreatIntelResult(sources_checked=["abuseipdb"])

    # ── AlienVault OTX ────────────────────────────────────────────────────────

    @staticmethod
    async def _check_otx(ip: str, redis: "Redis[str] | None") -> list[str]:
        if not settings.ALIENVAULT_API_KEY:
            return []

        cache_key = f"ti:otx:{ip}"
        if redis is not None:
            try:
                cached = await redis.get(cache_key)
                if cached:
                    return json.loads(cached)
            except Exception:
                pass

        flags: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                    headers={"X-OTX-API-KEY": settings.ALIENVAULT_API_KEY},
                )
                resp.raise_for_status()
                data = resp.json()

            pulse_count = data.get("pulse_info", {}).get("count", 0)
            if pulse_count > 0:
                flags.append(f"otx_pulses:{pulse_count}")
            if pulse_count >= 5:
                flags.append("otx_high_reputation")

        except Exception as exc:
            logger.debug("otx_lookup_failed", ip=ip, error=str(exc))

        if redis is not None:
            try:
                await redis.set(cache_key, json.dumps(flags), ex=_CACHE_TTL)
            except Exception:
                pass

        return flags

    # ── VirusTotal ────────────────────────────────────────────────────────────

    @staticmethod
    async def _check_virustotal(ip: str, redis: "Redis[str] | None") -> list[str]:
        if not settings.VIRUSTOTAL_API_KEY:
            return []

        cache_key = f"ti:vt:{ip}"
        if redis is not None:
            try:
                cached = await redis.get(cache_key)
                if cached:
                    return json.loads(cached)
            except Exception:
                pass

        flags: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                )
                resp.raise_for_status()
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                flags.append(f"virustotal_malicious:{malicious}")
            if suspicious > 0:
                flags.append(f"virustotal_suspicious:{suspicious}")

        except Exception as exc:
            logger.debug("virustotal_lookup_failed", ip=ip, error=str(exc))

        if redis is not None:
            try:
                await redis.set(cache_key, json.dumps(flags), ex=_CACHE_TTL)
            except Exception:
                pass

        return flags

    # ── Main enrichment entry point ───────────────────────────────────────────

    @staticmethod
    async def enrich_ip(ip: str | None, redis: "Redis[str] | None" = None) -> EnrichmentResult:
        """
        Enriches a single IP with GeoIP + ThreatIntel data.
        Never raises — always returns EnrichmentResult (may be empty).
        All external calls run concurrently with a 10s overall timeout.
        """
        if not ip:
            return EnrichmentResult()

        try:
            geo_task = GeoIPService.lookup(ip, redis)
            abuse_task = ThreatIntelService._check_abuseipdb(ip, redis)
            otx_task = ThreatIntelService._check_otx(ip, redis)
            vt_task = ThreatIntelService._check_virustotal(ip, redis)

            geo, abuse, otx_flags, vt_flags = await asyncio.wait_for(
                asyncio.gather(geo_task, abuse_task, otx_task, vt_task, return_exceptions=True),
                timeout=10.0,
            )

            # Gracefully handle individual task failures
            geo_result: GeoResult = geo if isinstance(geo, GeoResult) else GeoResult()
            abuse_result: ThreatIntelResult = (
                abuse if isinstance(abuse, ThreatIntelResult) else ThreatIntelResult()
            )
            otx_result: list[str] = otx_flags if isinstance(otx_flags, list) else []
            vt_result: list[str] = vt_flags if isinstance(vt_flags, list) else []

            all_flags = list(set(abuse_result.threat_intel_flags + otx_result + vt_result))
            is_threat = abuse_result.is_threat_ip or bool(otx_result) or any(
                "malicious" in f for f in vt_result
            )

            return EnrichmentResult(
                geo_country=geo_result.country,
                geo_country_code=geo_result.country_code,
                geo_city=geo_result.city,
                geo_latitude=geo_result.latitude,
                geo_longitude=geo_result.longitude,
                geo_isp=geo_result.isp,
                abuse_confidence=abuse_result.abuse_confidence,
                is_threat_ip=is_threat,
                threat_intel_flags=all_flags,
            )

        except Exception as exc:
            logger.debug("enrich_ip_failed", ip=ip, error=str(exc))
            return EnrichmentResult()

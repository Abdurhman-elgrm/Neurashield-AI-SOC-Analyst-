from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import structlog

from app.core.config import settings
from app.threat_intel.geoip import GeoIPService, GeoResult

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

# ─── Source-specific cache TTLs ───────────────────────────────────────────────
# GeoIP: IP→location mapping changes rarely — 30-day cache is safe.
# AbuseIPDB: reputation scores change daily as reports come in.
# OTX: pulse data updates every few hours.
# VirusTotal: real-time scanning, cache only 1 hour.
_GEOIP_CACHE_TTL = int(os.getenv("GEOIP_CACHE_TTL_SECS", str(86_400 * 30)))  # 30 days
_ABUSE_CACHE_TTL = int(os.getenv("ABUSE_CACHE_TTL_SECS", str(86_400)))  # 24 hours
_OTX_CACHE_TTL = int(os.getenv("OTX_CACHE_TTL_SECS", str(21_600)))  # 6 hours
_VT_CACHE_TTL = int(os.getenv("VT_CACHE_TTL_SECS", str(3_600)))  # 1 hour

# ─── Configurable AbuseIPDB thresholds ────────────────────────────────────────
_ABUSE_SUSPICIOUS_SCORE = int(os.getenv("ABUSEIPDB_SUSPICIOUS_SCORE", "25"))
_ABUSE_MALICIOUS_SCORE = int(os.getenv("ABUSEIPDB_MALICIOUS_SCORE", "75"))

# ─── Circuit breaker ──────────────────────────────────────────────────────────
# Opens the circuit after N consecutive failures; resets after _CB_RESET_SECS.
_CB_MAX_FAILURES = int(os.getenv("THREAT_INTEL_CB_FAILURES", "3"))
_CB_RESET_SECS = int(os.getenv("THREAT_INTEL_CB_RESET_SECS", "300"))

_cb_failures: dict[str, int] = {}  # service → failure count
_cb_open_until: dict[str, float] = {}  # service → epoch when circuit resets


def _cb_is_open(service: str) -> bool:
    return _cb_open_until.get(service, 0.0) > time.time()


def _cb_record_success(service: str) -> None:
    _cb_failures[service] = 0
    _cb_open_until.pop(service, None)


def _cb_record_failure(service: str) -> None:
    count = _cb_failures.get(service, 0) + 1
    _cb_failures[service] = count
    if count >= _CB_MAX_FAILURES:
        _cb_open_until[service] = time.time() + _CB_RESET_SECS
        logger.warning(
            "threat_intel_circuit_open",
            service=service,
            failures=count,
            reset_in_secs=_CB_RESET_SECS,
        )


# ─── RFC 1918 / loopback / link-local private IP detection ───────────────────


def _is_private_ip(ip: str) -> bool:
    """Return True for IPs that don't require external enrichment."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


@dataclass
class ThreatIntelResult:
    abuse_confidence: int = 0  # 0-100 from AbuseIPDB
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
    All lookups are cached in Redis with source-specific TTLs. Fails silently —
    never blocks event ingestion. Circuit breaker prevents hammering failed APIs.
    Private/RFC1918 IPs are skipped (no external lookup needed).
    """

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────

    @staticmethod
    async def _check_abuseipdb(ip: str, redis: Redis[str] | None) -> ThreatIntelResult:
        if not settings.ABUSEIPDB_API_KEY:
            return ThreatIntelResult()
        if _cb_is_open("abuseipdb"):
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

            _cb_record_success("abuseipdb")

            confidence = data.get("abuseConfidenceScore", 0)
            flags: list[str] = []
            if confidence >= _ABUSE_SUSPICIOUS_SCORE:
                flags.append("abuseipdb_reported")
            if confidence >= _ABUSE_MALICIOUS_SCORE:
                flags.append("abuseipdb_high_confidence")
            if data.get("isWhitelisted"):
                flags = []
                confidence = 0

            result = ThreatIntelResult(
                abuse_confidence=confidence,
                is_threat_ip=confidence >= _ABUSE_SUSPICIOUS_SCORE,
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
                    await redis.set(cache_key, json.dumps(payload), ex=_ABUSE_CACHE_TTL)
                except Exception:
                    pass

            return result

        except Exception as exc:
            _cb_record_failure("abuseipdb")
            logger.debug("abuseipdb_lookup_failed", ip=ip, error=str(exc))
            return ThreatIntelResult(sources_checked=["abuseipdb"])

    # ── AlienVault OTX ────────────────────────────────────────────────────────

    @staticmethod
    async def _check_otx(ip: str, redis: Redis[str] | None) -> list[str]:
        if not settings.ALIENVAULT_API_KEY:
            return []
        if _cb_is_open("otx"):
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

            _cb_record_success("otx")

            pulse_count = data.get("pulse_info", {}).get("count", 0)
            if pulse_count > 0:
                flags.append(f"otx_pulses:{pulse_count}")
            if pulse_count >= 5:
                flags.append("otx_high_reputation")

        except Exception as exc:
            _cb_record_failure("otx")
            logger.debug("otx_lookup_failed", ip=ip, error=str(exc))

        if redis is not None:
            try:
                await redis.set(cache_key, json.dumps(flags), ex=_OTX_CACHE_TTL)
            except Exception:
                pass

        return flags

    # ── VirusTotal ────────────────────────────────────────────────────────────

    @staticmethod
    async def _check_virustotal(ip: str, redis: Redis[str] | None) -> list[str]:
        if not settings.VIRUSTOTAL_API_KEY:
            return []
        if _cb_is_open("virustotal"):
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
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

            _cb_record_success("virustotal")

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            if malicious > 0:
                flags.append(f"virustotal_malicious:{malicious}")
            if suspicious > 0:
                flags.append(f"virustotal_suspicious:{suspicious}")
            # Consensus threshold: >50% of engines flagging = high confidence
            if total > 0 and malicious / total > 0.5:
                flags.append("virustotal_consensus_malicious")

        except Exception as exc:
            _cb_record_failure("virustotal")
            logger.debug("virustotal_lookup_failed", ip=ip, error=str(exc))

        if redis is not None:
            try:
                await redis.set(cache_key, json.dumps(flags), ex=_VT_CACHE_TTL)
            except Exception:
                pass

        return flags

    # ── Main enrichment entry point ───────────────────────────────────────────

    @staticmethod
    async def enrich_ip(ip: str | None, redis: Redis[str] | None = None) -> EnrichmentResult:
        """
        Enriches a single IP with GeoIP + ThreatIntel data.

        Short-circuits for:
          - None / empty IPs
          - Private/RFC1918/loopback IPs (no external lookup needed)

        Never raises — always returns EnrichmentResult (may be empty).
        All external calls run concurrently with a 10s overall timeout.
        Each source uses its own cache TTL and circuit breaker.
        """
        if not ip:
            return EnrichmentResult()

        if _is_private_ip(ip):
            logger.debug("skipping_private_ip_enrichment", ip=ip)
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
            is_threat = (
                abuse_result.is_threat_ip
                or bool(otx_result)
                or "virustotal_consensus_malicious" in vt_result
                or any("malicious" in f for f in vt_result)
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

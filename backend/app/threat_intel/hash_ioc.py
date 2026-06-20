"""
MalwareBazaar hash IOC lookup — free API, no key required.

Strategy:
  - Redis cache: positive hits 24h, negative 1h (minimises external calls)
  - Circuit breaker: opens after 3 consecutive API failures, resets after 5 min
  - Only SHA-256 supported (most reliable hash in MalwareBazaar)
  - result.to_flags() returns strings ready for threat_intel_flags list
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING

import httpx
import structlog

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

_MB_API_URL      = "https://mb-api.abuse.ch/api/v1/"
_POSITIVE_TTL    = int(os.getenv("HASH_IOC_POSITIVE_TTL_SECS", str(86_400)))   # 24 h
_NEGATIVE_TTL    = int(os.getenv("HASH_IOC_NEGATIVE_TTL_SECS", str(3_600)))    # 1 h
_REQUEST_TIMEOUT = float(os.getenv("HASH_IOC_TIMEOUT_SECS", "4.0"))

# Circuit breaker state (process-local; resets on worker restart — acceptable)
_CB_MAX_FAILURES = 3
_CB_RESET_SECS   = 300
_cb_failures: int  = 0
_cb_open_until: float = 0.0


# ─── Result ───────────────────────────────────────────────────────────────────

@dataclass
class HashIOCResult:
    found: bool = False
    sha256: str = ""
    malware_name: str | None = None
    malware_family: str | None = None
    file_type: str | None = None
    reporter: str | None = None
    tags: list[str] = field(default_factory=list)
    source: str = "malwarebazaar"

    def to_flags(self) -> list[str]:
        """
        Returns strings to append to NormalizedEvent.threat_intel_flags.
        Callers check for 'hash_ioc_match' to trigger the detection rule.
        """
        if not self.found:
            return []
        flags = ["hash_ioc_match"]
        if self.malware_name:
            safe = self.malware_name.replace(" ", "_")[:64]
            flags.append(f"malwarebazaar:{safe}")
        return flags


# ─── Circuit breaker ──────────────────────────────────────────────────────────

def _cb_is_open() -> bool:
    return _cb_open_until > time.time()


def _cb_success() -> None:
    global _cb_failures, _cb_open_until
    _cb_failures    = 0
    _cb_open_until  = 0.0


def _cb_failure() -> None:
    global _cb_failures, _cb_open_until
    _cb_failures += 1
    if _cb_failures >= _CB_MAX_FAILURES:
        _cb_open_until = time.time() + _CB_RESET_SECS
        logger.warning(
            "hash_ioc_circuit_open",
            failures=_cb_failures,
            reset_in_secs=_CB_RESET_SECS,
        )


# ─── Cache helpers ────────────────────────────────────────────────────────────

def _cache_key(sha256: str) -> str:
    return f"hash_ioc:{sha256}"


async def _read_cache(sha256: str, redis: "Redis") -> HashIOCResult | None:
    try:
        raw = await redis.get(_cache_key(sha256))
        if raw is not None:
            return HashIOCResult(**json.loads(raw))
    except Exception as exc:
        logger.warning("hash_ioc_cache_read_error", error=str(exc))
    return None


async def _write_cache(result: HashIOCResult, ttl: int, redis: "Redis") -> None:
    try:
        await redis.setex(_cache_key(result.sha256), ttl, json.dumps(asdict(result)))
    except Exception as exc:
        logger.warning("hash_ioc_cache_write_error", error=str(exc))


# ─── Public API ───────────────────────────────────────────────────────────────

async def check_file_hash(sha256: str | None, redis: "Redis") -> HashIOCResult:
    """
    Check a SHA-256 hash against MalwareBazaar.

    Fast-returns HashIOCResult(found=False) when:
      - hash is None / wrong length / circuit breaker open
    Returns cached result when available.
    Makes one HTTP POST otherwise.
    """
    if not sha256 or len(sha256) != 64:
        return HashIOCResult()

    sha256 = sha256.lower()

    cached = await _read_cache(sha256, redis)
    if cached is not None:
        return cached

    if _cb_is_open():
        return HashIOCResult(sha256=sha256)

    # ── Query MalwareBazaar ───────────────────────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            resp = await client.post(
                _MB_API_URL,
                data={"query": "get_info", "hash": sha256},
                headers={"Accept": "application/json"},
            )
        resp.raise_for_status()
        body = resp.json()
        _cb_success()
    except Exception as exc:
        logger.warning("hash_ioc_api_error", sha256=sha256[:16], error=str(exc))
        _cb_failure()
        return HashIOCResult(sha256=sha256)

    query_status = body.get("query_status", "")

    if query_status == "hash_not_found":
        result = HashIOCResult(found=False, sha256=sha256)
        await _write_cache(result, _NEGATIVE_TTL, redis)
        return result

    if query_status == "ok" and body.get("data"):
        info = body["data"][0]
        raw_tags = [t for t in (info.get("tags") or []) if t and len(t) > 2]
        malware_name = info.get("signature") or (raw_tags[0] if raw_tags else None)
        result = HashIOCResult(
            found=True,
            sha256=sha256,
            malware_name=malware_name,
            malware_family=raw_tags[0] if raw_tags else None,
            file_type=info.get("file_type"),
            reporter=info.get("reporter"),
            tags=raw_tags,
            source="malwarebazaar",
        )
        await _write_cache(result, _POSITIVE_TTL, redis)
        logger.warning(
            "hash_ioc_malware_confirmed",
            sha256=sha256[:16],
            malware_name=malware_name,
            file_type=result.file_type,
        )
        return result

    # Unexpected status — don't cache, return negative
    logger.info("hash_ioc_unexpected_status", status=query_status, sha256=sha256[:16])
    return HashIOCResult(sha256=sha256)

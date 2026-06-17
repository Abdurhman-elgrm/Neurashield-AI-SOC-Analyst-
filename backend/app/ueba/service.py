"""
UEBAService — Phase 2 behavioral analysis orchestrator.

Pipeline for each event:
  1. Behavioral baseline  (new IP, new process, after-hours, privileged user)
  2. Impossible travel    (auth events with GeoIP data)
  3. Attack chain         (brute force, lateral movement, credential stuffing)
  4. Anomaly scoring      (additive weighted score → is_anomaly flag)
"""
from __future__ import annotations

import time

import structlog
from redis.asyncio import Redis

from app.normalization.models import NormalizedEvent
from app.threat_intel.service import EnrichmentResult
from app.ueba.anomaly import AnomalyResult, compute_anomaly
from app.ueba.attack_chain import AttackChainDetector
from app.ueba.baseline import BehavioralBaseline
from app.ueba.impossible_travel import is_impossible_travel

logger = structlog.get_logger(__name__)

UEBAResult = AnomalyResult

# Processes that are common Windows infrastructure — flagging them as
# "new_process_on_host" would produce constant false positives.
_SYSTEM_NOISE_PROCS = {
    "svchost.exe", "ntoskrnl.exe", "lsass.exe", "csrss.exe",
    "wininit.exe", "services.exe", "smss.exe", "winlogon.exe",
    "explorer.exe", "taskhost.exe", "taskhostw.exe", "dwm.exe",
    "conhost.exe", "dllhost.exe", "RuntimeBroker.exe",
    "sihost.exe", "fontdrvhost.exe", "spoolsv.exe",
    "WmiPrvSE.exe", "WmiApSrv.exe", "msdtc.exe",
}


class UEBAService:

    @staticmethod
    async def analyze(
        normalized: NormalizedEvent,
        enrichment: EnrichmentResult | None,
        redis: Redis,
        tenant_id: str,
    ) -> UEBAResult:
        """Run the full UEBA pipeline. Never raises — returns zero-score on error."""
        try:
            return await UEBAService._analyze(normalized, enrichment, redis, tenant_id)
        except Exception as exc:
            logger.warning("ueba_analysis_error", error=str(exc))
            return UEBAResult()

    @staticmethod
    async def _analyze(
        normalized: NormalizedEvent,
        enrichment: EnrichmentResult | None,
        redis: Redis,
        tenant_id: str,
    ) -> UEBAResult:
        enr = enrichment or EnrichmentResult()
        username = normalized.username
        source_ip = normalized.source_ip
        process_name = normalized.process_name
        hostname = normalized.hostname or None
        category = normalized.category

        import datetime as _dt
        ts = normalized.timestamp or _dt.datetime.now(_dt.timezone.utc)
        hour_utc = ts.hour
        is_privileged = normalized.user.is_privileged if normalized.user else False

        # ── 1. Behavioral baseline ─────────────────────────────────────────────
        baseline = BehavioralBaseline(redis, tenant_id)
        bl_flags: list[str] = []
        reasons: dict[str, str] = {}

        bfl = await baseline.evaluate(
            username=username,
            source_ip=source_ip,
            process_name=process_name,
            hostname=hostname,
            hour_utc=hour_utc,
            is_privileged=is_privileged,
        )

        # after_hours: only meaningful when there's a real user performing the action.
        # System/infrastructure events (WMI, scheduled tasks) run at night by design
        # and would generate constant noise if flagged without a user context.
        if bfl.after_hours and username:
            bl_flags.append("after_hours")
            reasons["after_hours"] = (
                f"User '{username}' was active at {ts.strftime('%H:%M')} UTC "
                f"— outside expected business hours (06:00–22:00)"
            )

        if bfl.new_source_ip and username and source_ip:
            bl_flags.append("new_source_ip")
            reasons["new_source_ip"] = (
                f"Source IP {source_ip} has not been seen for user '{username}' "
                f"in the past 30 days"
            )

        # new_process_on_host: skip known Windows infrastructure processes to
        # avoid flagging every system boot/service start as an anomaly.
        if bfl.new_process_on_host and process_name and hostname:
            if process_name.lower() not in {p.lower() for p in _SYSTEM_NOISE_PROCS}:
                bl_flags.append("new_process_on_host")
                reasons["new_process_on_host"] = (
                    f"'{process_name}' has not been seen on host '{hostname}' before"
                )

        if bfl.privileged_user and username:
            bl_flags.append("privileged_user")
            reasons["privileged_user"] = (
                f"User '{username}' authenticated with elevated/privileged credentials"
            )

        # ── 2. Impossible travel (auth + GeoIP only) ───────────────────────────
        if username and enr.geo_latitude and enr.geo_longitude and category == "auth":
            last = await baseline.get_last_location(username)
            curr_ts = ts.timestamp() if hasattr(ts, "timestamp") else time.time()
            if last and is_impossible_travel(
                last["lat"], last["lon"], last["ts"],
                enr.geo_latitude, enr.geo_longitude, curr_ts,
            ):
                bl_flags.append("impossible_travel")
                reasons["impossible_travel"] = (
                    f"User '{username}' logged in from a location "
                    f"({enr.geo_city or enr.geo_country or source_ip}) "
                    f"that is geographically impossible given the time elapsed since "
                    f"their previous session"
                )
            await baseline.set_last_location(username, enr.geo_latitude, enr.geo_longitude)

        # ── 3. Auth success / failure classification ───────────────────────────
        # Use EventID for precise classification instead of fragile substring
        # matching (e.g. tag "logon_failure" incorrectly matched "logon" before).
        _win_eid = str(normalized.raw.get("windows_event_id", ""))
        is_auth_success = category == "auth" and (
            _win_eid in ("4624", "4648")  # Successful logon / logon with explicit credentials
        )
        is_auth_failure = category == "auth" and (
            _win_eid == "4625"  # Failed logon
        )
        # Fall back to tag-based for Linux/non-Windows sources (no EventID)
        if not _win_eid and category == "auth":
            tags_lower = [t.lower() for t in normalized.tags]
            is_auth_success = any(t in tags_lower for t in ("logon_success", "auth_success", "accepted"))
            is_auth_failure = any(t in tags_lower for t in ("logon_failure", "auth_failure", "failed"))

        # ── 4. Attack chain detection ──────────────────────────────────────────
        detector = AttackChainDetector(redis, tenant_id)
        chain_flags = await detector.evaluate(
            category=category,
            username=username,
            source_ip=source_ip,
            hostname=hostname,
            is_auth_success=is_auth_success,
            is_auth_failure=is_auth_failure,
        )

        # Build contextual reasons for attack-chain flags
        if "brute_force" in chain_flags and username:
            reasons["brute_force"] = (
                f"≥5 authentication failures detected for '{username}' within 5 minutes"
            )
        if "brute_force_success" in chain_flags and username:
            reasons["brute_force_success"] = (
                f"Successful login for '{username}' immediately after repeated failures "
                f"— possible credential compromise"
            )
        if "lateral_movement" in chain_flags and username:
            reasons["lateral_movement"] = (
                f"User '{username}' authenticated to 3+ distinct hosts within 10 minutes"
            )
        if "credential_stuffing" in chain_flags and source_ip:
            reasons["credential_stuffing"] = (
                f"IP {source_ip} targeted multiple distinct usernames within 5 minutes"
            )

        # ── 5. Final anomaly score ─────────────────────────────────────────────
        result = compute_anomaly(
            baseline_flags=bl_flags,
            attack_chain_flags=chain_flags,
            is_threat_ip=enr.is_threat_ip,
            reasons=reasons,
        )

        if result.is_anomaly:
            logger.info(
                "ueba_anomaly_detected",
                tenant_id=tenant_id,
                username=username,
                hostname=hostname,
                score=result.anomaly_score,
                flags=result.ueba_flags,
            )

        return result

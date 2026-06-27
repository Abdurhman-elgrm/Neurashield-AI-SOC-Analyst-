"""
Attack Chain Correlator — matches recent alerts against multi-stage attack patterns.

Called from the DetectionWorker after a new alert is committed.
For each built-in chain rule, checks if the new alert + recent alerts on the same
host satisfy the required stages within the chain's time window.

When a chain fires:
  - Acquires an atomic Redis SET NX lock on the cluster fingerprint to prevent races
  - Creates a new Alert with severity=critical and evidence listing all contributing alerts
  - Never raises — failure is logged and silently swallowed so it never blocks the pipeline
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.metrics import ALERTS_CREATED_TOTAL
from app.core.utils import create_task_safe
from app.models.alert import Alert, AlertSeverity, AlertStatus

from .builtin_chains import BUILTIN_CHAINS
from .models import AttackChainRule, ChainMatch

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

# Maximum lookback window across all chains (avoids loading unbounded history)
_MAX_LOOKBACK_SECS = max(c.window_secs for c in BUILTIN_CHAINS)


# ─── Cluster deduplication helpers ───────────────────────────────────────────


def _cluster_fingerprint(alert_ids: list[UUID]) -> str:
    """SHA-256 of sorted alert UUIDs — unique key for this exact cluster."""
    sorted_ids = sorted(str(aid) for aid in alert_ids)
    return hashlib.sha256("|".join(sorted_ids).encode()).hexdigest()[:32]


async def _create_investigation_with_lock(
    lock_key: str,
    ttl_secs: int,
    factory: Callable[[], Awaitable[None]],
) -> bool:
    """
    Acquire a Redis SET NX distributed lock, then call factory() if we won.
    Uses stream Redis for the lock so it is isolated from rate-limiting Redis.
    Returns True if the lock was acquired and factory() was called.
    """
    from app.core.redis import get_stream_redis

    redis = None
    try:
        redis = await get_stream_redis()
        acquired = await redis.set(lock_key, "1", ex=ttl_secs, nx=True)
        if not acquired:
            return False
        try:
            await factory()
        except Exception as factory_exc:
            # factory() failed — release the lock immediately so the next replica
            # can retry rather than waiting for the TTL to expire.
            try:
                await redis.delete(lock_key)
            except Exception:
                pass
            raise factory_exc
        return True
    except Exception as exc:
        logger.warning("chain_lock_failed", lock_key=lock_key, error=str(exc))
        return False


# ─── Public entry point ───────────────────────────────────────────────────────


async def check_attack_chains(
    alert: Alert,
    tenant_id: UUID,
    redis: Redis,
) -> None:
    """
    Non-blocking entry point called from DetectionWorker after alert commit.
    Spawns an isolated task so any failure never blocks the detection pipeline.
    """
    create_task_safe(
        _run_chain_check(alert, tenant_id, redis),
        name=f"chain_check_{alert.id}",
    )


# ─── Core logic ───────────────────────────────────────────────────────────────


async def _run_chain_check(alert: Alert, tenant_id: UUID, redis: Redis) -> None:
    try:
        if not alert.source_host:
            return

        from app.core.database import database_manager

        async with database_manager.session() as db:
            recent = await _load_recent_alerts(db, tenant_id, alert.source_host)

            # Include the triggering alert itself — it may complete a chain
            all_alerts = [alert] + [a for a in recent if a.id != alert.id]

            for chain in BUILTIN_CHAINS:
                match = _try_match_chain(chain, all_alerts)
                if match is None:
                    continue

                # Build a fingerprint from the exact set of contributing alerts so
                # that two concurrent workers processing the same event never create
                # duplicate chain alerts (SET NX is atomic; exists+setex is not).
                fingerprint = _cluster_fingerprint(match.matched_alert_ids)
                lock_key = f"chain_lock:{tenant_id}:{fingerprint}"

                chain_alert_ref: list[Alert] = []

                async def _create_alert(
                    _m: object = match, _r: list[Alert] = chain_alert_ref
                ) -> None:
                    ca = _build_chain_alert(_m, tenant_id)  # type: ignore[arg-type]
                    db.add(ca)
                    await db.flush()
                    await db.commit()
                    ALERTS_CREATED_TOTAL.labels(
                        tenant_id=str(tenant_id),
                        severity=ca.severity.value,
                    ).inc()
                    _r.append(ca)

                fired = await _create_investigation_with_lock(
                    lock_key,
                    chain.window_secs,
                    _create_alert,
                )
                if not fired:
                    continue

                chain_alert = chain_alert_ref[0]
                logger.warning(
                    "attack_chain_fired",
                    chain=chain.name,
                    host=alert.source_host,
                    tenant_id=str(tenant_id),
                    alert_id=str(chain_alert.id),
                    contributing_alerts=len(match.matched_alert_ids),
                )

                # Auto-create an Investigation so analysts have a workspace
                await _auto_create_investigation(db, chain_alert, match, tenant_id)

                # Notify via WebSocket
                _notify_chain_alert(chain_alert, tenant_id)

    except Exception:
        logger.warning("attack_chain_check_failed", alert_id=str(alert.id), exc_info=True)


# ─── Alert loading ────────────────────────────────────────────────────────────


async def _load_recent_alerts(
    db: AsyncSession,
    tenant_id: UUID,
    host: str,
) -> list[Alert]:
    cutoff = datetime.now(tz=UTC) - timedelta(seconds=_MAX_LOOKBACK_SECS)
    result = await db.execute(
        select(Alert)
        .where(
            Alert.tenant_id == tenant_id,
            Alert.source_host == host,
            Alert.created_at >= cutoff,
            Alert.deleted_at.is_(None),
            # Exclude chain alerts themselves — they contain stage keywords in their
            # titles and would cascade-trigger new chains on every chain alert created.
            Alert.title.not_like("[Attack Chain]%"),
        )
        .order_by(Alert.created_at.desc())
        .limit(50)
    )
    return list(result.scalars().all())


# ─── Chain matching ───────────────────────────────────────────────────────────


def _try_match_chain(
    chain: AttackChainRule,
    alerts: list[Alert],
) -> ChainMatch | None:
    """
    Returns a ChainMatch if the alerts satisfy at least chain.min_stages
    required stages within the chain's window, otherwise None.
    """
    now = datetime.now(tz=UTC)
    cutoff = now - timedelta(seconds=chain.window_secs)

    in_window = [a for a in alerts if a.created_at and a.created_at >= cutoff]
    if len(in_window) < chain.min_stages:
        return None

    matched_alert_ids: list[UUID] = []
    matched_stage_names: list[str] = []
    used_alert_ids: set[UUID] = set()

    for stage in chain.stages:
        if not stage.required:
            continue
        for alert in in_window:
            if alert.id in used_alert_ids:
                continue
            if _stage_matches_alert(stage, alert):
                matched_alert_ids.append(alert.id)
                matched_stage_names.append(stage.name)
                used_alert_ids.add(alert.id)
                break

    required_stages = [s for s in chain.stages if s.required]
    if len(matched_stage_names) < min(chain.min_stages, len(required_stages)):
        return None

    return ChainMatch(
        rule=chain,
        matched_alert_ids=matched_alert_ids,
        matched_stage_names=matched_stage_names,
        host=in_window[0].source_host or "",
    )


def _stage_matches_alert(stage: ChainStage, alert: Alert) -> bool:
    title_lower = (alert.title or "").lower()
    for kw in stage.keywords:
        # Support simple regex patterns (for 'multiple.*failed' etc.)
        try:
            if re.search(kw.lower(), title_lower):
                return True
        except re.error:
            if kw.lower() in title_lower:
                return True
    return False


# ─── Alert creation ───────────────────────────────────────────────────────────


def _build_chain_alert(match: ChainMatch, tenant_id: UUID) -> Alert:
    chain = match.rule
    stages_str = " → ".join(match.matched_stage_names)

    sev_map = {
        "critical": AlertSeverity.CRITICAL,
        "high": AlertSeverity.HIGH,
        "medium": AlertSeverity.MEDIUM,
        "low": AlertSeverity.LOW,
    }
    severity = sev_map.get(chain.final_severity, AlertSeverity.CRITICAL)

    return Alert(
        tenant_id=tenant_id,
        status=AlertStatus.OPEN,
        severity=severity,
        title=f"[Attack Chain] {chain.name} on {match.host}",
        description=(
            f"{chain.description}\n\n"
            f"Detected stages: {stages_str}\n"
            f"Correlated from {len(match.matched_alert_ids)} alert(s) "
            f"within a {chain.window_secs // 60}-minute window."
        ),
        source_host=match.host,
        evidence={
            "chain_name": chain.name,
            "matched_stages": match.matched_stage_names,
            "contributing_alerts": [str(aid) for aid in match.matched_alert_ids],
            "window_secs": chain.window_secs,
            "chain_type": "attack_chain",
        },
        mitre_tactics=list(chain.mitre_tactics),
        mitre_techniques=list(chain.mitre_techniques),
        suppression_key=f"chain:{tenant_id}:{match.host}:{chain.name}",
    )


async def _auto_create_investigation(
    db: AsyncSession,
    chain_alert: Alert,
    match: ChainMatch,
    tenant_id: UUID,
) -> None:
    """
    Create an Investigation that analysts can open immediately after a chain fires.
    Uses the chain fingerprint as investigation_group_id to prevent duplicates.
    """
    try:
        from sqlalchemy import select as _select

        from app.models.investigation import Investigation, InvestigationStatus

        group_id = f"chain:{tenant_id}:{_cluster_fingerprint(match.matched_alert_ids)}"

        # Idempotent: skip if an investigation for this fingerprint already exists
        existing = await db.execute(
            _select(Investigation.id)
            .where(
                Investigation.tenant_id == tenant_id,
                Investigation.investigation_group_id == group_id,
            )
            .limit(1)
        )
        if existing.scalar_one_or_none() is not None:
            return

        sev_score = {"critical": 90, "high": 75, "medium": 50, "low": 25}
        threat_score = sev_score.get(chain_alert.severity.value, 75)

        stages_str = " → ".join(match.matched_stage_names)
        inv = Investigation(
            tenant_id=tenant_id,
            investigation_group_id=group_id,
            title=f"[Auto] {match.rule.name} on {match.host}",
            source="auto_chain",
            status=InvestigationStatus.NEW.value,
            threat_score=threat_score,
            confidence="high",
            tp_probability=0.8,
            fp_probability=0.2,
            executive_summary=(
                f"Attack chain '{match.rule.name}' detected on host {match.host}. "
                f"Stages: {stages_str}. "
                f"Correlated from {len(match.matched_alert_ids)} alert(s)."
            ),
            technical_summary=match.rule.description,
            triggering_alert_ids=[str(aid) for aid in match.matched_alert_ids]
            + [str(chain_alert.id)],
            attack_progression=[{"stage": s, "matched": True} for s in match.matched_stage_names],
            recommended_actions=[
                "Isolate affected host immediately",
                "Review LSASS access and credential activity",
                "Check for lateral movement from this host",
                "Escalate to incident response if confirmed",
            ],
        )
        db.add(inv)
        await db.commit()

        logger.info(
            "auto_investigation_created",
            investigation_id=str(inv.id),
            chain=match.rule.name,
            host=match.host,
            tenant_id=str(tenant_id),
        )
    except Exception as exc:
        logger.warning("auto_investigation_failed", error=str(exc), exc_info=True)


def _notify_chain_alert(alert: Alert, tenant_id: UUID) -> None:
    """Fire-and-forget WebSocket notification for chain alerts."""

    async def _publish() -> None:
        try:
            from app.core.redis import TenantRedisClient, redis_manager
            from app.pipeline import stream_names
            from app.realtime.broadcaster import publish_to_tenant_ws
            from app.realtime.events import alert_created_msg

            redis = redis_manager.get_client()
            client = TenantRedisClient(redis, str(tenant_id), "pipeline")
            msg = alert_created_msg(
                str(tenant_id),
                {
                    "alert_id": str(alert.id),
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "source_host": alert.source_host,
                    "status": alert.status.value,
                    "created_at": alert.created_at.isoformat() if alert.created_at else None,
                },
            )
            await publish_to_tenant_ws(client, stream_names.ALERTS_PUBSUB_CHANNEL, msg.to_json())
        except Exception as exc:
            logger.warning(
                "chain_alert_ws_notify_failed",
                alert_id=str(alert.id),
                error=str(exc),
            )

    create_task_safe(_publish(), name=f"chain_ws_notify_{alert.id}")

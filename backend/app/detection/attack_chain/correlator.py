"""
Attack Chain Correlator — matches recent alerts against multi-stage attack patterns.

Called from the DetectionWorker after a new alert is committed.
For each built-in chain rule, checks if the new alert + recent alerts on the same
host satisfy the required stages within the chain's time window.

When a chain fires:
  - Creates a new Alert with severity=critical and evidence listing all contributing alerts
  - Writes a dedup key to Redis (TTL = window_secs) to prevent duplicate chain alerts
  - Never raises — failure is logged and silently swallowed so it never blocks the pipeline
"""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert, AlertSeverity, AlertStatus
from .builtin_chains import BUILTIN_CHAINS
from .models import AttackChainRule, ChainMatch

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

# Maximum lookback window across all chains (avoids loading unbounded history)
_MAX_LOOKBACK_SECS = max(c.window_secs for c in BUILTIN_CHAINS)


# ─── Public entry point ───────────────────────────────────────────────────────

async def check_attack_chains(
    alert: Alert,
    tenant_id: UUID,
    redis: "Redis",
) -> None:
    """
    Non-blocking entry point called from DetectionWorker after alert commit.
    Spawns an isolated task so any failure never blocks the detection pipeline.
    """
    asyncio.create_task(
        _run_chain_check(alert, tenant_id, redis),
        name=f"chain_check_{alert.id}",
    )


# ─── Core logic ───────────────────────────────────────────────────────────────

async def _run_chain_check(alert: Alert, tenant_id: UUID, redis: "Redis") -> None:
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

                dedup_key = _dedup_key(tenant_id, alert.source_host, chain.name)
                already_fired = await redis.exists(dedup_key)
                if already_fired:
                    continue

                chain_alert = _build_chain_alert(match, tenant_id)
                db.add(chain_alert)
                await db.flush()
                await db.commit()

                # Dedup lock — prevents duplicate chain alerts within the window
                await redis.setex(dedup_key, chain.window_secs, "1")

                logger.warning(
                    "attack_chain_fired",
                    chain=chain.name,
                    host=alert.source_host,
                    tenant_id=str(tenant_id),
                    alert_id=str(chain_alert.id),
                    contributing_alerts=len(match.matched_alert_ids),
                )

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
    cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=_MAX_LOOKBACK_SECS)
    result = await db.execute(
        select(Alert)
        .where(
            Alert.tenant_id == tenant_id,
            Alert.source_host == host,
            Alert.created_at >= cutoff,
            Alert.deleted_at.is_(None),
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
    now = datetime.now(tz=timezone.utc)
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


def _stage_matches_alert(stage: "ChainStage", alert: Alert) -> bool:
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
        "high":     AlertSeverity.HIGH,
        "medium":   AlertSeverity.MEDIUM,
        "low":      AlertSeverity.LOW,
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
            "chain_name":          chain.name,
            "matched_stages":      match.matched_stage_names,
            "contributing_alerts": [str(aid) for aid in match.matched_alert_ids],
            "window_secs":         chain.window_secs,
            "chain_type":          "attack_chain",
        },
        mitre_tactics=list(chain.mitre_tactics),
        mitre_techniques=list(chain.mitre_techniques),
        suppression_key=f"chain:{tenant_id}:{match.host}:{chain.name}",
    )


def _dedup_key(tenant_id: UUID, host: str, chain_name: str) -> str:
    safe_chain = chain_name.lower().replace(" ", "_")[:60]
    safe_host  = host.replace(".", "_").replace(":", "_")[:40]
    return f"chain_dedup:{tenant_id}:{safe_host}:{safe_chain}"


def _notify_chain_alert(alert: Alert, tenant_id: UUID) -> None:
    """Fire-and-forget WebSocket notification for chain alerts."""
    async def _publish() -> None:
        try:
            from app.core.redis import TenantRedisClient, redis_manager
            from app.pipeline import stream_names
            from app.realtime.broadcaster import publish_to_tenant_ws
            from app.realtime.events import alert_created_msg

            redis   = redis_manager.get_client()
            client  = TenantRedisClient(redis, str(tenant_id), "pipeline")
            msg     = alert_created_msg(
                str(tenant_id),
                {
                    "alert_id":    str(alert.id),
                    "severity":    alert.severity.value,
                    "title":       alert.title,
                    "source_host": alert.source_host,
                    "status":      alert.status.value,
                    "created_at":  alert.created_at.isoformat() if alert.created_at else None,
                },
            )
            await publish_to_tenant_ws(client, stream_names.ALERTS_PUBSUB_CHANNEL, msg.to_json())
        except Exception:
            pass

    asyncio.create_task(_publish())

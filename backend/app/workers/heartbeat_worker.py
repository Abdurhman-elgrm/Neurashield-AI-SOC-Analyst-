from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import update

from app.core.database import database_manager
from app.models.agent import Agent, AgentStatus

logger = structlog.get_logger(__name__)

# Two-tier offline detection:
#   ONLINE  →  DEGRADED  after 3 min without heartbeat  (brief connectivity loss)
#   DEGRADED → OFFLINE   after 15 min without heartbeat (device truly disconnected)
# Agents that skip directly to 15+ min without ever going DEGRADED are also caught.
DEGRADED_THRESHOLD_SECS = 3 * 60    # 3 min
OFFLINE_THRESHOLD_SECS  = 15 * 60   # 15 min
CHECK_INTERVAL_SECS     = 30


class HeartbeatWorker:
    """
    Periodically transitions agent status based on heartbeat staleness.

    ONLINE  → DEGRADED : no heartbeat for 3–15 min  (brief connectivity issue)
    DEGRADED → OFFLINE : no heartbeat for 15+ min   (device truly unreachable)

    Email notification fires only on the OFFLINE transition to avoid alert fatigue
    from short network interruptions (sleep/wake cycles, DHCP renewal, etc.).
    """

    async def run(self, stop_event: asyncio.Event) -> None:
        logger.info(
            "heartbeat_worker_started",
            degraded_threshold_secs=DEGRADED_THRESHOLD_SECS,
            offline_threshold_secs=OFFLINE_THRESHOLD_SECS,
        )
        while not stop_event.is_set():
            try:
                await self._check_agent_status()
            except Exception as exc:
                logger.error("heartbeat_check_error", error=str(exc), exc_info=True)

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=CHECK_INTERVAL_SECS)
            except asyncio.TimeoutError:
                pass

        logger.info("heartbeat_worker_stopped")

    async def _check_agent_status(self) -> None:
        now             = datetime.now(tz=timezone.utc)
        degraded_cutoff = now - timedelta(seconds=DEGRADED_THRESHOLD_SECS)
        offline_cutoff  = now - timedelta(seconds=OFFLINE_THRESHOLD_SECS)

        async with database_manager.session() as db:
            # ── Step 1: ONLINE → DEGRADED (3–15 min gap) ─────────────────────
            await db.execute(
                update(Agent)
                .where(
                    Agent.status == AgentStatus.ONLINE,
                    Agent.last_seen_at < degraded_cutoff,
                    Agent.last_seen_at >= offline_cutoff,
                    Agent.deleted_at.is_(None),
                )
                .values(status=AgentStatus.DEGRADED)
            )

            # ── Step 2: ONLINE or DEGRADED → OFFLINE (15+ min gap) ───────────
            # Catches both: agents that went through DEGRADED and agents that
            # jumped from ONLINE to a long outage in a single check window.
            result = await db.execute(
                update(Agent)
                .where(
                    Agent.status.in_([AgentStatus.ONLINE, AgentStatus.DEGRADED]),
                    Agent.last_seen_at < offline_cutoff,
                    Agent.deleted_at.is_(None),
                )
                .values(status=AgentStatus.OFFLINE)
                .returning(Agent.id, Agent.hostname, Agent.tenant_id, Agent.last_seen_at)
            )
            rows = result.fetchall()

            # Commit both steps atomically
            await db.commit()

        # Email notifications fire outside the DB session (non-blocking)
        if rows:
            from app.services.notification_service import notify_agent_offline_email
            for row in rows:
                logger.info(
                    "agent_marked_offline",
                    agent_id=str(row.id),
                    hostname=row.hostname,
                    tenant_id=str(row.tenant_id),
                )
                last_seen = (
                    row.last_seen_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                    if row.last_seen_at
                    else "Unknown"
                )
                asyncio.create_task(notify_agent_offline_email(
                    agent_id=str(row.id),
                    hostname=row.hostname or "Unknown",
                    tenant_id=row.tenant_id,
                    last_seen=last_seen,
                ))

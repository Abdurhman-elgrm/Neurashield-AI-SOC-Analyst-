from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import select, update

from app.core.database import database_manager
from app.models.agent import Agent, AgentStatus

logger = structlog.get_logger(__name__)

# How long without a heartbeat before marking offline
OFFLINE_THRESHOLD_SECS = 120
# Polling interval for the check
CHECK_INTERVAL_SECS = 30


class HeartbeatWorker:
    """
    Periodically marks agents as OFFLINE when they haven't sent
    a heartbeat within OFFLINE_THRESHOLD_SECS.
    """

    async def run(self, stop_event: asyncio.Event) -> None:
        logger.info("heartbeat_worker_started", threshold_secs=OFFLINE_THRESHOLD_SECS)
        while not stop_event.is_set():
            try:
                await self._check_offline_agents()
            except Exception as exc:
                logger.error("heartbeat_check_error", error=str(exc), exc_info=True)

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=CHECK_INTERVAL_SECS)
            except asyncio.TimeoutError:
                pass

        logger.info("heartbeat_worker_stopped")

    async def _check_offline_agents(self) -> None:
        cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=OFFLINE_THRESHOLD_SECS)

        async with database_manager.session() as db:
            result = await db.execute(
                update(Agent)
                .where(
                    Agent.status == AgentStatus.ONLINE,
                    Agent.last_seen_at < cutoff,
                    Agent.deleted_at.is_(None),
                )
                .values(status=AgentStatus.OFFLINE)
                .returning(Agent.id, Agent.hostname, Agent.tenant_id)
            )
            rows = result.fetchall()
            if rows:
                await db.commit()
                for row in rows:
                    logger.info(
                        "agent_marked_offline",
                        agent_id=str(row.id),
                        hostname=row.hostname,
                        tenant_id=str(row.tenant_id),
                    )

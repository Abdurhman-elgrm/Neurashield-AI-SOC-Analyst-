"""
Baseline snapshot worker.

Periodically snapshots UEBA baselines (seen IPs, seen processes) from Redis
to the DB.  On startup, also restores baselines from DB for any tenant whose
Redis keys are missing (e.g. after a pod restart).

One global instance — covers all active tenants.
"""

from __future__ import annotations

import asyncio
import os

import structlog

from app.core.database import database_manager
from app.core.redis import redis_manager

logger = structlog.get_logger(__name__)

_SNAPSHOT_INTERVAL_SECS = int(os.getenv("UEBA_BASELINE_SNAPSHOT_INTERVAL_SECS", "3600"))  # 1 hour


class BaselineSnapshotWorker:
    async def run(self, stop_event: asyncio.Event) -> None:
        logger.info("baseline_snapshot_worker_started", interval_secs=_SNAPSHOT_INTERVAL_SECS)

        # Restore baselines on startup (warm Redis from DB after pod restart)
        await self._restore_all()

        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=_SNAPSHOT_INTERVAL_SECS)
            except TimeoutError:
                pass

            if stop_event.is_set():
                break

            await self._snapshot_all()

        logger.info("baseline_snapshot_worker_stopped")

    async def _load_tenant_ids(self) -> list[str]:
        from sqlalchemy import select

        from app.models.tenant import Tenant

        async with database_manager.session() as db:
            result = await db.execute(
                select(Tenant.id).where(
                    Tenant.is_active.is_(True),
                    Tenant.deleted_at.is_(None),
                )
            )
            return [str(row[0]) for row in result.fetchall()]

    async def _restore_all(self) -> None:
        try:
            tenant_ids = await self._load_tenant_ids()
            redis = redis_manager.get_client()
            from app.ueba.baseline_persistence import BaselinePersistenceService

            async with database_manager.session() as db:
                for tid in tenant_ids:
                    svc = BaselinePersistenceService(tid, redis)
                    await svc.restore(db)
            logger.info("baseline_restore_all_complete", tenant_count=len(tenant_ids))
        except Exception as exc:
            logger.error("baseline_restore_all_failed", error=str(exc), exc_info=True)

    async def _snapshot_all(self) -> None:
        try:
            tenant_ids = await self._load_tenant_ids()
            redis = redis_manager.get_client()
            from app.ueba.baseline_persistence import BaselinePersistenceService

            async with database_manager.session() as db:
                for tid in tenant_ids:
                    svc = BaselinePersistenceService(tid, redis)
                    await svc.snapshot(db)
            logger.info("baseline_snapshot_all_complete", tenant_count=len(tenant_ids))
        except Exception as exc:
            logger.error("baseline_snapshot_all_failed", error=str(exc), exc_info=True)

"""
Data Retention Worker — enforces per-tenant event and alert retention policies.

Runs every hour. For each active tenant, deletes events/alerts older than the
tenant's configured retention window.
Uses chunked deletes to avoid long-running transactions and lock contention.
"""
from __future__ import annotations

import asyncio

import structlog
from sqlalchemy import text

from app.core.database import database_manager

logger = structlog.get_logger(__name__)

_SWEEP_INTERVAL_SECS = 3600   # 1 hour between sweeps
_DELETE_CHUNK_SIZE   = 5_000  # rows deleted per statement


class DataRetentionWorker:

    async def run(self, stop_event: asyncio.Event) -> None:
        logger.info("retention_worker_started")
        while not stop_event.is_set():
            try:
                await self._sweep()
            except Exception:
                logger.warning("retention_sweep_failed", exc_info=True)

            try:
                await asyncio.wait_for(
                    asyncio.shield(stop_event.wait()),
                    timeout=_SWEEP_INTERVAL_SECS,
                )
            except asyncio.TimeoutError:
                pass  # normal — continue to next sweep

    async def _sweep(self) -> None:
        async with database_manager.session() as db:
            result = await db.execute(text("""
                SELECT id::text, event_retention_days, alert_retention_days
                FROM tenants
                WHERE is_active = TRUE AND deleted_at IS NULL
            """))
            tenants = result.fetchall()

        for row in tenants:
            tenant_id = str(row[0])
            event_days = int(row[1])
            alert_days = int(row[2])

            try:
                events_deleted = await self._delete_old_events(tenant_id, event_days)
                alerts_deleted = await self._delete_old_alerts(tenant_id, alert_days)
                if events_deleted > 0 or alerts_deleted > 0:
                    logger.info(
                        "retention_sweep_done",
                        tenant_id=tenant_id,
                        events_deleted=events_deleted,
                        alerts_deleted=alerts_deleted,
                    )
            except Exception:
                logger.warning("retention_sweep_tenant_failed", tenant_id=tenant_id, exc_info=True)

    async def _delete_old_events(self, tenant_id: str, retention_days: int) -> int:
        total = 0
        while True:
            async with database_manager.session() as db:
                # Use string interpolation for INTERVAL — retention_days is an int from DB,
                # not user-controlled input, so this is safe.
                result = await db.execute(text(f"""
                    DELETE FROM events
                    WHERE id IN (
                        SELECT id FROM events
                        WHERE tenant_id = :tid
                          AND event_timestamp < NOW() - INTERVAL '{retention_days} days'
                        LIMIT {_DELETE_CHUNK_SIZE}
                    )
                """).bindparams(tid=tenant_id))
                deleted = result.rowcount or 0
                await db.commit()

            if deleted == 0:
                break
            total += deleted
            await asyncio.sleep(0.05)  # yield between chunks to reduce lock contention

        return total

    async def _delete_old_alerts(self, tenant_id: str, retention_days: int) -> int:
        total = 0
        while True:
            async with database_manager.session() as db:
                result = await db.execute(text(f"""
                    DELETE FROM alerts
                    WHERE id IN (
                        SELECT id FROM alerts
                        WHERE tenant_id = :tid
                          AND created_at < NOW() - INTERVAL '{retention_days} days'
                          AND status IN ('closed', 'false_positive')
                        LIMIT {_DELETE_CHUNK_SIZE}
                    )
                """).bindparams(tid=tenant_id))
                deleted = result.rowcount or 0
                await db.commit()

            if deleted == 0:
                break
            total += deleted
            await asyncio.sleep(0.05)

        return total

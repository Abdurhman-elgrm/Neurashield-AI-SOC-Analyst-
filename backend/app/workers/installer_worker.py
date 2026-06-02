"""
Installer Token Expiry Worker

Periodically bulk-marks PENDING installer tokens whose expires_at has passed
as EXPIRED.  Without this worker, the status column stays stale — tokens past
their TTL would show as "pending" in the UI and in list queries even though
the is_expired property would block their use.

The sweep is intentionally cheap: a single UPDATE ... WHERE with a partial index
(idx_installer_token_pending_expires) is used so it only scans PENDING rows.
"""
from __future__ import annotations

import asyncio

import structlog

from app.core.database import database_manager
from app.services.installer_service import InstallerService

logger = structlog.get_logger(__name__)

# How often to run the expiry sweep
SWEEP_INTERVAL_SECS = 120  # every 2 minutes is more than enough for 1-hour TTL tokens


class InstallerTokenWorker:
    """
    Single-instance global worker — one sweep touches all tenants because
    InstallerService.expire_old_tokens() does a cross-tenant bulk UPDATE.
    """

    async def run(self, stop_event: asyncio.Event) -> None:
        logger.info("installer_token_worker_started", interval_secs=SWEEP_INTERVAL_SECS)
        while not stop_event.is_set():
            try:
                await self._sweep()
            except Exception as exc:
                logger.error("installer_token_sweep_error", error=str(exc), exc_info=True)

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=SWEEP_INTERVAL_SECS)
            except asyncio.TimeoutError:
                pass

        logger.info("installer_token_worker_stopped")

    async def _sweep(self) -> None:
        async with database_manager.session() as db:
            count = await InstallerService.expire_old_tokens(db)
            if count > 0:
                await db.commit()
                logger.info("installer_tokens_expired_by_sweep", count=count)

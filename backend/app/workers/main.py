"""
Worker entrypoint.  Run with:
  python -m app.workers.main

Starts normalization workers, detection workers, and the heartbeat monitor
for all active tenants.  Uses graceful shutdown via SIGINT/SIGTERM.
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket

import structlog

from app.core.config import settings
from app.core.database import database_manager
from app.core.logging import configure_logging
from app.core.redis import redis_manager
from app.pipeline import stream_names
from app.pipeline.publisher import StreamPublisher
from app.core.redis import TenantRedisClient
from app.workers.normalization_worker import NormalizationWorker
from app.workers.detection_worker import DetectionWorker
from app.workers.correlation_worker import CorrelationWorker
from app.workers.investigation_worker import InvestigationWorker
from app.workers.heartbeat_worker import HeartbeatWorker
from app.workers.installer_worker import InstallerTokenWorker
from app.workers.realtime_worker import RealtimeWorker
from app.realtime.broadcast import RealtimeListener

logger = structlog.get_logger(__name__)

# Worker consumer identity (unique per process/pod)
_WORKER_ID = f"{socket.gethostname()}-{os.getpid()}"


async def _load_active_tenant_ids() -> list[str]:
    """Returns tenant IDs that have at least one active, non-deleted tenant."""
    from sqlalchemy import select, text
    from app.models.tenant import Tenant

    async with database_manager.session() as db:
        result = await db.execute(
            select(Tenant.id).where(
                Tenant.is_active.is_(True),
                Tenant.deleted_at.is_(None),
            )
        )
        return [str(row.id) for row in result.fetchall()]


async def _ensure_streams(tenant_ids: list[str]) -> None:
    redis = redis_manager.get_client()
    for tid in tenant_ids:
        client = TenantRedisClient(redis, tid, stream_names.SUBSYSTEM)
        publisher = StreamPublisher(client)
        await publisher.ensure_consumer_groups()
    logger.info("consumer_groups_initialized", tenant_count=len(tenant_ids))


async def main() -> None:
    configure_logging(settings.LOG_LEVEL, settings.ENVIRONMENT)
    logger.info("worker_starting", worker_id=_WORKER_ID)

    await database_manager.initialize()
    await redis_manager.initialize()

    stop_event = asyncio.Event()

    def _shutdown(sig: int) -> None:
        logger.info("worker_shutdown_signal_received", signal=sig)
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: _shutdown(s))

    tenant_ids = await _load_active_tenant_ids()
    logger.info("tenants_discovered", count=len(tenant_ids))

    await _ensure_streams(tenant_ids)

    tasks: list[asyncio.Task] = []

    # One normalization + detection + correlation + investigation worker per tenant
    for tid in tenant_ids:
        norm_worker  = NormalizationWorker(tid, f"norm-{_WORKER_ID}")
        det_worker   = DetectionWorker(tid, f"detect-{_WORKER_ID}")
        corr_worker  = CorrelationWorker(tid, f"corr-{_WORKER_ID}")
        inv_worker   = InvestigationWorker(tid, f"inv-{_WORKER_ID}")
        rt_worker    = RealtimeWorker(tid, f"rt-{_WORKER_ID}")
        tasks.append(asyncio.create_task(norm_worker.run(stop_event), name=f"norm-{tid}"))
        tasks.append(asyncio.create_task(det_worker.run(stop_event), name=f"detect-{tid}"))
        tasks.append(asyncio.create_task(corr_worker.run(stop_event), name=f"corr-{tid}"))
        tasks.append(asyncio.create_task(inv_worker.run(stop_event), name=f"inv-{tid}"))
        tasks.append(asyncio.create_task(rt_worker.run(stop_event), name=f"realtime-{tid}"))

    # One heartbeat monitor (global)
    hb_worker = HeartbeatWorker()
    tasks.append(asyncio.create_task(hb_worker.run(stop_event), name="heartbeat"))

    # Installer token expiry sweep (global, single instance)
    installer_worker = InstallerTokenWorker()
    tasks.append(asyncio.create_task(installer_worker.run(stop_event), name="installer-expiry"))

    # Realtime Redis pub/sub listener (global, one per process)
    rt_listener = RealtimeListener(redis_manager.get_client())
    tasks.append(asyncio.create_task(rt_listener.run(), name="realtime-listener"))

    logger.info("worker_ready", task_count=len(tasks))

    await stop_event.wait()

    logger.info("worker_draining_tasks")
    for task in tasks:
        task.cancel()

    await asyncio.gather(*tasks, return_exceptions=True)

    await redis_manager.close()
    await database_manager.close()
    logger.info("worker_shutdown_complete")


if __name__ == "__main__":
    asyncio.run(main())

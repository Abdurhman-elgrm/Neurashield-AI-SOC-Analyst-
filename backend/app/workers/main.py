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


async def _tenant_hot_reload(
    existing_tenant_ids: set[str],
    worker_registry: dict[str, bool],
    stop_event: asyncio.Event,
) -> None:
    """Check for new tenants every 5 minutes and spin up workers."""
    while not stop_event.is_set():
        await asyncio.sleep(300)
        if stop_event.is_set():
            break
        try:
            async with database_manager.session() as db:
                from app.models.tenant import Tenant
                from sqlalchemy import select
                result = await db.execute(
                    select(Tenant.id).where(
                        Tenant.is_active.is_(True),
                        Tenant.deleted_at.is_(None),
                    )
                )
                current_ids = {str(row[0]) for row in result.fetchall()}
                new_ids = current_ids - existing_tenant_ids

            for tenant_id in new_ids:
                logger.info("new_tenant_detected_spinning_up_workers", tenant_id=tenant_id)
                redis = redis_manager.get_client()
                client = TenantRedisClient(redis, tenant_id, stream_names.SUBSYSTEM)
                publisher = StreamPublisher(client)
                await publisher.ensure_consumer_groups()

                norm_worker = NormalizationWorker(tenant_id, f"norm-{_WORKER_ID}")
                det_worker  = DetectionWorker(tenant_id, f"detect-{_WORKER_ID}")
                corr_worker = CorrelationWorker(tenant_id, f"corr-{_WORKER_ID}")
                inv_worker  = InvestigationWorker(tenant_id, f"inv-{_WORKER_ID}")
                rt_worker   = RealtimeWorker(tenant_id, f"rt-{_WORKER_ID}")

                asyncio.create_task(norm_worker.run(stop_event), name=f"norm-{tenant_id}")
                asyncio.create_task(det_worker.run(stop_event), name=f"detect-{tenant_id}")
                asyncio.create_task(corr_worker.run(stop_event), name=f"corr-{tenant_id}")
                asyncio.create_task(inv_worker.run(stop_event), name=f"inv-{tenant_id}")
                asyncio.create_task(rt_worker.run(stop_event), name=f"realtime-{tenant_id}")

                existing_tenant_ids.add(tenant_id)
                worker_registry[tenant_id] = True
                logger.info("new_tenant_workers_started", tenant_id=tenant_id)
        except Exception:
            logger.warning("tenant_hot_reload_failed", exc_info=True)


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

    tenant_ids_set: set[str] = set(tenant_ids)
    worker_registry: dict[str, bool] = {}

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
        worker_registry[tid] = True

    # One heartbeat monitor (global)
    hb_worker = HeartbeatWorker()
    tasks.append(asyncio.create_task(hb_worker.run(stop_event), name="heartbeat"))

    # Installer token expiry sweep (global, single instance)
    installer_worker = InstallerTokenWorker()
    tasks.append(asyncio.create_task(installer_worker.run(stop_event), name="installer-expiry"))

    # Realtime Redis pub/sub listener (global, one per process)
    rt_listener = RealtimeListener(redis_manager.get_client())
    tasks.append(asyncio.create_task(rt_listener.run(), name="realtime-listener"))

    # Hot-reload: spin up workers for tenants that join after startup
    tasks.append(asyncio.create_task(
        _tenant_hot_reload(tenant_ids_set, worker_registry, stop_event),
        name="tenant-hot-reload",
    ))

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

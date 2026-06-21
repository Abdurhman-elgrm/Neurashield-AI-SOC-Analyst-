from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import database_manager, get_db
from app.core.redis import redis_manager

router = APIRouter(tags=["Health"])


@router.get("/health", include_in_schema=False)
async def liveness() -> JSONResponse:
    """
    Liveness probe — returns 200 if the process is alive.
    Used by container orchestrators to determine if the container should be restarted.
    No dependency checks — if this responds, the process is up.
    """
    return JSONResponse(
        status_code=200,
        content={"status": "alive", "version": settings.APP_VERSION},
    )


@router.get("/health/ready", include_in_schema=False)
async def readiness() -> JSONResponse:
    """
    Readiness probe — returns 200 only if all dependencies are healthy.
    Used by load balancers to remove unhealthy instances from rotation.
    Fails during startup, DB migrations, or dependency outages.
    """
    checks: dict[str, str | bool] = {}
    all_healthy = True

    db_ok = await database_manager.check_health()
    checks["database"] = db_ok
    if not db_ok:
        all_healthy = False

    redis_ok = await redis_manager.check_health()
    checks["redis"] = redis_ok
    if not redis_ok:
        all_healthy = False

    # Worker liveness — True if the worker process has pinged Redis in the last 120 s.
    # False means the Railway Worker service is down; events pile up in Redis unprocessed.
    worker_ok = False
    if redis_ok:
        try:
            from app.workers.main import WORKER_LIVENESS_KEY
            worker_ok = bool(await redis_manager.get_client().exists(WORKER_LIVENESS_KEY))
        except Exception:
            pass
    checks["worker"] = worker_ok

    status_code = 200 if all_healthy else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ready" if all_healthy else "unavailable",
            "checks": checks,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
        },
    )


@router.get("/health/db", include_in_schema=False)
async def db_schema_check(db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """
    Debug endpoint — lists all public tables in the database.
    Useful for verifying migrations ran correctly on Railway.
    """
    try:
        from sqlalchemy import text
        result = await db.execute(text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' ORDER BY table_name"
        ))
        tables = [row[0] for row in result.fetchall()]
        return JSONResponse(
            status_code=200,
            content={
                "status": "ok",
                "table_count": len(tables),
                "tables": tables,
            },
        )
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "error": str(exc)},
        )

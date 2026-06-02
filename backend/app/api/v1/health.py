from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.database import database_manager
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

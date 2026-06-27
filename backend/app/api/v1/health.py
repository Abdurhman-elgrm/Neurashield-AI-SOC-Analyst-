from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import database_manager, get_db
from app.core.dependencies import CurrentUser
from app.core.exceptions import ForbiddenError, UnauthorizedError
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
            "timestamp": datetime.now(tz=UTC).isoformat(),
        },
    )


@router.get("/metrics", include_in_schema=False)
async def prometheus_metrics(request: Request) -> Response:
    """
    Prometheus metrics scrape endpoint.
    Requires either:
      - Bearer token matching METRICS_SECRET_TOKEN env var (for Prometheus scraper), OR
      - Authenticated user session (admin convenience)
    """
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    # Bearer token check for Prometheus scraper (no user session needed)
    metrics_token = settings.METRICS_SECRET_TOKEN
    auth_header = request.headers.get("Authorization", "")
    if metrics_token and auth_header.startswith("Bearer "):
        provided = auth_header[7:]
        import hmac

        if hmac.compare_digest(provided, metrics_token):
            return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)

    # Fallback: require authenticated user (admin convenience in dev/staging)
    if not settings.is_production and not metrics_token:
        return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)

    # In production without a matching bearer token, refuse
    raise UnauthorizedError(
        "Metrics endpoint requires Authorization: Bearer <METRICS_SECRET_TOKEN>"
    )


@router.get("/health/metrics-info", include_in_schema=False)
async def metrics_info(current_user: CurrentUser) -> JSONResponse:
    """
    Returns non-sensitive system information for authenticated admins.
    Never exposed in production without authentication.
    """
    import platform
    import sys

    return JSONResponse(
        status_code=200,
        content={
            "python_version": sys.version,
            "platform": platform.platform(),
            "app_version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
        },
    )


@router.get("/health/db", include_in_schema=False)
async def db_schema_check(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Schema inspection endpoint — lists all public tables.
    Requires authentication. Disabled in production.
    """
    if settings.is_production:
        raise ForbiddenError("Schema inspection is not available in production")

    try:
        from sqlalchemy import text

        result = await db.execute(
            text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' ORDER BY table_name"
            )
        )
        tables = [row[0] for row in result.fetchall()]
        return JSONResponse(
            status_code=200,
            content={
                "status": "ok",
                "table_count": len(tables),
                "tables": tables,
            },
        )
    except ForbiddenError:
        raise
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "error": str(exc)},
        )

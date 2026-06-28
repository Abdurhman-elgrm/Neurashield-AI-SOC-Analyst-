from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings

# ── Sentry — initialised once at module load, before any FastAPI wiring ────────
# No-ops silently when SENTRY_DSN is empty so development stays unaffected.
if settings.SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.asyncio import AsyncioIntegration
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    from sentry_sdk.integrations.httpx import HttpxIntegration
    from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
    from sentry_sdk.integrations.starlette import StarletteIntegration

    sentry_sdk.init(
        dsn=settings.SENTRY_DSN,
        environment=settings.ENVIRONMENT,
        release=settings.APP_VERSION,
        traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
        profiles_sample_rate=settings.SENTRY_PROFILES_SAMPLE_RATE,
        integrations=[
            StarletteIntegration(transaction_style="url"),
            FastApiIntegration(transaction_style="url"),
            SqlalchemyIntegration(),
            AsyncioIntegration(),
            HttpxIntegration(),
        ],
        # Never send PII (email, IP, user-agent) to Sentry
        send_default_pii=False,
    )
from app.core.database import database_manager
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import (
    ContentLengthLimitMiddleware,
    PrometheusMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.redis import redis_manager

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    configure_logging(
        log_level=settings.LOG_LEVEL,
        environment=settings.ENVIRONMENT,
    )
    logger.info(
        "application_starting",
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
    )

    # Set Prometheus build info once at startup.
    from app.core.metrics import BUILD_INFO

    BUILD_INFO.info({"version": settings.APP_VERSION, "environment": settings.ENVIRONMENT})

    # ── Run Alembic migrations on every startup ────────────────────────────
    # Safe: alembic upgrade head is idempotent — no-op when schema is current.
    # Runs in a thread executor so the async event loop is not blocked.
    import asyncio
    import os

    from alembic import command as alembic_command
    from alembic.config import Config

    logger.info("running_database_migrations")
    try:
        _ini_path = os.path.join(os.path.dirname(__file__), "..", "alembic.ini")
        _alembic_cfg = Config(os.path.normpath(_ini_path))
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: alembic_command.upgrade(_alembic_cfg, "head"),
        )
        logger.info("database_migrations_complete")
    except Exception as migration_err:
        logger.error(
            "database_migration_failed",
            error=str(migration_err),
            error_type=type(migration_err).__name__,
        )
        # A failed migration means the DB schema is in an unknown state.
        # Starting the app would risk data corruption or silent API errors,
        # so we abort startup here to surface the failure immediately.
        raise
    # ──────────────────────────────────────────────────────────────────────

    await database_manager.initialize()

    # ── Auto-ingest RAG knowledge base if empty ────────────────────────────
    async def _maybe_ingest_rag() -> None:
        async with database_manager.session() as db:
            from sqlalchemy import func, select

            from app.ai.rag import ingest_all
            from app.models.rag_chunk import RAGChunk

            count_result = await db.execute(select(func.count()).select_from(RAGChunk))
            count = count_result.scalar() or 0
            if count < 100:
                logger.info("rag_ingestion_starting", existing_chunks=count)
                results = await ingest_all(db)
                logger.info("rag_ingestion_complete", results=results)
            else:
                logger.info("rag_already_populated", chunk_count=count)

    from app.core.utils import create_task_safe

    create_task_safe(_maybe_ingest_rag(), name="startup_rag_ingest")
    # ──────────────────────────────────────────────────────────────────────

    # ── Seed system playbook templates ────────────────────────────────────
    async def _seed_playbooks() -> None:
        try:
            async with database_manager.session() as db:
                from app.services.playbook_seed import seed_system_playbook_templates

                await seed_system_playbook_templates(db)
        except Exception:
            logger.warning("playbook_seed_failed", exc_info=True)

    create_task_safe(_seed_playbooks(), name="startup_playbook_seed")
    # ──────────────────────────────────────────────────────────────────────

    # Redis is optional — rate limiting degrades gracefully when unavailable.
    # A missing or unreachable Redis must never prevent the app from starting.
    try:
        await redis_manager.initialize()
    except Exception as redis_exc:
        logger.warning(
            "redis_unavailable_at_startup",
            error=str(redis_exc),
            detail="Rate limiting and session features will be skipped until Redis is reachable.",
        )

    try:
        from app.core.redis import initialize_stream_redis

        await initialize_stream_redis()
        logger.info("stream_redis_ready")
    except Exception as stream_exc:
        logger.warning("stream_redis_unavailable", error=str(stream_exc))

    logger.info("application_ready")
    yield

    logger.info("application_shutting_down")
    await redis_manager.close()
    await database_manager.close()
    logger.info("application_shutdown_complete")


def create_application() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Enterprise SOC SaaS Platform API",
        # Disable docs in production
        docs_url="/api/docs" if not settings.is_production else None,
        redoc_url="/api/redoc" if not settings.is_production else None,
        openapi_url="/api/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ─── Exception handlers (registered before middleware so they are wrapped) ──
    register_exception_handlers(app)

    # ─── Middleware (LAST add_middleware call = OUTERMOST layer) ─────────────
    # Stack order (innermost → outermost at request time):
    #   SecurityHeaders → RequestContext → CORS
    # SecurityHeadersMiddleware is registered first so it sits INSIDE the CORS
    # layer; its headers are added to every response including error responses.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)
    # Reject oversized payloads before they reach application code.
    app.add_middleware(ContentLengthLimitMiddleware, max_bytes=10 * 1024 * 1024)
    # Prometheus RED metrics — registered last (outermost) to capture full latency.
    app.add_middleware(PrometheusMiddleware)

    origins = settings.ALLOWED_ORIGINS
    use_wildcard = origins == ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        # Accept any Railway deployment automatically (no Variables needed).
        allow_origin_regex=settings.CORS_ALLOW_ORIGIN_REGEX or None,
        # Wildcard origin cannot be combined with allow_credentials=True.
        allow_credentials=not use_wildcard,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Tenant-ID",
            "X-Request-ID",
            "X-Idempotency-Key",
            "Accept",
            "Accept-Language",
            "Cache-Control",
        ],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    )

    # ─── Routes ───────────────────────────────────────────────────────────────
    from app.api.v1.router import api_router

    app.include_router(api_router, prefix=settings.API_PREFIX)

    return app


app = create_application()

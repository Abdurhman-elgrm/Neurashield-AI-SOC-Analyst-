from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import database_manager
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware
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

    # ── Run Alembic migrations on every startup ────────────────────────────
    # Safe: alembic upgrade head is idempotent — no-op when schema is current.
    # Runs in a thread executor so the async event loop is not blocked.
    import asyncio
    import os
    from alembic.config import Config
    from alembic import command as alembic_command

    logger.info("running_database_migrations")
    try:
        _ini_path = os.path.join(os.path.dirname(__file__), "..", "alembic.ini")
        _alembic_cfg = Config(os.path.normpath(_ini_path))
        loop = asyncio.get_event_loop()
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
    # ──────────────────────────────────────────────────────────────────────

    await database_manager.initialize()

    # ── Auto-ingest RAG knowledge base if empty ────────────────────────────
    async def _maybe_ingest_rag() -> None:
        async with database_manager.session() as db:
            from app.ai.rag import ingest_all
            from sqlalchemy import select, func
            from app.models.rag_chunk import RAGChunk
            count_result = await db.execute(select(func.count()).select_from(RAGChunk))
            count = count_result.scalar() or 0
            if count < 100:
                logger.info("rag_ingestion_starting", existing_chunks=count)
                results = await ingest_all(db)
                logger.info("rag_ingestion_complete", results=results)
            else:
                logger.info("rag_already_populated", chunk_count=count)

    asyncio.create_task(_maybe_ingest_rag())
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
    # RequestContextMiddleware is registered first → sits INSIDE CORSMiddleware.
    # CORSMiddleware is registered last → OUTERMOST, so it adds CORS headers to
    # ALL responses including those produced by exception handlers.
    app.add_middleware(RequestContextMiddleware)

    origins = settings.ALLOWED_ORIGINS
    use_wildcard = origins == ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        # Accept any Railway deployment automatically (no Variables needed).
        allow_origin_regex=settings.CORS_ALLOW_ORIGIN_REGEX or None,
        # Wildcard origin cannot be combined with allow_credentials=True.
        allow_credentials=not use_wildcard,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    )

    # ─── Routes ───────────────────────────────────────────────────────────────
    from app.api.v1.router import api_router
    app.include_router(api_router, prefix=settings.API_PREFIX)

    return app


app = create_application()

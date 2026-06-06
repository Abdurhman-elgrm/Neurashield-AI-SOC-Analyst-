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

    await database_manager.initialize()
    await redis_manager.initialize()

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

    # ─── Middleware (order matters — first registered = outermost) ────────────
    # Use wildcard origins when ALLOWED_ORIGINS contains "*", otherwise use the
    # explicit list.  With wildcard we cannot send credentials, so set
    # allow_credentials=False to avoid a browser CORS error.
    origins = settings.ALLOWED_ORIGINS
    use_wildcard = origins == ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        # Also accept any Railway deployment automatically via regex.
        # Falls back to no regex if CORS_ALLOW_ORIGIN_REGEX is empty string.
        allow_origin_regex=settings.CORS_ALLOW_ORIGIN_REGEX or None,
        allow_credentials=not use_wildcard,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    )
    # RequestContextMiddleware must be inside CORS so it runs on every request
    app.add_middleware(RequestContextMiddleware)

    # ─── Routes ───────────────────────────────────────────────────────────────
    from app.api.v1.router import api_router
    app.include_router(api_router, prefix=settings.API_PREFIX)

    # ─── Exception handlers ───────────────────────────────────────────────────
    register_exception_handlers(app)

    return app


app = create_application()

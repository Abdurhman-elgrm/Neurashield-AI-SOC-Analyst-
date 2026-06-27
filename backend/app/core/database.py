from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

logger = structlog.get_logger(__name__)


class DatabaseManager:
    """
    Manages the async SQLAlchemy engine and session factory lifecycle.
    Initialized once at application startup, cleaned up on shutdown.
    """

    _engine: AsyncEngine | None = None
    _session_factory: async_sessionmaker[AsyncSession] | None = None

    async def initialize(self) -> None:
        connect_args: dict[str, Any] = {}
        if settings.is_production:
            connect_args["ssl"] = "require"

        self._engine = create_async_engine(
            settings.async_database_url,
            echo=settings.DEBUG,
            pool_size=settings.DB_POOL_SIZE,
            max_overflow=settings.DB_MAX_OVERFLOW,
            pool_timeout=settings.DB_POOL_TIMEOUT,
            pool_recycle=settings.DB_POOL_RECYCLE,
            pool_pre_ping=True,
            connect_args=connect_args,
        )

        self._session_factory = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

        await self._verify_connection()
        logger.info("database_initialized", url=self._masked_url())

    async def _verify_connection(self) -> None:
        assert self._engine is not None
        async with self._engine.connect() as conn:
            from sqlalchemy import text

            await conn.execute(text("SELECT 1"))

    async def close(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("database_connection_closed")

    def get_session(self) -> AsyncSession:
        if self._session_factory is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._session_factory()

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Context manager for worker code that manages its own transaction lifecycle."""
        s = self.get_session()
        try:
            yield s
        except Exception:
            await s.rollback()
            raise
        finally:
            await s.close()

    async def check_health(self) -> bool:
        """Readiness check — verifies a live DB round-trip."""
        try:
            assert self._engine is not None
            async with self._engine.connect() as conn:
                from sqlalchemy import text

                await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    def _masked_url(self) -> str:
        url = settings.async_database_url
        if "@" in url:
            # Mask credentials: postgresql+asyncpg://user:pass@host/db → ...@host/db
            at_idx = url.index("@")
            return "postgresql+asyncpg://***:***" + url[at_idx:]
        return url


# ─── Singleton ────────────────────────────────────────────────────────────────
database_manager = DatabaseManager()


# ─── FastAPI dependency ───────────────────────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yields a scoped database session per HTTP request.
    Commits on success, rolls back on any unhandled exception.
    """
    session = database_manager.get_session()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()

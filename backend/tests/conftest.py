from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from sqlalchemy import JSON, event
from sqlalchemy.dialects.postgresql import JSONB

from app.core.config import settings
from app.core.database import database_manager, get_db
from app.core.logging import configure_logging
from app.core.redis import redis_manager
from app.main import create_application
from app.models import Base


# ─── SQLite JSONB compatibility ───────────────────────────────────────────────

# SQLite does not have a native JSONB type.  Override it with JSON so that
# Base.metadata.create_all() can build the schema in tests.

@event.listens_for(Base.metadata, "before_create")
def _replace_jsonb(target, connection, **kw):
    if connection.dialect.name == "sqlite":
        for table in target.tables.values():
            for col in table.columns:
                if isinstance(col.type, JSONB):
                    col.type = JSON()


# ─── Test database ────────────────────────────────────────────────────────────

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session", autouse=True)
def configure_test_logging() -> None:
    configure_logging(log_level="WARNING", environment="development")


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    factory = async_sessionmaker(test_engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
        await session.rollback()  # Tests are isolated — never commit
    finally:
        await session.close()


# ─── Mock Redis ───────────────────────────────────────────────────────────────

@pytest.fixture
def mock_redis():
    mock = AsyncMock()
    mock.ping = AsyncMock(return_value=True)
    mock.get = AsyncMock(return_value=None)
    mock.set = AsyncMock(return_value=True)
    mock.delete = AsyncMock(return_value=1)
    mock.exists = AsyncMock(return_value=False)
    mock.incr = AsyncMock(return_value=1)
    mock.expire = AsyncMock(return_value=True)
    mock.ttl = AsyncMock(return_value=60)
    mock.publish = AsyncMock(return_value=1)
    # Redis Streams
    mock.xadd = AsyncMock(return_value="1234567890-0")
    mock.xreadgroup = AsyncMock(return_value=[])
    mock.xack = AsyncMock(return_value=1)
    mock.xgroup_create = AsyncMock(return_value=True)
    mock.xautoclaim = AsyncMock(return_value=("0-0", []))
    mock.hget = AsyncMock(return_value=None)
    mock.hset = AsyncMock(return_value=1)
    mock.hgetall = AsyncMock(return_value={})
    mock.hdel = AsyncMock(return_value=1)
    mock.incrby = AsyncMock(return_value=1)
    return mock


# ─── Test application ─────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def client(db_session: AsyncSession, mock_redis: Any) -> AsyncGenerator[AsyncClient, None]:
    """
    HTTP client with overridden DB and Redis dependencies.
    Every test gets a clean DB session (rolled back after the test).
    """
    app = create_application()

    app.dependency_overrides[get_db] = lambda: db_session

    from app.core.redis import get_redis
    app.dependency_overrides[get_redis] = lambda: mock_redis

    # Prevent lifespan from re-initializing real connections
    database_manager._engine = AsyncMock()
    database_manager._session_factory = lambda: db_session
    redis_manager._client = mock_redis

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Content-Type": "application/json"},
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


# ─── Auth helpers ─────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def registered_user(client: AsyncClient) -> dict[str, Any]:
    """Creates a test user and returns the registration response payload."""
    response = await client.post(
        f"{settings.API_PREFIX}/auth/register",
        json={
            "email": "test@example.com",
            "password": "TestPassword1",
            "full_name": "Test User",
        },
    )
    assert response.status_code == 201
    return response.json()


@pytest_asyncio.fixture
async def auth_headers(registered_user: dict[str, Any]) -> dict[str, str]:
    """Returns Authorization headers for an authenticated test user."""
    token = registered_user["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}

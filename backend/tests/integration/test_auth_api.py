"""Integration tests for authentication endpoints."""

from __future__ import annotations

from typing import Any

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings


async def _verify_email(db_session: AsyncSession, email: str) -> None:
    """Bypass email verification in tests by updating the flag directly in DB."""
    from sqlalchemy import update

    from app.models.user import User

    await db_session.execute(
        update(User).where(User.email == email).values(email_verified=True)
    )
    await db_session.flush()


@pytest_asyncio.fixture
async def user_and_headers(
    client: AsyncClient, db_session: AsyncSession
) -> dict[str, Any]:
    """Registers a fresh user, verifies their email, and returns credentials + auth headers.
    Uses a per-test unique email to avoid 409 conflicts when committed rows persist
    across function-scoped tests sharing a session-scoped SQLite engine.
    """
    import uuid

    email = f"authtest-{uuid.uuid4().hex[:8]}@example.com"
    reg = await client.post(
        f"{settings.API_PREFIX}/auth/register",
        json={
            "email": email,
            "password": "AuthTest1!Secure",
            "full_name": "Auth Tester",
        },
    )
    assert reg.status_code == 201, reg.text
    # Mark as verified so subsequent login / /me calls are not blocked by
    # EMAIL_NOT_VERIFIED. In production this is done via the email link.
    await _verify_email(db_session, email)
    data = reg.json()["data"]
    return {
        "email": email,
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "headers": {"Authorization": f"Bearer {data['access_token']}"},
    }


@pytest.mark.asyncio
class TestRegister:
    async def test_register_success(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"{settings.API_PREFIX}/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "StrongPass1!",
                "full_name": "New User",
            },
        )
        assert resp.status_code == 201
        data = resp.json()["data"]
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    async def test_register_duplicate_email(self, client: AsyncClient) -> None:
        payload = {
            "email": "duplicate@example.com",
            "password": "StrongPass1!",
            "full_name": "User One",
        }
        first = await client.post(f"{settings.API_PREFIX}/auth/register", json=payload)
        assert first.status_code == 201

        second = await client.post(f"{settings.API_PREFIX}/auth/register", json=payload)
        assert second.status_code == 409

    async def test_register_weak_password_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"{settings.API_PREFIX}/auth/register",
            json={
                "email": "weak@example.com",
                "password": "short",
                "full_name": "Weak User",
            },
        )
        assert resp.status_code == 422

    async def test_register_invalid_email_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"{settings.API_PREFIX}/auth/register",
            json={
                "email": "not-an-email",
                "password": "StrongPass1!",
                "full_name": "Bad Email",
            },
        )
        assert resp.status_code == 422

    async def test_register_missing_fields_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"{settings.API_PREFIX}/auth/register",
            json={"email": "missing@example.com"},
        )
        assert resp.status_code == 422


@pytest.mark.asyncio
class TestLogin:
    async def test_login_success(
        self, client: AsyncClient, user_and_headers: dict
    ) -> None:
        resp = await client.post(
            f"{settings.API_PREFIX}/auth/login",
            json={"email": user_and_headers["email"], "password": "AuthTest1!Secure"},
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "access_token" in data
        assert "refresh_token" in data

    async def test_login_wrong_password(
        self, client: AsyncClient, user_and_headers: dict
    ) -> None:
        resp = await client.post(
            f"{settings.API_PREFIX}/auth/login",
            json={"email": user_and_headers["email"], "password": "WrongPassword1!"},
        )
        assert resp.status_code == 401

    async def test_login_nonexistent_user(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"{settings.API_PREFIX}/auth/login",
            json={"email": "ghost@example.com", "password": "SomePass1!"},
        )
        assert resp.status_code == 401

    async def test_login_missing_email_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"{settings.API_PREFIX}/auth/login",
            json={"password": "SomePass1!"},
        )
        assert resp.status_code == 422


@pytest.mark.asyncio
class TestCurrentUser:
    async def test_get_me_authenticated(
        self, client: AsyncClient, user_and_headers: dict
    ) -> None:
        resp = await client.get(
            f"{settings.API_PREFIX}/auth/me",
            headers=user_and_headers["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["email"] == user_and_headers["email"]
        assert data["full_name"] == "Auth Tester"
        assert "password" not in data
        assert "hashed_password" not in data

    async def test_get_me_unauthenticated(self, client: AsyncClient) -> None:
        resp = await client.get(f"{settings.API_PREFIX}/auth/me")
        assert resp.status_code == 401

    async def test_get_me_invalid_token(self, client: AsyncClient) -> None:
        resp = await client.get(
            f"{settings.API_PREFIX}/auth/me",
            headers={"Authorization": "Bearer not.a.valid.jwt"},
        )
        assert resp.status_code == 401

    async def test_get_me_malformed_header(self, client: AsyncClient) -> None:
        resp = await client.get(
            f"{settings.API_PREFIX}/auth/me",
            headers={"Authorization": "Token bad-format"},
        )
        assert resp.status_code == 401


@pytest.mark.asyncio
class TestDemoLogin:
    # demo_service.py uses raw UUID parameters in DELETE statements that
    # SQLite cannot bind (sqlite3.ProgrammingError: type 'UUID' not supported).
    # These tests require a real PostgreSQL instance and are skipped in the
    # unit/integration test suite that runs on SQLite in-memory.

    @pytest.mark.skip(reason="demo_service uses PostgreSQL-only UUID binding; run against real Postgres")
    async def test_demo_login_returns_tokens(self, client: AsyncClient) -> None:
        resp = await client.post(f"{settings.API_PREFIX}/auth/demo")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "access_token" in data
        assert "refresh_token" in data

    @pytest.mark.skip(reason="demo_service uses PostgreSQL-only UUID binding; run against real Postgres")
    async def test_demo_user_can_access_me(self, client: AsyncClient) -> None:
        resp = await client.post(f"{settings.API_PREFIX}/auth/demo")
        assert resp.status_code == 200
        token = resp.json()["data"]["access_token"]

        me = await client.get(
            f"{settings.API_PREFIX}/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me.status_code == 200
        assert me.json()["data"]["email"] is not None

    @pytest.mark.skip(reason="demo_service uses PostgreSQL-only UUID binding; run against real Postgres")
    async def test_demo_login_is_idempotent(self, client: AsyncClient) -> None:
        """Multiple demo logins must not fail (demo user is reused)."""
        r1 = await client.post(f"{settings.API_PREFIX}/auth/demo")
        r2 = await client.post(f"{settings.API_PREFIX}/auth/demo")
        assert r1.status_code == 200
        assert r2.status_code == 200


@pytest.mark.asyncio
class TestLogout:
    async def test_logout_accepts_refresh_token(
        self, client: AsyncClient, user_and_headers: dict
    ) -> None:
        resp = await client.post(
            f"{settings.API_PREFIX}/auth/logout",
            json={"refresh_token": user_and_headers["refresh_token"]},
            headers=user_and_headers["headers"],
        )
        # Logout is a best-effort operation — 200 is the expected response
        assert resp.status_code == 200

    async def test_logout_without_token_still_200(
        self, client: AsyncClient, user_and_headers: dict
    ) -> None:
        """Logout with no body must not raise 500 — it's silently accepted."""
        resp = await client.post(
            f"{settings.API_PREFIX}/auth/logout",
            json={},
            headers=user_and_headers["headers"],
        )
        assert resp.status_code in (200, 204)

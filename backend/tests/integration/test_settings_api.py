"""Integration tests for the settings API — specifically severity thresholds persistence."""

from __future__ import annotations

from typing import Any

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings


async def _verify_email(db_session: AsyncSession, email: str) -> None:
    """Bypass email verification in tests by flipping the flag directly in DB."""
    from sqlalchemy import update

    from app.models.user import User

    await db_session.execute(
        update(User).where(User.email == email).values(email_verified=True)
    )
    await db_session.flush()


@pytest_asyncio.fixture
async def tenant_setup(client: AsyncClient, db_session: AsyncSession) -> dict[str, Any]:
    """Create a verified user and tenant, returning full auth headers including X-Tenant-ID.
    Uses per-test unique emails/slugs to avoid 409 conflicts with committed rows that
    persist across function-scoped tests sharing a session-scoped SQLite engine.
    """
    import uuid

    uid = uuid.uuid4().hex[:8]
    email = f"settings-{uid}@example.com"
    reg = await client.post(
        f"{settings.API_PREFIX}/auth/register",
        json={
            "email": email,
            "password": "SettingsPass1!Secure",
            "full_name": "Settings User",
        },
    )
    assert reg.status_code == 201, reg.text
    # Verify email so the user can create tenants and access settings endpoints
    await _verify_email(db_session, email)
    token = reg.json()["data"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    tenant = await client.post(
        f"{settings.API_PREFIX}/tenants",
        json={"name": f"Settings Tenant {uid}", "slug": f"settings-{uid}"},
        headers=headers,
    )
    assert tenant.status_code == 201, tenant.text
    tenant_id = tenant.json()["data"]["id"]

    return {
        "headers": {**headers, "X-Tenant-ID": tenant_id},
        "tenant_id": tenant_id,
    }


@pytest.mark.asyncio
class TestSeverityThresholds:
    async def test_get_returns_defaults(
        self, client: AsyncClient, tenant_setup: dict
    ) -> None:
        """Fresh tenant should return the schema defaults."""
        resp = await client.get(
            f"{settings.API_PREFIX}/settings/severity-thresholds",
            headers=tenant_setup["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["critical_min_score"] == 80
        assert data["high_min_score"] == 60
        assert data["medium_min_score"] == 30
        assert data["low_min_score"] == 0
        assert data["escalate_after_minutes"] == 60
        assert data["auto_close_after_days"] == 30

    async def test_put_returns_saved_values(
        self, client: AsyncClient, tenant_setup: dict
    ) -> None:
        payload = {
            "critical_min_score": 90,
            "high_min_score": 70,
            "medium_min_score": 40,
            "low_min_score": 10,
            "escalate_after_minutes": 30,
            "auto_close_after_days": 14,
        }
        resp = await client.put(
            f"{settings.API_PREFIX}/settings/severity-thresholds",
            json=payload,
            headers=tenant_setup["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["critical_min_score"] == 90
        assert data["high_min_score"] == 70
        assert data["escalate_after_minutes"] == 30
        assert data["auto_close_after_days"] == 14

    async def test_get_after_put_returns_updated_values(
        self, client: AsyncClient, tenant_setup: dict
    ) -> None:
        """Core persistence test: PUT → GET round-trip must return the saved values."""
        payload = {
            "critical_min_score": 95,
            "high_min_score": 75,
            "medium_min_score": 45,
            "low_min_score": 5,
            "escalate_after_minutes": 45,
            "auto_close_after_days": 7,
        }
        put = await client.put(
            f"{settings.API_PREFIX}/settings/severity-thresholds",
            json=payload,
            headers=tenant_setup["headers"],
        )
        assert put.status_code == 200

        get = await client.get(
            f"{settings.API_PREFIX}/settings/severity-thresholds",
            headers=tenant_setup["headers"],
        )
        assert get.status_code == 200
        data = get.json()["data"]
        assert data["critical_min_score"] == 95
        assert data["high_min_score"] == 75
        assert data["medium_min_score"] == 45
        assert data["low_min_score"] == 5
        assert data["escalate_after_minutes"] == 45
        assert data["auto_close_after_days"] == 7

    async def test_partial_put_preserves_other_fields(
        self, client: AsyncClient, tenant_setup: dict
    ) -> None:
        """PUT with only some fields changed — other fields retain their values."""
        initial = {
            "critical_min_score": 80,
            "high_min_score": 60,
            "medium_min_score": 30,
            "low_min_score": 0,
            "escalate_after_minutes": 60,
            "auto_close_after_days": 30,
        }
        await client.put(
            f"{settings.API_PREFIX}/settings/severity-thresholds",
            json=initial,
            headers=tenant_setup["headers"],
        )

        updated = {**initial, "critical_min_score": 99, "auto_close_after_days": 3}
        put = await client.put(
            f"{settings.API_PREFIX}/settings/severity-thresholds",
            json=updated,
            headers=tenant_setup["headers"],
        )
        assert put.status_code == 200

        get = await client.get(
            f"{settings.API_PREFIX}/settings/severity-thresholds",
            headers=tenant_setup["headers"],
        )
        data = get.json()["data"]
        assert data["critical_min_score"] == 99
        assert data["auto_close_after_days"] == 3
        # Unchanged fields must still hold their values
        assert data["high_min_score"] == 60
        assert data["escalate_after_minutes"] == 60

    async def test_unauthenticated_get_rejected(self, client: AsyncClient) -> None:
        resp = await client.get(f"{settings.API_PREFIX}/settings/severity-thresholds")
        assert resp.status_code == 401

    async def test_unauthenticated_put_rejected(self, client: AsyncClient) -> None:
        resp = await client.put(
            f"{settings.API_PREFIX}/settings/severity-thresholds",
            json={"critical_min_score": 90},
        )
        assert resp.status_code == 401

    async def test_missing_tenant_header_rejected(
        self, client: AsyncClient, tenant_setup: dict
    ) -> None:
        """Request with JWT but no X-Tenant-ID header must be rejected."""
        headers_no_tenant = {
            "Authorization": tenant_setup["headers"]["Authorization"]
        }
        resp = await client.get(
            f"{settings.API_PREFIX}/settings/severity-thresholds",
            headers=headers_no_tenant,
        )
        assert resp.status_code in (401, 403, 422)

    async def test_invalid_score_range_rejected(
        self, client: AsyncClient, tenant_setup: dict
    ) -> None:
        """Scores must be non-negative integers."""
        resp = await client.put(
            f"{settings.API_PREFIX}/settings/severity-thresholds",
            json={
                "critical_min_score": -1,
                "high_min_score": 60,
                "medium_min_score": 30,
                "low_min_score": 0,
                "escalate_after_minutes": 60,
                "auto_close_after_days": 30,
            },
            headers=tenant_setup["headers"],
        )
        assert resp.status_code == 422

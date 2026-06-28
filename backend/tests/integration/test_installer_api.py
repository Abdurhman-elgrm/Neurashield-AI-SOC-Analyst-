"""Integration tests for the installer token API."""

from __future__ import annotations

from datetime import UTC, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_password
from app.models.installer_token import InstallerToken, InstallerTokenStatus

_BASE = f"{settings.API_PREFIX}/installer"


@pytest_asyncio.fixture
async def setup(client: AsyncClient, db_session: AsyncSession) -> dict[str, Any]:
    """Register a verified user, create a tenant, return full auth headers."""
    from tests.conftest import setup_verified_user_and_tenant

    data = await setup_verified_user_and_tenant(client, db_session, prefix="installer")
    return {
        "headers": data["headers"],
        "tenant_id": data["tenant_id"],
        "token": data["token"],
    }


def _gen_payload(machine_name: str = "WIN-SRV-01") -> dict:
    return {
        "organization": "Acme Security",
        "machine_name": machine_name,
        "metadata": {"env": "prod"},
    }


# ─── Generate token ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestGenerateToken:
    async def test_generate_returns_201_with_raw_token(self, client: AsyncClient, setup: dict):
        resp = await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload(),
            headers=setup["headers"],
        )
        assert resp.status_code == 201
        data = resp.json()["data"]
        assert "raw_token" in data
        assert data["raw_token"].startswith("inst_")
        assert len(data["raw_token"]) >= 48
        assert data["status"] == "pending"
        assert data["machine_name"] == "WIN-SRV-01"

    async def test_generate_raw_token_not_exposed_after_generation(
        self, client: AsyncClient, setup: dict
    ):
        """Raw token must only appear in the generate response, not in subsequent reads."""
        gen_resp = await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload("SEC-SCAN-01"),
            headers=setup["headers"],
        )
        assert gen_resp.status_code == 201
        token_id = gen_resp.json()["data"]["id"]

        status_resp = await client.get(
            f"{_BASE}/token/{token_id}/status",
            headers=setup["headers"],
        )
        assert status_resp.status_code == 200
        assert "raw_token" not in status_resp.json()["data"]

    async def test_generate_requires_agents_manage_permission(
        self, client: AsyncClient, setup: dict
    ):
        # Headers without X-Tenant-ID → 403 / 422
        headers_no_tenant = {"Authorization": setup["headers"]["Authorization"]}
        resp = await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload(),
            headers=headers_no_tenant,
        )
        assert resp.status_code in (403, 422)

    async def test_generate_unauthenticated_returns_401(self, client: AsyncClient):
        resp = await client.post(f"{_BASE}/generate-token", json=_gen_payload())
        assert resp.status_code == 401

    async def test_generate_rate_limit_enforced(
        self, client: AsyncClient, setup: dict, mock_redis: Any
    ):
        """After rate limit is exceeded the endpoint returns 429."""
        # Configure mock to reject the rate limit check
        mock_redis.incr = __import__("unittest.mock", fromlist=["AsyncMock"]).AsyncMock(
            return_value=11  # over the 10/hour limit
        )
        mock_redis.expire = __import__("unittest.mock", fromlist=["AsyncMock"]).AsyncMock(
            return_value=True
        )

        resp = await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload(),
            headers=setup["headers"],
        )
        # Rate limit exceeded → 429
        assert resp.status_code == 429


# ─── Status check ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestTokenStatus:
    async def test_get_status_pending(self, client: AsyncClient, setup: dict):
        gen = await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload("STATUS-HOST"),
            headers=setup["headers"],
        )
        assert gen.status_code == 201
        token_id = gen.json()["data"]["id"]

        resp = await client.get(
            f"{_BASE}/token/{token_id}/status",
            headers=setup["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["status"] == "pending"
        assert data["id"] == token_id
        assert data["token_preview"].startswith("inst_")

    async def test_get_status_nonexistent_returns_404(self, client: AsyncClient, setup: dict):
        resp = await client.get(
            f"{_BASE}/token/{uuid4()}/status",
            headers=setup["headers"],
        )
        assert resp.status_code == 404

    async def test_get_status_wrong_tenant_returns_404(
        self, client: AsyncClient, db_session: AsyncSession, setup: dict
    ):
        """Token belonging to a different tenant must not be visible."""
        other_tenant_id = uuid4()
        raw = "inst_othertenant0000000000000000"
        token = InstallerToken(
            tenant_id=other_tenant_id,
            token_hash=hash_password(raw),
            token_preview=raw[:8],
            organization="Other Org",
            machine_name="OTHER-HOST",
            status=InstallerTokenStatus.PENDING,
            expires_at=__import__("datetime").datetime.now(tz=__import__("datetime").timezone.utc)
            + timedelta(hours=1),
        )
        db_session.add(token)
        await db_session.flush()

        resp = await client.get(
            f"{_BASE}/token/{token.id}/status",
            headers=setup["headers"],
        )
        assert resp.status_code == 404

    async def test_get_status_requires_authentication(self, client: AsyncClient):
        resp = await client.get(f"{_BASE}/token/{uuid4()}/status")
        assert resp.status_code == 401


# ─── List tokens ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestListTokens:
    async def test_list_empty_initially(self, client: AsyncClient, setup: dict):
        resp = await client.get(f"{_BASE}/tokens", headers=setup["headers"])
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"] == []
        assert body["pagination"]["total"] == 0

    async def test_list_after_generation(self, client: AsyncClient, setup: dict):
        await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload("LIST-HOST-1"),
            headers=setup["headers"],
        )
        await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload("LIST-HOST-2"),
            headers=setup["headers"],
        )

        resp = await client.get(f"{_BASE}/tokens", headers=setup["headers"])
        assert resp.status_code == 200
        assert resp.json()["pagination"]["total"] == 2

    async def test_list_filter_by_status(self, client: AsyncClient, setup: dict):
        await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload("FILTER-HOST"),
            headers=setup["headers"],
        )

        resp = await client.get(
            f"{_BASE}/tokens?status=pending",
            headers=setup["headers"],
        )
        assert resp.status_code == 200
        for t in resp.json()["data"]:
            assert t["status"] == "pending"

    async def test_list_filter_unknown_status_returns_all(self, client: AsyncClient, setup: dict):
        await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload("UNKNOWN-FILTER-HOST"),
            headers=setup["headers"],
        )
        resp = await client.get(
            f"{_BASE}/tokens?status=bogus_status",
            headers=setup["headers"],
        )
        assert resp.status_code == 200
        assert resp.json()["pagination"]["total"] >= 1

    async def test_list_pagination(self, client: AsyncClient, setup: dict):
        for i in range(3):
            await client.post(
                f"{_BASE}/generate-token",
                json=_gen_payload(f"PAGE-HOST-{i}"),
                headers=setup["headers"],
            )

        page1 = await client.get(
            f"{_BASE}/tokens?page=1&limit=2",
            headers=setup["headers"],
        )
        assert page1.status_code == 200
        assert len(page1.json()["data"]) <= 2

    async def test_list_requires_authentication(self, client: AsyncClient):
        resp = await client.get(f"{_BASE}/tokens")
        assert resp.status_code == 401


# ─── Revoke token ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestRevokeToken:
    async def test_revoke_pending_token(self, client: AsyncClient, setup: dict):
        gen = await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload("REVOKE-HOST"),
            headers=setup["headers"],
        )
        assert gen.status_code == 201
        token_id = gen.json()["data"]["id"]

        resp = await client.post(
            f"{_BASE}/revoke/{token_id}",
            json={"reason": "no longer needed"},
            headers=setup["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["status"] == "revoked"
        assert data["revoked_at"] is not None

    async def test_revoke_nonexistent_returns_404(self, client: AsyncClient, setup: dict):
        resp = await client.post(
            f"{_BASE}/revoke/{uuid4()}",
            json={},
            headers=setup["headers"],
        )
        assert resp.status_code == 404

    async def test_revoke_active_token_returns_409(
        self, client: AsyncClient, db_session: AsyncSession, setup: dict
    ):
        """Attempting to revoke an already-active token must return 409 Conflict."""
        from datetime import datetime

        raw = "inst_activetokentest000000000000"
        token = InstallerToken(
            tenant_id=UUID(setup["tenant_id"]),
            token_hash=hash_password(raw),
            token_preview=raw[:8],
            organization="Corp",
            machine_name="ACTIVE-HOST",
            status=InstallerTokenStatus.ACTIVE,
            expires_at=datetime.now(tz=UTC) + timedelta(hours=1),
        )
        db_session.add(token)
        await db_session.flush()

        resp = await client.post(
            f"{_BASE}/revoke/{token.id}",
            json={"reason": "trying to revoke active"},
            headers=setup["headers"],
        )
        assert resp.status_code == 409

    async def test_revoke_requires_agents_manage_permission(self, client: AsyncClient, setup: dict):
        gen = await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload("PERM-HOST"),
            headers=setup["headers"],
        )
        token_id = gen.json()["data"]["id"]

        headers_no_tenant = {"Authorization": setup["headers"]["Authorization"]}
        resp = await client.post(
            f"{_BASE}/revoke/{token_id}",
            json={},
            headers=headers_no_tenant,
        )
        assert resp.status_code in (403, 422)


# ─── Token lifecycle (end-to-end state machine) ───────────────────────────────


@pytest.mark.asyncio
class TestTokenLifecycle:
    async def test_generate_then_check_then_revoke(self, client: AsyncClient, setup: dict):
        # 1. Generate
        gen = await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload("LIFECYCLE-HOST"),
            headers=setup["headers"],
        )
        assert gen.status_code == 201
        token_id = gen.json()["data"]["id"]
        raw_token = gen.json()["data"]["raw_token"]
        assert raw_token.startswith("inst_")

        # 2. Status → pending
        status = await client.get(
            f"{_BASE}/token/{token_id}/status",
            headers=setup["headers"],
        )
        assert status.json()["data"]["status"] == "pending"

        # 3. Revoke
        revoke = await client.post(
            f"{_BASE}/revoke/{token_id}",
            json={"reason": "lifecycle test"},
            headers=setup["headers"],
        )
        assert revoke.status_code == 200

        # 4. Status → revoked
        final = await client.get(
            f"{_BASE}/token/{token_id}/status",
            headers=setup["headers"],
        )
        assert final.json()["data"]["status"] == "revoked"

    async def test_revoked_token_not_revokable_again(self, client: AsyncClient, setup: dict):
        gen = await client.post(
            f"{_BASE}/generate-token",
            json=_gen_payload("DOUBLE-REVOKE-HOST"),
            headers=setup["headers"],
        )
        token_id = gen.json()["data"]["id"]

        await client.post(
            f"{_BASE}/revoke/{token_id}",
            json={"reason": "first revoke"},
            headers=setup["headers"],
        )

        resp = await client.post(
            f"{_BASE}/revoke/{token_id}",
            json={"reason": "second revoke attempt"},
            headers=setup["headers"],
        )
        assert resp.status_code == 409


# ─── Expiry (seeded expired tokens) ──────────────────────────────────────────


@pytest.mark.asyncio
class TestExpiredToken:
    async def test_expired_token_shows_expired_status(
        self, client: AsyncClient, db_session: AsyncSession, setup: dict
    ):
        """A token whose expires_at is in the past shows 'expired' in list/status."""
        from datetime import datetime

        raw = "inst_expiredtoken0000000000000000"
        token = InstallerToken(
            tenant_id=UUID(setup["tenant_id"]),
            token_hash=hash_password(raw),
            token_preview=raw[:8],
            organization="Corp",
            machine_name="EXPIRED-HOST",
            status=InstallerTokenStatus.EXPIRED,
            expires_at=datetime.now(tz=UTC) - timedelta(hours=2),
        )
        db_session.add(token)
        await db_session.flush()

        resp = await client.get(
            f"{_BASE}/token/{token.id}/status",
            headers=setup["headers"],
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["status"] == "expired"

    async def test_list_filter_expired_returns_only_expired(
        self, client: AsyncClient, db_session: AsyncSession, setup: dict
    ):
        from datetime import datetime

        raw = "inst_expiredlist0000000000000000"
        token = InstallerToken(
            tenant_id=UUID(setup["tenant_id"]),
            token_hash=hash_password(raw),
            token_preview=raw[:8],
            organization="Corp",
            machine_name="EXP-LIST-HOST",
            status=InstallerTokenStatus.EXPIRED,
            expires_at=datetime.now(tz=UTC) - timedelta(hours=1),
        )
        db_session.add(token)
        await db_session.flush()

        resp = await client.get(
            f"{_BASE}/tokens?status=expired",
            headers=setup["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert len(data) >= 1
        for t in data:
            assert t["status"] == "expired"

    async def test_expired_token_cannot_be_revoked(
        self, client: AsyncClient, db_session: AsyncSession, setup: dict
    ):
        """Expired tokens are terminal — revoke must return 409."""
        from datetime import datetime

        raw = "inst_expirevoke00000000000000000"
        token = InstallerToken(
            tenant_id=UUID(setup["tenant_id"]),
            token_hash=hash_password(raw),
            token_preview=raw[:8],
            organization="Corp",
            machine_name="EXP-REVOKE-HOST",
            status=InstallerTokenStatus.EXPIRED,
            expires_at=datetime.now(tz=UTC) - timedelta(hours=1),
        )
        db_session.add(token)
        await db_session.flush()

        resp = await client.post(
            f"{_BASE}/revoke/{token.id}",
            json={"reason": "trying to revoke expired"},
            headers=setup["headers"],
        )
        assert resp.status_code == 409

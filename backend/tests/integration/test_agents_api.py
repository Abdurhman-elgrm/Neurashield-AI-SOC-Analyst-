"""Integration tests for agent enrollment and management."""

from __future__ import annotations

from typing import Any

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from tests.conftest import setup_verified_user_and_tenant


@pytest_asyncio.fixture
async def tenant_and_member(
    client: AsyncClient, db_session: AsyncSession
) -> dict[str, Any]:
    """Creates a verified user, creates a tenant, returns auth headers + tenant_id."""
    return await setup_verified_user_and_tenant(client, db_session, prefix="agents")


@pytest.mark.asyncio
class TestAgentEnrollment:
    async def test_enroll_agent_success(self, client: AsyncClient, tenant_and_member: dict):
        resp = await client.post(
            f"{settings.API_PREFIX}/agents/enroll",
            json={
                "name": "Server-01",
                "hostname": "server-01.internal",
                "os_type": "linux",
                "agent_version": "1.0.0",
                "ip_address": "10.0.0.1",
            },
            headers=tenant_and_member["headers"],
        )
        assert resp.status_code == 201
        data = resp.json()["data"]
        assert "agent_id" in data
        assert "enrollment_token" in data
        assert len(data["enrollment_token"]) > 20

    async def test_enroll_requires_agents_manage_permission(
        self, client: AsyncClient, tenant_and_member: dict
    ):
        # Use headers without X-Tenant-ID to trigger 403
        headers = {k: v for k, v in tenant_and_member["headers"].items() if k != "X-Tenant-ID"}
        resp = await client.post(
            f"{settings.API_PREFIX}/agents/enroll",
            json={"name": "S1", "hostname": "s1", "os_type": "linux"},
            headers=headers,
        )
        assert resp.status_code in (403, 422)

    async def test_list_agents_empty_initially(self, client: AsyncClient, tenant_and_member: dict):
        resp = await client.get(
            f"{settings.API_PREFIX}/agents",
            headers=tenant_and_member["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["data"] == []
        assert data["pagination"]["total"] == 0

    async def test_list_agents_after_enroll(self, client: AsyncClient, tenant_and_member: dict):
        await client.post(
            f"{settings.API_PREFIX}/agents/enroll",
            json={"name": "Agent1", "hostname": "agent1", "os_type": "windows"},
            headers=tenant_and_member["headers"],
        )
        resp = await client.get(
            f"{settings.API_PREFIX}/agents",
            headers=tenant_and_member["headers"],
        )
        assert resp.status_code == 200
        assert resp.json()["pagination"]["total"] == 1


@pytest.mark.asyncio
class TestAgentIngestion:
    async def test_ingest_requires_agent_auth_headers(self, client: AsyncClient):
        resp = await client.post(
            f"{settings.API_PREFIX}/agents/ingest",
            json={"events": []},
        )
        assert resp.status_code == 401

    async def test_heartbeat_requires_agent_auth_headers(self, client: AsyncClient):
        resp = await client.post(
            f"{settings.API_PREFIX}/agents/heartbeat",
            json={},
        )
        assert resp.status_code == 401

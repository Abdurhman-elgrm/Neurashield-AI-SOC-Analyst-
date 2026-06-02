"""Integration tests for the alerts API."""
from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.alert import Alert, AlertSeverity, AlertStatus


@pytest_asyncio.fixture
async def setup(client: AsyncClient, db_session: AsyncSession) -> dict[str, Any]:
    reg = await client.post(
        f"{settings.API_PREFIX}/auth/register",
        json={"email": "soc@example.com", "password": "TestPass1!", "full_name": "SOC"},
    )
    token = reg.json()["data"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    tenant_resp = await client.post(
        f"{settings.API_PREFIX}/tenants",
        json={"name": "SOC Corp", "slug": "soc-corp"},
        headers=headers,
    )
    tenant_id = tenant_resp.json()["data"]["id"]
    full_headers = {**headers, "X-Tenant-ID": tenant_id}

    from uuid import UUID as _UUID
    # Seed an alert directly in DB
    alert = Alert(
        tenant_id=_UUID(tenant_id),
        status=AlertStatus.OPEN,
        severity=AlertSeverity.HIGH,
        title="Test Alert",
        source_host="HOST1",
        evidence={},
        mitre_tactics=[],
        mitre_techniques=[],
    )
    db_session.add(alert)
    await db_session.flush()

    return {"headers": full_headers, "tenant_id": tenant_id, "alert_id": str(alert.id)}


@pytest.mark.asyncio
class TestAlertsAPI:

    async def test_list_alerts(self, client: AsyncClient, setup: dict):
        resp = await client.get(f"{settings.API_PREFIX}/alerts", headers=setup["headers"])
        assert resp.status_code == 200
        assert len(resp.json()["data"]) >= 1

    async def test_get_alert_by_id(self, client: AsyncClient, setup: dict):
        resp = await client.get(
            f"{settings.API_PREFIX}/alerts/{setup['alert_id']}",
            headers=setup["headers"],
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["title"] == "Test Alert"

    async def test_get_nonexistent_alert_returns_404(self, client: AsyncClient, setup: dict):
        resp = await client.get(
            f"{settings.API_PREFIX}/alerts/{uuid4()}",
            headers=setup["headers"],
        )
        assert resp.status_code == 404

    async def test_acknowledge_alert(self, client: AsyncClient, setup: dict):
        resp = await client.patch(
            f"{settings.API_PREFIX}/alerts/{setup['alert_id']}",
            json={"status": "acknowledged"},
            headers=setup["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["status"] == "acknowledged"
        assert data["acknowledged_at"] is not None

    async def test_close_alert(self, client: AsyncClient, setup: dict):
        resp = await client.patch(
            f"{settings.API_PREFIX}/alerts/{setup['alert_id']}",
            json={"status": "closed", "notes": "Resolved after investigation"},
            headers=setup["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["status"] == "closed"
        assert data["notes"] == "Resolved after investigation"

    async def test_invalid_status_rejected(self, client: AsyncClient, setup: dict):
        resp = await client.patch(
            f"{settings.API_PREFIX}/alerts/{setup['alert_id']}",
            json={"status": "invalid_status"},
            headers=setup["headers"],
        )
        assert resp.status_code == 422

    async def test_filter_by_status(self, client: AsyncClient, setup: dict):
        resp = await client.get(
            f"{settings.API_PREFIX}/alerts?status=open",
            headers=setup["headers"],
        )
        assert resp.status_code == 200
        for alert in resp.json()["data"]:
            assert alert["status"] == "open"

    async def test_filter_by_severity(self, client: AsyncClient, setup: dict):
        resp = await client.get(
            f"{settings.API_PREFIX}/alerts?severity=high",
            headers=setup["headers"],
        )
        assert resp.status_code == 200
        for alert in resp.json()["data"]:
            assert alert["severity"] == "high"

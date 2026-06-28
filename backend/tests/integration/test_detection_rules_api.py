"""Integration tests for detection rule CRUD."""

from __future__ import annotations

from typing import Any

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from tests.conftest import setup_verified_user_and_tenant


@pytest_asyncio.fixture
async def setup(client: AsyncClient, db_session: AsyncSession) -> dict[str, Any]:
    return await setup_verified_user_and_tenant(client, db_session, prefix="rules")


_PATTERN_RULE = {
    "name": "Suspicious cmd.exe",
    "description": "Detects cmd.exe with encoded command",
    "rule_type": "pattern",
    "severity": "high",
    "conditions": [
        {"field": "process.name", "op": "eq", "value": "cmd.exe"},
        {"field": "process.command_line", "op": "contains", "value": "/c"},
    ],
    "mitre_tactics": ["execution"],
    "mitre_techniques": ["T1059.003"],
    "suppression_window_secs": 300,
}

_THRESHOLD_RULE = {
    "name": "Many failed logins",
    "rule_type": "threshold",
    "severity": "critical",
    "conditions": {
        "field": "username",
        "threshold": 10,
        "window_secs": 300,
        "filters": [{"field": "category", "op": "eq", "value": "auth"}],
    },
    "suppression_window_secs": 600,
}


@pytest.mark.asyncio
class TestDetectionRulesCRUD:
    async def test_create_pattern_rule(self, client: AsyncClient, setup: dict):
        resp = await client.post(
            f"{settings.API_PREFIX}/rules",
            json=_PATTERN_RULE,
            headers=setup["headers"],
        )
        assert resp.status_code == 201
        data = resp.json()["data"]
        assert data["name"] == "Suspicious cmd.exe"
        assert data["rule_type"] == "pattern"
        assert data["severity"] == "high"
        assert data["enabled"] is True

    async def test_create_threshold_rule(self, client: AsyncClient, setup: dict):
        resp = await client.post(
            f"{settings.API_PREFIX}/rules",
            json=_THRESHOLD_RULE,
            headers=setup["headers"],
        )
        assert resp.status_code == 201
        assert resp.json()["data"]["rule_type"] == "threshold"

    async def test_list_rules_empty_initially(self, client: AsyncClient, setup: dict):
        resp = await client.get(f"{settings.API_PREFIX}/rules", headers=setup["headers"])
        assert resp.status_code == 200
        assert resp.json()["data"] == []

    async def test_list_rules_after_creation(self, client: AsyncClient, setup: dict):
        await client.post(
            f"{settings.API_PREFIX}/rules", json=_PATTERN_RULE, headers=setup["headers"]
        )
        resp = await client.get(f"{settings.API_PREFIX}/rules", headers=setup["headers"])
        assert resp.json()["pagination"]["total"] == 1

    async def test_get_rule_by_id(self, client: AsyncClient, setup: dict):
        create_resp = await client.post(
            f"{settings.API_PREFIX}/rules", json=_PATTERN_RULE, headers=setup["headers"]
        )
        rule_id = create_resp.json()["data"]["id"]
        resp = await client.get(f"{settings.API_PREFIX}/rules/{rule_id}", headers=setup["headers"])
        assert resp.status_code == 200
        assert resp.json()["data"]["id"] == rule_id

    async def test_update_rule_enabled_flag(self, client: AsyncClient, setup: dict):
        create_resp = await client.post(
            f"{settings.API_PREFIX}/rules", json=_PATTERN_RULE, headers=setup["headers"]
        )
        rule_id = create_resp.json()["data"]["id"]
        resp = await client.patch(
            f"{settings.API_PREFIX}/rules/{rule_id}",
            json={"enabled": False},
            headers=setup["headers"],
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["enabled"] is False

    async def test_delete_rule_soft(self, client: AsyncClient, setup: dict):
        create_resp = await client.post(
            f"{settings.API_PREFIX}/rules", json=_PATTERN_RULE, headers=setup["headers"]
        )
        rule_id = create_resp.json()["data"]["id"]
        del_resp = await client.delete(
            f"{settings.API_PREFIX}/rules/{rule_id}", headers=setup["headers"]
        )
        assert del_resp.status_code == 200
        # After delete, should return 404
        get_resp = await client.get(
            f"{settings.API_PREFIX}/rules/{rule_id}", headers=setup["headers"]
        )
        assert get_resp.status_code == 404

    async def test_invalid_rule_type_rejected(self, client: AsyncClient, setup: dict):
        resp = await client.post(
            f"{settings.API_PREFIX}/rules",
            json={**_PATTERN_RULE, "rule_type": "invalid"},
            headers=setup["headers"],
        )
        assert resp.status_code == 422

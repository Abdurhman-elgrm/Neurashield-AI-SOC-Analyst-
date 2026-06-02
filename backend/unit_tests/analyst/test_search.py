from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.analyst.search import PivotEngine, _build_pivot_result, _ENTITY_TYPE_MAP
from app.analyst.schemas import PivotResult

from .conftest import (
    TENANT_ID, INV_ID, INV_ID_2,
    make_mock_db, scalar_result, scalars_result,
    make_investigation,
)


# ─── _build_pivot_result ──────────────────────────────────────────────────────

def test_build_pivot_result_empty_rows():
    result = _build_pivot_result("ip", "1.2.3.4", [])
    assert result.entity_type == "ip"
    assert result.entity_key == "ip:1.2.3.4"
    assert result.total == 0
    assert result.investigation_ids == []
    assert result.investigation_refs == []


def test_build_pivot_result_with_rows():
    inv = make_investigation(investigation_id=INV_ID, threat_score=80)
    inv.executive_summary = "Lateral movement detected"

    result = _build_pivot_result("user", "alice", [inv])

    assert result.total == 1
    assert result.investigation_ids == [INV_ID]
    assert result.entity_key == "user:alice"


def test_build_pivot_result_truncates_executive_summary():
    inv = make_investigation()
    inv.executive_summary = "A" * 300

    result = _build_pivot_result("host", "ws-001", [inv])

    assert len(result.investigation_refs[0]["executive_summary"]) == 200


def test_build_pivot_result_multiple_rows():
    inv1 = make_investigation(investigation_id=INV_ID, threat_score=90)
    inv2 = make_investigation(investigation_id=INV_ID_2, threat_score=60)

    result = _build_pivot_result("ip", "10.0.0.1", [inv1, inv2])

    assert result.total == 2
    assert len(result.investigation_ids) == 2
    assert result.investigation_refs[0]["threat_score"] == 90


def test_build_pivot_result_ref_fields():
    inv = make_investigation(
        investigation_id=INV_ID,
        threat_score=75,
        confidence="high",
        status="investigating",
    )

    result = _build_pivot_result("domain", "evil.com", [inv])
    ref = result.investigation_refs[0]

    assert ref["investigation_id"] == INV_ID
    assert ref["threat_score"] == 75
    assert ref["status"] == "investigating"
    assert "created_at" in ref


# ─── Entity type map ──────────────────────────────────────────────────────────

def test_entity_type_map_contains_user():
    assert "user" in _ENTITY_TYPE_MAP
    assert _ENTITY_TYPE_MAP["user"] == "involved_users"


def test_entity_type_map_contains_ip():
    assert "ip" in _ENTITY_TYPE_MAP
    assert _ENTITY_TYPE_MAP["ip"] == "involved_ips"


def test_entity_type_map_contains_domain():
    assert "domain" in _ENTITY_TYPE_MAP
    assert _ENTITY_TYPE_MAP["domain"] == "suspicious_domains"


def test_entity_type_map_contains_hash():
    assert "hash" in _ENTITY_TYPE_MAP


def test_entity_type_map_contains_process():
    assert "process" in _ENTITY_TYPE_MAP


def test_entity_type_map_contains_host():
    assert "host" in _ENTITY_TYPE_MAP


# ─── PivotEngine.list_entity_types ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_entity_types_returns_expected():
    types = await PivotEngine.list_entity_types()
    assert set(types) == set(_ENTITY_TYPE_MAP.keys())
    assert "user" in types
    assert "ip" in types


# ─── PivotEngine.pivot — text fallback ────────────────────────────────────────

@pytest.mark.asyncio
async def test_pivot_unknown_entity_type_uses_text_search():
    db = make_mock_db()
    inv = make_investigation()
    # First execute call: JSONB query (returns nothing for unknown type → goes directly to text fallback)
    # For unknown types, it skips JSONB and goes straight to text search
    db.execute = AsyncMock(return_value=scalars_result([inv]))

    result = await PivotEngine.pivot(db, TENANT_ID, "unknown_type", "some-value")

    assert result.entity_type == "unknown_type"
    assert result.total == 1


@pytest.mark.asyncio
async def test_pivot_text_search_returns_empty():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalars_result([]))

    result = await PivotEngine.pivot(db, TENANT_ID, "unknown_type", "xyz")

    assert result.total == 0


# ─── PivotEngine.pivot — known type ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_pivot_known_type_user_returns_results():
    db = make_mock_db()
    inv = make_investigation()
    # First call: JSONB query returns rows
    db.execute = AsyncMock(return_value=scalars_result([inv]))

    result = await PivotEngine.pivot(db, TENANT_ID, "user", "alice")

    assert result.entity_type == "user"
    assert result.total == 1


@pytest.mark.asyncio
async def test_pivot_known_type_ip_falls_back_on_empty_jsonb():
    db = make_mock_db()
    inv = make_investigation()
    # JSONB returns empty → falls back to text search → finds result
    db.execute = AsyncMock(side_effect=[
        scalars_result([]),   # JSONB query: empty
        scalars_result([inv]),  # text fallback: found
    ])

    result = await PivotEngine.pivot(db, TENANT_ID, "ip", "10.0.0.5")

    assert result.total == 1


# ─── PivotEngine.cross_investigation_entity_summary ──────────────────────────

@pytest.mark.asyncio
async def test_cross_investigation_entity_summary_returns_dict():
    db = make_mock_db()
    inv = make_investigation(threat_score=85)
    db.execute = AsyncMock(return_value=scalars_result([inv]))

    summary = await PivotEngine.cross_investigation_entity_summary(
        db, TENANT_ID, "ip:192.168.1.10"
    )

    assert summary["entity_key"] == "ip:192.168.1.10"
    assert summary["entity_type"] == "ip"
    assert summary["entity_value"] == "192.168.1.10"
    assert summary["investigation_count"] == 1
    assert summary["max_threat_score"] == 85


@pytest.mark.asyncio
async def test_cross_investigation_entity_summary_no_prefix():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalars_result([]))

    summary = await PivotEngine.cross_investigation_entity_summary(
        db, TENANT_ID, "workstation-01"
    )

    assert summary["entity_type"] == "host"
    assert summary["entity_value"] == "workstation-01"
    assert summary["investigation_count"] == 0
    assert summary["max_threat_score"] == 0

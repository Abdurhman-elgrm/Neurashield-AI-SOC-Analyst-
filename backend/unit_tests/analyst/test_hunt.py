from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.analyst.hunt import (
    HuntEngine,
    _build_filter_clauses,
    _apply_operator,
    _resolve_column,
    _matches_jsonb_filters,
    _build_match_reasons,
    _encode_cursor,
    _decode_cursor,
)
from app.analyst.schemas import HuntFilter, HuntQuery, SavedHuntCreate
from app.core.exceptions import NotFoundError
from app.models.investigation import Investigation

from .conftest import (
    ANALYST_ID, TENANT_ID, INV_ID, HUNT_ID,
    make_mock_db, scalar_result, scalars_result,
    make_investigation, make_saved_hunt,
)


# ─── _apply_operator ─────────────────────────────────────────────────────────

def test_apply_operator_eq():
    col = Investigation.status
    clause = _apply_operator(col, "new", "eq")
    assert clause is not None


def test_apply_operator_contains_produces_ilike():
    col = Investigation.executive_summary
    clause = _apply_operator(col, "lateral movement", "contains")
    assert clause is not None


def test_apply_operator_gt_numeric():
    col = Investigation.threat_score
    clause = _apply_operator(col, "70", "gt")
    assert clause is not None


def test_apply_operator_lt_numeric():
    col = Investigation.threat_score
    clause = _apply_operator(col, "30", "lt")
    assert clause is not None


def test_apply_operator_gte_numeric():
    col = Investigation.threat_score
    clause = _apply_operator(col, "50", "gte")
    assert clause is not None


def test_apply_operator_lte_numeric():
    col = Investigation.threat_score
    clause = _apply_operator(col, "80", "lte")
    assert clause is not None


def test_apply_operator_startswith():
    col = Investigation.executive_summary
    clause = _apply_operator(col, "Phishing", "startswith")
    assert clause is not None


def test_apply_operator_endswith():
    col = Investigation.executive_summary
    clause = _apply_operator(col, "detected", "endswith")
    assert clause is not None


def test_apply_operator_unknown_returns_none():
    col = Investigation.status
    clause = _apply_operator(col, "x", "between")
    assert clause is None


def test_apply_operator_non_numeric_for_gt_returns_none():
    col = Investigation.threat_score
    clause = _apply_operator(col, "not-a-number", "gt")
    assert clause is None


# ─── _resolve_column ─────────────────────────────────────────────────────────

def test_resolve_column_status():
    assert _resolve_column("status") is not None


def test_resolve_column_threat_score():
    assert _resolve_column("threat_score") is not None


def test_resolve_column_executive_summary():
    assert _resolve_column("executive_summary") is not None


def test_resolve_column_unknown_returns_none():
    assert _resolve_column("nonexistent_field") is None


# ─── _build_filter_clauses ────────────────────────────────────────────────────

def test_build_filter_clauses_empty():
    clauses = _build_filter_clauses([])
    assert clauses == []


def test_build_filter_clauses_known_field():
    filters = [HuntFilter(field="status", value="new", operator="eq")]
    clauses = _build_filter_clauses(filters)
    assert len(clauses) == 1


def test_build_filter_clauses_unknown_field_skipped():
    filters = [HuntFilter(field="not_real_field", value="x")]
    clauses = _build_filter_clauses(filters)
    assert clauses == []


def test_build_filter_clauses_multiple():
    filters = [
        HuntFilter(field="status", value="new"),
        HuntFilter(field="threat_score", value="50", operator="gte"),
    ]
    clauses = _build_filter_clauses(filters)
    assert len(clauses) == 2


# ─── _matches_jsonb_filters ───────────────────────────────────────────────────

def test_matches_jsonb_filters_no_filters():
    row = make_investigation()
    row.behaviors_json = None
    row.timeline_json = None
    query = HuntQuery()

    assert _matches_jsonb_filters(row, query) is True


def test_matches_jsonb_filters_mitre_tactic_match():
    row = make_investigation()
    row.behaviors_json = {
        "detected_behaviors": [
            {"behavior_name": "lateral_movement", "mitre_tactics": ["TA0008"]}
        ]
    }
    query = HuntQuery(mitre_tactics=["TA0008"])

    assert _matches_jsonb_filters(row, query) is True


def test_matches_jsonb_filters_mitre_tactic_no_match():
    row = make_investigation()
    row.behaviors_json = {
        "detected_behaviors": [
            {"behavior_name": "initial_access", "mitre_tactics": ["TA0001"]}
        ]
    }
    query = HuntQuery(mitre_tactics=["TA0008"])

    assert _matches_jsonb_filters(row, query) is False


def test_matches_jsonb_filters_rule_match():
    row = make_investigation()
    row.behaviors_json = None
    row.timeline_json = {
        "entries": [{"rule_match": ["rule_001"]}]
    }
    query = HuntQuery(rule_matches=["rule_001"])

    assert _matches_jsonb_filters(row, query) is True


def test_matches_jsonb_filters_rule_no_match():
    row = make_investigation()
    row.timeline_json = {"entries": [{"rule_match": ["rule_abc"]}]}
    query = HuntQuery(rule_matches=["rule_xyz"])

    assert _matches_jsonb_filters(row, query) is False


# ─── HuntEngine.run_query ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_query_returns_empty_on_no_rows():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalars_result([]))

    query = HuntQuery()
    result = await HuntEngine.run_query(db, TENANT_ID, query)

    assert result.total == 0
    assert result.entries == []
    assert result.has_more is False


@pytest.mark.asyncio
async def test_run_query_returns_entries():
    db = make_mock_db()
    inv = make_investigation()
    db.execute = AsyncMock(return_value=scalars_result([inv]))

    query = HuntQuery()
    result = await HuntEngine.run_query(db, TENANT_ID, query)

    assert result.total == 1
    assert result.entries[0].investigation_id == INV_ID


@pytest.mark.asyncio
async def test_run_query_generates_cursor_when_more():
    db = make_mock_db()
    invs = [make_investigation(investigation_id=f"inv-{i}") for i in range(51)]
    db.execute = AsyncMock(return_value=scalars_result(invs))

    query = HuntQuery(limit=50)
    result = await HuntEngine.run_query(db, TENANT_ID, query)

    assert result.has_more is True
    assert result.next_cursor is not None
    assert result.total == 50


# ─── save/list/get/delete saved hunts ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_save_hunt_calls_db_add():
    db = make_mock_db()
    payload = SavedHuntCreate(name="My Hunt", query_params={})

    with patch("app.analyst.hunt.SavedHunt") as MockHunt:
        mock_h = MagicMock()
        mock_h.id = HUNT_ID
        MockHunt.return_value = mock_h

        result = await HuntEngine.save_hunt(db, TENANT_ID, ANALYST_ID, payload)

    db.add.assert_called_once_with(mock_h)
    db.flush.assert_awaited()


@pytest.mark.asyncio
async def test_list_saved_hunts_returns_hunts():
    db = make_mock_db()
    h1 = make_saved_hunt(name="Hunt A")
    h2 = make_saved_hunt(name="Hunt B")
    db.execute = AsyncMock(return_value=scalars_result([h1, h2]))

    result = await HuntEngine.list_saved_hunts(db, TENANT_ID)
    assert len(result) == 2


@pytest.mark.asyncio
async def test_get_saved_hunt_returns_hunt():
    db = make_mock_db()
    h = make_saved_hunt()
    db.execute = AsyncMock(return_value=scalar_result(h))

    result = await HuntEngine.get_saved_hunt(db, TENANT_ID, HUNT_ID)
    assert result is h


@pytest.mark.asyncio
async def test_get_saved_hunt_raises_not_found():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    with pytest.raises(NotFoundError):
        await HuntEngine.get_saved_hunt(db, TENANT_ID, HUNT_ID)


@pytest.mark.asyncio
async def test_delete_saved_hunt_calls_delete():
    db = make_mock_db()
    h = make_saved_hunt()
    db.execute = AsyncMock(return_value=scalar_result(h))

    await HuntEngine.delete_saved_hunt(db, TENANT_ID, HUNT_ID)

    db.delete.assert_called_once()


@pytest.mark.asyncio
async def test_delete_saved_hunt_raises_when_missing():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    with pytest.raises(NotFoundError):
        await HuntEngine.delete_saved_hunt(db, TENANT_ID, HUNT_ID)


# ─── Cursor helpers ───────────────────────────────────────────────────────────

def test_encode_decode_cursor_roundtrip():
    ts = "2024-01-15T12:00:00+00:00"
    uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    cursor = _encode_cursor(ts, uid)
    ts_out, id_out = _decode_cursor(cursor)
    assert ts_out == ts
    assert id_out == uid

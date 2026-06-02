from __future__ import annotations

from datetime import datetime, timezone

import pytest
from unittest.mock import AsyncMock

from app.analyst.timeline_api import (
    TimelineService,
    _apply_timeline_filters,
    _encode_timeline_cursor,
    _decode_timeline_cursor,
)
from app.analyst.schemas import TimelineFilter
from app.core.exceptions import NotFoundError

from .conftest import (
    ANALYST_ID, TENANT_ID, INV_ID,
    make_mock_db, scalar_result,
    make_investigation,
)

_TS_BASE = 1_700_000_000.0


def _make_entry(
    *,
    event_id: str = "evt-001",
    timestamp: float = _TS_BASE,
    hostname: str = "ws-01",
    category: str = "process",
    severity: int = 3,
    entity_keys: list[str] | None = None,
    rule_match: list[str] | None = None,
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "hostname": hostname,
        "category": category,
        "severity": severity,
        "action": "process_create",
        "outcome": "success",
        "entity_keys": entity_keys or [f"host:{hostname}"],
        "rule_match": rule_match or [],
    }


# ─── _apply_timeline_filters ─────────────────────────────────────────────────

def test_apply_filters_no_filters_returns_all():
    entries = [_make_entry(event_id=f"e{i}") for i in range(5)]
    f = TimelineFilter()
    result = _apply_timeline_filters(entries, f)
    assert len(result) == 5


def test_apply_filters_from_ts():
    entries = [
        _make_entry(event_id="early", timestamp=_TS_BASE - 100),
        _make_entry(event_id="late",  timestamp=_TS_BASE + 100),
    ]
    dt = datetime.fromtimestamp(_TS_BASE, tz=timezone.utc)
    f = TimelineFilter(from_ts=dt)
    result = _apply_timeline_filters(entries, f)
    assert len(result) == 1
    assert result[0]["event_id"] == "late"


def test_apply_filters_to_ts():
    entries = [
        _make_entry(event_id="early", timestamp=_TS_BASE - 100),
        _make_entry(event_id="late",  timestamp=_TS_BASE + 100),
    ]
    dt = datetime.fromtimestamp(_TS_BASE, tz=timezone.utc)
    f = TimelineFilter(to_ts=dt)
    result = _apply_timeline_filters(entries, f)
    assert len(result) == 1
    assert result[0]["event_id"] == "early"


def test_apply_filters_severity_min():
    entries = [
        _make_entry(event_id="low",  severity=2),
        _make_entry(event_id="high", severity=7),
    ]
    f = TimelineFilter(severity_min=5)
    result = _apply_timeline_filters(entries, f)
    assert len(result) == 1
    assert result[0]["event_id"] == "high"


def test_apply_filters_category_exact_match():
    entries = [
        _make_entry(event_id="proc", category="process"),
        _make_entry(event_id="net",  category="network"),
    ]
    f = TimelineFilter(category="process")
    result = _apply_timeline_filters(entries, f)
    assert len(result) == 1
    assert result[0]["event_id"] == "proc"


def test_apply_filters_category_case_insensitive():
    entries = [_make_entry(category="PROCESS")]
    f = TimelineFilter(category="process")
    result = _apply_timeline_filters(entries, f)
    assert len(result) == 1


def test_apply_filters_entity_filter_hostname():
    entries = [
        _make_entry(event_id="ws1", hostname="workstation-01"),
        _make_entry(event_id="srv", hostname="server-02"),
    ]
    f = TimelineFilter(entity_filter="workstation")
    result = _apply_timeline_filters(entries, f)
    assert len(result) == 1
    assert result[0]["event_id"] == "ws1"


def test_apply_filters_entity_filter_entity_key():
    entries = [
        _make_entry(event_id="e1", entity_keys=["host:ws-01", "user:alice"]),
        _make_entry(event_id="e2", entity_keys=["host:srv-02"]),
    ]
    f = TimelineFilter(entity_filter="alice")
    result = _apply_timeline_filters(entries, f)
    assert len(result) == 1
    assert result[0]["event_id"] == "e1"


def test_apply_filters_combined():
    entries = [
        _make_entry(event_id="e1", category="process", severity=5),
        _make_entry(event_id="e2", category="network", severity=5),
        _make_entry(event_id="e3", category="process", severity=2),
    ]
    f = TimelineFilter(category="process", severity_min=4)
    result = _apply_timeline_filters(entries, f)
    assert len(result) == 1
    assert result[0]["event_id"] == "e1"


# ─── Cursor helpers ───────────────────────────────────────────────────────────

def test_encode_decode_cursor_roundtrip():
    idx = 25
    cursor = _encode_timeline_cursor(idx)
    assert _decode_timeline_cursor(cursor) == idx


def test_encode_cursor_index_zero():
    cursor = _encode_timeline_cursor(0)
    assert _decode_timeline_cursor(cursor) == 0


def test_encode_cursor_large_index():
    cursor = _encode_timeline_cursor(1000)
    assert _decode_timeline_cursor(cursor) == 1000


# ─── TimelineService.get_timeline ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_timeline_null_json_returns_empty():
    db = make_mock_db()
    inv = make_investigation()
    inv.timeline_json = None
    db.execute = AsyncMock(return_value=scalar_result(inv))

    filters = TimelineFilter()
    result = await TimelineService.get_timeline(db, TENANT_ID, INV_ID, filters)

    assert result.entries == []
    assert result.total_events == 0
    assert result.has_more is False


@pytest.mark.asyncio
async def test_get_timeline_empty_json_returns_empty():
    db = make_mock_db()
    inv = make_investigation()
    inv.timeline_json = {}
    db.execute = AsyncMock(return_value=scalar_result(inv))

    result = await TimelineService.get_timeline(db, TENANT_ID, INV_ID, TimelineFilter())
    assert result.entries == []


@pytest.mark.asyncio
async def test_get_timeline_returns_entries():
    db = make_mock_db()
    inv = make_investigation()
    inv.timeline_json = {
        "entries": [_make_entry(event_id="e1"), _make_entry(event_id="e2")],
        "total_events": 2,
    }
    db.execute = AsyncMock(return_value=scalar_result(inv))

    result = await TimelineService.get_timeline(db, TENANT_ID, INV_ID, TimelineFilter())

    assert len(result.entries) == 2
    assert result.total_events == 2


@pytest.mark.asyncio
async def test_get_timeline_raises_not_found():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    with pytest.raises(NotFoundError):
        await TimelineService.get_timeline(db, TENANT_ID, INV_ID, TimelineFilter())


@pytest.mark.asyncio
async def test_get_timeline_has_more_and_cursor():
    db = make_mock_db()
    inv = make_investigation()
    entries = [_make_entry(event_id=f"e{i}", timestamp=_TS_BASE + i) for i in range(10)]
    inv.timeline_json = {"entries": entries, "total_events": 10}
    db.execute = AsyncMock(return_value=scalar_result(inv))

    # Request only 5 per page
    result = await TimelineService.get_timeline(
        db, TENANT_ID, INV_ID, TimelineFilter(limit=5)
    )

    assert len(result.entries) == 5
    assert result.has_more is True
    assert result.next_cursor is not None


@pytest.mark.asyncio
async def test_get_timeline_cursor_fetches_next_page():
    db = make_mock_db()
    inv = make_investigation()
    entries = [_make_entry(event_id=f"e{i}", timestamp=_TS_BASE + i) for i in range(10)]
    inv.timeline_json = {"entries": entries, "total_events": 10}
    db.execute = AsyncMock(return_value=scalar_result(inv))

    cursor = _encode_timeline_cursor(5)
    result = await TimelineService.get_timeline(
        db, TENANT_ID, INV_ID, TimelineFilter(limit=5, cursor=cursor)
    )

    assert result.entries[0].event_id == "e5"


@pytest.mark.asyncio
async def test_get_timeline_sort_desc():
    db = make_mock_db()
    inv = make_investigation()
    inv.timeline_json = {
        "entries": [
            _make_entry(event_id="early", timestamp=_TS_BASE),
            _make_entry(event_id="late",  timestamp=_TS_BASE + 100),
        ],
    }
    db.execute = AsyncMock(return_value=scalar_result(inv))

    result = await TimelineService.get_timeline(
        db, TENANT_ID, INV_ID, TimelineFilter(sort="desc")
    )

    assert result.entries[0].event_id == "late"


@pytest.mark.asyncio
async def test_get_timeline_sort_asc():
    db = make_mock_db()
    inv = make_investigation()
    inv.timeline_json = {
        "entries": [
            _make_entry(event_id="early", timestamp=_TS_BASE),
            _make_entry(event_id="late",  timestamp=_TS_BASE + 100),
        ],
    }
    db.execute = AsyncMock(return_value=scalar_result(inv))

    result = await TimelineService.get_timeline(
        db, TENANT_ID, INV_ID, TimelineFilter(sort="asc")
    )

    assert result.entries[0].event_id == "early"

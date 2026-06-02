from __future__ import annotations

import base64

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.analyst.activity import ActivityService, AnalystAction, _encode_cursor, _decode_cursor
from .conftest import (
    ANALYST_ID, TENANT_ID, INV_ID,
    make_mock_db, scalar_result, scalars_result,
    make_activity, NOW,
)


# ─── AnalystAction constants ──────────────────────────────────────────────────

def test_analyst_action_opened_investigation():
    assert AnalystAction.OPENED_INVESTIGATION == "investigation.opened"


def test_analyst_action_verdict_set():
    assert AnalystAction.VERDICT_SET == "investigation.verdict_set"


def test_analyst_action_note_added():
    assert AnalystAction.NOTE_ADDED == "investigation.note_added"


def test_analyst_action_assigned():
    assert AnalystAction.ASSIGNED == "investigation.assigned"


def test_analyst_action_hunt_run():
    assert AnalystAction.HUNT_RUN == "investigation.hunt_run"


def test_analyst_action_merged():
    assert AnalystAction.MERGED == "investigation.merged"


# ─── ActivityService.log ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_creates_activity_entry():
    db = make_mock_db()

    with patch("app.analyst.activity.InvestigationActivity") as MockActivity:
        mock_entry = MagicMock()
        mock_entry.id = MagicMock()
        MockActivity.return_value = mock_entry

        result = await ActivityService.log(
            db,
            tenant_id=TENANT_ID,
            investigation_id=INV_ID,
            analyst_id=ANALYST_ID,
            action=AnalystAction.OPENED_INVESTIGATION,
        )

    db.add.assert_called_once_with(mock_entry)
    db.flush.assert_awaited()


@pytest.mark.asyncio
async def test_log_stores_action_and_metadata():
    db = make_mock_db()
    meta = {"new_status": "investigating", "reason": "initial triage"}

    with patch("app.analyst.activity.InvestigationActivity") as MockActivity:
        mock_entry = MagicMock()
        MockActivity.return_value = mock_entry

        await ActivityService.log(
            db,
            tenant_id=TENANT_ID,
            investigation_id=INV_ID,
            analyst_id=ANALYST_ID,
            action=AnalystAction.STATUS_CHANGED,
            metadata=meta,
        )

    call_kwargs = MockActivity.call_args.kwargs
    assert call_kwargs["action"] == AnalystAction.STATUS_CHANGED
    assert call_kwargs["action_data"] == meta


@pytest.mark.asyncio
async def test_log_stores_target_id():
    db = make_mock_db()

    with patch("app.analyst.activity.InvestigationActivity") as MockActivity:
        mock_entry = MagicMock()
        MockActivity.return_value = mock_entry

        await ActivityService.log(
            db,
            tenant_id=TENANT_ID,
            investigation_id=INV_ID,
            analyst_id=ANALYST_ID,
            action=AnalystAction.NOTE_ADDED,
            target_id="some-note-uuid",
        )

    call_kwargs = MockActivity.call_args.kwargs
    assert call_kwargs["target_id"] == "some-note-uuid"


@pytest.mark.asyncio
async def test_log_propagates_db_error():
    db = make_mock_db()
    db.flush = AsyncMock(side_effect=RuntimeError("DB down"))

    with patch("app.analyst.activity.InvestigationActivity"):
        with pytest.raises(RuntimeError, match="DB down"):
            await ActivityService.log(
                db,
                tenant_id=TENANT_ID,
                investigation_id=INV_ID,
                analyst_id=ANALYST_ID,
                action=AnalystAction.OPENED_INVESTIGATION,
            )


# ─── ActivityService.list_activity ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_activity_returns_entries():
    db = make_mock_db()
    a1 = make_activity(action=AnalystAction.NOTE_ADDED)
    a2 = make_activity(action=AnalystAction.STATUS_CHANGED)
    db.execute = AsyncMock(return_value=scalars_result([a1, a2]))

    rows, next_cursor = await ActivityService.list_activity(db, TENANT_ID, INV_ID)

    assert len(rows) == 2
    assert next_cursor is None


@pytest.mark.asyncio
async def test_list_activity_empty():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalars_result([]))

    rows, next_cursor = await ActivityService.list_activity(db, TENANT_ID, INV_ID)

    assert rows == []
    assert next_cursor is None


@pytest.mark.asyncio
async def test_list_activity_generates_cursor_when_more_than_limit():
    db = make_mock_db()
    entries = [make_activity() for _ in range(52)]
    # Each has a real created_at and id attribute already set by make_activity
    db.execute = AsyncMock(return_value=scalars_result(entries))

    rows, next_cursor = await ActivityService.list_activity(
        db, TENANT_ID, INV_ID, limit=50
    )

    assert len(rows) == 50
    assert next_cursor is not None


@pytest.mark.asyncio
async def test_list_activity_with_invalid_cursor_ignored():
    db = make_mock_db()
    a1 = make_activity()
    db.execute = AsyncMock(return_value=scalars_result([a1]))

    rows, _ = await ActivityService.list_activity(
        db, TENANT_ID, INV_ID, cursor="invalid-cursor"
    )
    assert len(rows) == 1


# ─── Cursor helpers ───────────────────────────────────────────────────────────

def test_encode_cursor_produces_base64():
    cursor = _encode_cursor("2024-01-15T12:00:00+00:00", "some-uuid")
    decoded = base64.urlsafe_b64decode(cursor.encode()).decode()
    assert "|" in decoded


def test_decode_cursor_roundtrip():
    ts = "2024-01-15T12:00:00+00:00"
    uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    cursor = _encode_cursor(ts, uid)
    ts_out, id_out = _decode_cursor(cursor)
    assert ts_out == ts
    assert id_out == uid

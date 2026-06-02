from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.analyst.notes import NoteService
from app.analyst.schemas import NoteCreate, NoteUpdate
from app.core.exceptions import ForbiddenError, NotFoundError

from .conftest import (
    ANALYST_ID, ANALYST2_ID, ADMIN_ID, TENANT_ID, INV_ID, NOTE_ID,
    make_mock_db, scalar_result, scalars_result,
    make_note,
)


# ─── create ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_note_calls_db_add():
    db = make_mock_db()
    db.execute = AsyncMock()

    payload = NoteCreate(content="Hello analyst", pinned=False)
    with patch("app.analyst.notes.InvestigationNote") as MockNote:
        mock_instance = MagicMock()
        mock_instance.id = NOTE_ID
        MockNote.return_value = mock_instance

        result = await NoteService.create(db, TENANT_ID, INV_ID, ANALYST_ID, payload)

    db.add.assert_called_once_with(mock_instance)
    db.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_note_sets_content():
    db = make_mock_db()
    payload = NoteCreate(content="Important finding", pinned=True)

    with patch("app.analyst.notes.InvestigationNote") as MockNote:
        mock_instance = MagicMock()
        mock_instance.id = NOTE_ID
        MockNote.return_value = mock_instance

        await NoteService.create(db, TENANT_ID, INV_ID, ANALYST_ID, payload)

    call_kwargs = MockNote.call_args.kwargs
    assert call_kwargs["content"] == "Important finding"
    assert call_kwargs["pinned"] is True
    assert call_kwargs["analyst_id"] == ANALYST_ID


# ─── get_by_id ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_by_id_returns_note():
    db = make_mock_db()
    note = make_note()
    db.execute = AsyncMock(return_value=scalar_result(note))

    result = await NoteService.get_by_id(db, TENANT_ID, NOTE_ID)
    assert result is note


@pytest.mark.asyncio
async def test_get_by_id_returns_none_when_missing():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    result = await NoteService.get_by_id(db, TENANT_ID, NOTE_ID)
    assert result is None


# ─── require_by_id ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_require_by_id_raises_not_found():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    with pytest.raises(NotFoundError):
        await NoteService.require_by_id(db, TENANT_ID, NOTE_ID)


@pytest.mark.asyncio
async def test_require_by_id_returns_note():
    db = make_mock_db()
    note = make_note()
    db.execute = AsyncMock(return_value=scalar_result(note))

    result = await NoteService.require_by_id(db, TENANT_ID, NOTE_ID)
    assert result is note


# ─── update ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_note_content_by_author():
    db = make_mock_db()
    note = make_note(analyst_id=ANALYST_ID, content="old content")
    db.execute = AsyncMock(return_value=scalar_result(note))

    payload = NoteUpdate(content="new content")
    result = await NoteService.update(db, TENANT_ID, NOTE_ID, ANALYST_ID, payload)

    assert note.content == "new content"
    db.flush.assert_awaited()


@pytest.mark.asyncio
async def test_update_note_pinned_by_author():
    db = make_mock_db()
    note = make_note(analyst_id=ANALYST_ID, pinned=False)
    db.execute = AsyncMock(return_value=scalar_result(note))

    payload = NoteUpdate(pinned=True)
    await NoteService.update(db, TENANT_ID, NOTE_ID, ANALYST_ID, payload)

    assert note.pinned is True


@pytest.mark.asyncio
async def test_update_note_rejects_non_author():
    db = make_mock_db()
    note = make_note(analyst_id=ANALYST_ID)
    db.execute = AsyncMock(return_value=scalar_result(note))

    payload = NoteUpdate(content="hacked")
    with pytest.raises(ForbiddenError):
        await NoteService.update(db, TENANT_ID, NOTE_ID, ANALYST2_ID, payload)


@pytest.mark.asyncio
async def test_update_note_admin_can_edit_others():
    db = make_mock_db()
    note = make_note(analyst_id=ANALYST_ID, content="original")
    db.execute = AsyncMock(return_value=scalar_result(note))

    payload = NoteUpdate(content="admin update")
    result = await NoteService.update(
        db, TENANT_ID, NOTE_ID, ADMIN_ID, payload, is_admin=True
    )
    assert note.content == "admin update"


@pytest.mark.asyncio
async def test_update_partial_no_content_unchanged():
    db = make_mock_db()
    note = make_note(analyst_id=ANALYST_ID, content="keep this", pinned=False)
    db.execute = AsyncMock(return_value=scalar_result(note))

    payload = NoteUpdate(pinned=True)
    await NoteService.update(db, TENANT_ID, NOTE_ID, ANALYST_ID, payload)

    assert note.content == "keep this"
    assert note.pinned is True


# ─── delete ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_note_calls_soft_delete():
    db = make_mock_db()
    note = make_note(analyst_id=ANALYST_ID)
    db.execute = AsyncMock(return_value=scalar_result(note))

    await NoteService.delete(db, TENANT_ID, NOTE_ID, ANALYST_ID)

    note.soft_delete.assert_called_once()
    db.flush.assert_awaited()


@pytest.mark.asyncio
async def test_delete_note_rejects_non_author():
    db = make_mock_db()
    note = make_note(analyst_id=ANALYST_ID)
    db.execute = AsyncMock(return_value=scalar_result(note))

    with pytest.raises(ForbiddenError):
        await NoteService.delete(db, TENANT_ID, NOTE_ID, ANALYST2_ID)


@pytest.mark.asyncio
async def test_delete_note_admin_bypass():
    db = make_mock_db()
    note = make_note(analyst_id=ANALYST_ID)
    db.execute = AsyncMock(return_value=scalar_result(note))

    await NoteService.delete(db, TENANT_ID, NOTE_ID, ADMIN_ID, is_admin=True)
    note.soft_delete.assert_called_once()


# ─── set_pin ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_set_pin_true():
    db = make_mock_db()
    note = make_note(pinned=False)
    db.execute = AsyncMock(return_value=scalar_result(note))

    result = await NoteService.set_pin(db, TENANT_ID, NOTE_ID, pinned=True)
    assert note.pinned is True


@pytest.mark.asyncio
async def test_set_pin_false():
    db = make_mock_db()
    note = make_note(pinned=True)
    db.execute = AsyncMock(return_value=scalar_result(note))

    await NoteService.set_pin(db, TENANT_ID, NOTE_ID, pinned=False)
    assert note.pinned is False


# ─── list_for_investigation ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_for_investigation_returns_rows_and_total():
    db = make_mock_db()
    notes = [make_note(note_id=NOTE_ID), make_note(note_id=NOTE_ID)]
    db.execute = AsyncMock(side_effect=[
        scalar_result(2),       # count query
        scalars_result(notes),  # rows query
    ])

    rows, total = await NoteService.list_for_investigation(db, TENANT_ID, INV_ID)

    assert total == 2
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_list_for_investigation_empty():
    db = make_mock_db()
    db.execute = AsyncMock(side_effect=[
        scalar_result(0),
        scalars_result([]),
    ])

    rows, total = await NoteService.list_for_investigation(db, TENANT_ID, INV_ID)

    assert total == 0
    assert rows == []


# ─── count ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_count_for_investigation():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(7))

    count = await NoteService.count_for_investigation(db, TENANT_ID, INV_ID)
    assert count == 7

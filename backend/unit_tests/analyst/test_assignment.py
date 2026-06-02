from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.analyst.assignment import AssignmentService
from app.analyst.schemas import AssignmentCreate
from app.core.exceptions import NotFoundError

from .conftest import (
    ANALYST_ID, ANALYST2_ID, ADMIN_ID, TENANT_ID, INV_ID, ASSIGN_ID,
    make_mock_db, scalar_result, scalars_result,
    make_investigation, make_assignment,
)


# ─── assign ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_assign_calls_db_add():
    db = make_mock_db()
    inv = make_investigation()
    db.execute = AsyncMock(side_effect=[
        scalar_result(inv),  # _require_investigation
        MagicMock(),         # _deactivate_current UPDATE
    ])

    payload = AssignmentCreate(assigned_to=ANALYST_ID)
    await AssignmentService.assign(db, TENANT_ID, INV_ID, ADMIN_ID, payload)

    assert db.add.called
    db.flush.assert_awaited()


@pytest.mark.asyncio
async def test_assign_updates_investigation_assigned_to():
    db = make_mock_db()
    inv = make_investigation(assigned_to=None)
    db.execute = AsyncMock(side_effect=[
        scalar_result(inv),
        MagicMock(),
    ])

    payload = AssignmentCreate(assigned_to=ANALYST2_ID)
    await AssignmentService.assign(db, TENANT_ID, INV_ID, ADMIN_ID, payload)

    assert inv.assigned_to == ANALYST2_ID


@pytest.mark.asyncio
async def test_assign_escalated_flag_stored():
    db = make_mock_db()
    inv = make_investigation()
    db.execute = AsyncMock(side_effect=[
        scalar_result(inv),
        MagicMock(),
    ])

    payload = AssignmentCreate(
        assigned_to=ANALYST_ID,
        escalated=True,
        escalation_reason="P0 incident",
    )
    result = await AssignmentService.assign(db, TENANT_ID, INV_ID, ADMIN_ID, payload)

    # The ORM object is created with the right fields
    assert result.escalated is True
    assert result.escalation_reason == "P0 incident"


@pytest.mark.asyncio
async def test_assign_raises_not_found_when_no_investigation():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    payload = AssignmentCreate(assigned_to=ANALYST_ID)
    with pytest.raises(NotFoundError):
        await AssignmentService.assign(db, TENANT_ID, INV_ID, ADMIN_ID, payload)


@pytest.mark.asyncio
async def test_assign_sets_assigned_to_field():
    db = make_mock_db()
    inv = make_investigation()
    db.execute = AsyncMock(side_effect=[
        scalar_result(inv),
        MagicMock(),
    ])

    payload = AssignmentCreate(assigned_to=ANALYST2_ID)
    result = await AssignmentService.assign(db, TENANT_ID, INV_ID, ADMIN_ID, payload)

    assert result.assigned_to == ANALYST2_ID
    assert result.assigned_by == ADMIN_ID
    assert result.is_active is True


# ─── unassign ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unassign_clears_assigned_to():
    db = make_mock_db()
    inv = make_investigation(assigned_to=ANALYST_ID)
    db.execute = AsyncMock(side_effect=[
        scalar_result(inv),
        MagicMock(),
    ])

    await AssignmentService.unassign(db, TENANT_ID, INV_ID, ADMIN_ID)

    assert inv.assigned_to is None
    db.flush.assert_awaited()


# ─── escalate ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_escalate_creates_escalated_assignment():
    db = make_mock_db()
    inv = make_investigation()
    existing_assign = make_assignment(assigned_to=ANALYST_ID, is_active=True)
    db.execute = AsyncMock(side_effect=[
        scalar_result(existing_assign),  # get_current
        scalar_result(inv),              # _require_investigation in assign
        MagicMock(),                     # _deactivate_current
    ])

    result = await AssignmentService.escalate(
        db, TENANT_ID, INV_ID, ADMIN_ID, "P0 incident"
    )

    assert result.escalated is True
    assert result.escalation_reason == "P0 incident"


@pytest.mark.asyncio
async def test_escalate_uses_provided_new_assignee():
    db = make_mock_db()
    inv = make_investigation()
    db.execute = AsyncMock(side_effect=[
        scalar_result(None),  # get_current → no active assignment
        scalar_result(inv),
        MagicMock(),
    ])

    result = await AssignmentService.escalate(
        db, TENANT_ID, INV_ID, ADMIN_ID, "urgent",
        new_assignee=ANALYST2_ID,
    )

    assert result.assigned_to == ANALYST2_ID
    assert result.escalated is True


@pytest.mark.asyncio
async def test_escalate_uses_existing_assignee_when_no_new():
    db = make_mock_db()
    inv = make_investigation()
    existing = make_assignment(assigned_to=ANALYST_ID)
    db.execute = AsyncMock(side_effect=[
        scalar_result(existing),
        scalar_result(inv),
        MagicMock(),
    ])

    result = await AssignmentService.escalate(
        db, TENANT_ID, INV_ID, ADMIN_ID, "escalate same analyst"
    )

    assert result.assigned_to == ANALYST_ID


# ─── transfer ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_transfer_creates_non_escalated_assignment():
    db = make_mock_db()
    inv = make_investigation()
    db.execute = AsyncMock(side_effect=[
        scalar_result(inv),
        MagicMock(),
    ])

    result = await AssignmentService.transfer(db, TENANT_ID, INV_ID, ANALYST2_ID, ADMIN_ID)

    assert result.assigned_to == ANALYST2_ID
    assert result.escalated is False


# ─── get_current ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_current_returns_active_assignment():
    db = make_mock_db()
    assignment = make_assignment(is_active=True)
    db.execute = AsyncMock(return_value=scalar_result(assignment))

    result = await AssignmentService.get_current(db, TENANT_ID, INV_ID)
    assert result is assignment


@pytest.mark.asyncio
async def test_get_current_returns_none_when_unassigned():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    result = await AssignmentService.get_current(db, TENANT_ID, INV_ID)
    assert result is None


# ─── list_history ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_history_returns_all_assignments():
    db = make_mock_db()
    a1 = make_assignment(is_active=False)
    a2 = make_assignment(is_active=True)
    db.execute = AsyncMock(return_value=scalars_result([a2, a1]))

    result = await AssignmentService.list_history(db, TENANT_ID, INV_ID)
    assert len(result) == 2


@pytest.mark.asyncio
async def test_list_history_empty():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalars_result([]))

    result = await AssignmentService.list_history(db, TENANT_ID, INV_ID)
    assert result == []

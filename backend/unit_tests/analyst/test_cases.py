from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.analyst.cases import CaseService
from app.analyst.schemas import STATUS_TRANSITIONS, VerdictCreate, InvestigationVerdict as VerdictEnum
from app.core.exceptions import NotFoundError, ValidationError

from .conftest import (
    ANALYST_ID, TENANT_ID, INV_ID, INV_ID_2,
    make_mock_db, scalar_result, scalars_result,
    make_investigation,
)


# ─── get_investigation ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_investigation_returns_found():
    db = make_mock_db()
    inv = make_investigation()
    db.execute = AsyncMock(return_value=scalar_result(inv))

    result = await CaseService.get_investigation(db, TENANT_ID, INV_ID)
    assert result is inv


@pytest.mark.asyncio
async def test_get_investigation_raises_not_found():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    with pytest.raises(NotFoundError):
        await CaseService.get_investigation(db, TENANT_ID, INV_ID)


# ─── change_status ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_change_status_new_to_triaged():
    db = make_mock_db()
    inv = make_investigation(status="new")
    db.execute = AsyncMock(return_value=scalar_result(inv))

    result = await CaseService.change_status(
        db, TENANT_ID, INV_ID, ANALYST_ID, "triaged"
    )

    assert inv.status == "triaged"
    db.flush.assert_awaited()


@pytest.mark.asyncio
async def test_change_status_new_to_investigating():
    db = make_mock_db()
    inv = make_investigation(status="new")
    db.execute = AsyncMock(return_value=scalar_result(inv))

    await CaseService.change_status(db, TENANT_ID, INV_ID, ANALYST_ID, "investigating")
    assert inv.status == "investigating"


@pytest.mark.asyncio
async def test_change_status_invalid_transition_raises():
    db = make_mock_db()
    inv = make_investigation(status="new")
    db.execute = AsyncMock(return_value=scalar_result(inv))

    with pytest.raises(ValidationError):
        await CaseService.change_status(
            db, TENANT_ID, INV_ID, ANALYST_ID, "resolved"
        )


@pytest.mark.asyncio
async def test_change_status_closed_to_investigating_allowed():
    db = make_mock_db()
    inv = make_investigation(status="closed")
    db.execute = AsyncMock(return_value=scalar_result(inv))

    await CaseService.change_status(db, TENANT_ID, INV_ID, ANALYST_ID, "investigating")
    assert inv.status == "investigating"


@pytest.mark.asyncio
async def test_change_status_false_positive_to_investigating_allowed():
    db = make_mock_db()
    inv = make_investigation(status="false_positive")
    db.execute = AsyncMock(return_value=scalar_result(inv))

    await CaseService.change_status(db, TENANT_ID, INV_ID, ANALYST_ID, "investigating")
    assert inv.status == "investigating"


# ─── STATUS_TRANSITIONS coverage ─────────────────────────────────────────────

def test_status_transitions_new_allows_triaged():
    assert "triaged" in STATUS_TRANSITIONS["new"]


def test_status_transitions_new_allows_investigating():
    assert "investigating" in STATUS_TRANSITIONS["new"]


def test_status_transitions_new_allows_closed():
    assert "closed" in STATUS_TRANSITIONS["new"]


def test_status_transitions_investigating_allows_contained():
    assert "contained" in STATUS_TRANSITIONS["investigating"]


def test_status_transitions_investigating_allows_resolved():
    assert "resolved" in STATUS_TRANSITIONS["investigating"]


def test_status_transitions_investigating_allows_false_positive():
    assert "false_positive" in STATUS_TRANSITIONS["investigating"]


def test_status_transitions_resolved_allows_closed():
    assert "closed" in STATUS_TRANSITIONS["resolved"]


# ─── open_case ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_open_case_already_investigating_returns_as_is():
    db = make_mock_db()
    inv = make_investigation(status="investigating")
    db.execute = AsyncMock(return_value=scalar_result(inv))

    result = await CaseService.open_case(db, TENANT_ID, INV_ID, ANALYST_ID)
    assert result.status == "investigating"
    db.flush.assert_not_awaited()


@pytest.mark.asyncio
async def test_open_case_from_new_transitions_to_investigating():
    db = make_mock_db()
    inv = make_investigation(status="new")
    db.execute = AsyncMock(return_value=scalar_result(inv))

    result = await CaseService.open_case(db, TENANT_ID, INV_ID, ANALYST_ID)
    assert inv.status == "investigating"


# ─── close_case ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_close_case_sets_closed_status():
    db = make_mock_db()
    inv = make_investigation(status="investigating")
    db.execute = AsyncMock(return_value=scalar_result(inv))

    result = await CaseService.close_case(db, TENANT_ID, INV_ID, ANALYST_ID)
    assert inv.status == "closed"


@pytest.mark.asyncio
async def test_close_case_with_false_positive_verdict():
    db = make_mock_db()
    inv = make_investigation(status="investigating", verdict=None)
    db.execute = AsyncMock(return_value=scalar_result(inv))

    verdict_payload = VerdictCreate(verdict=VerdictEnum.FALSE_POSITIVE)

    with patch("app.analyst.cases.VerdictService.set_verdict", new_callable=AsyncMock):
        result = await CaseService.close_case(
            db, TENANT_ID, INV_ID, ANALYST_ID, verdict_payload
        )

    assert inv.status == "false_positive"


# ─── reopen_case ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_reopen_case_from_closed():
    db = make_mock_db()
    inv = make_investigation(status="closed")
    db.execute = AsyncMock(return_value=scalar_result(inv))

    await CaseService.reopen_case(db, TENANT_ID, INV_ID, ANALYST_ID)
    assert inv.status == "investigating"


# ─── merge ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_merge_closes_secondary_investigations():
    db = make_mock_db()
    primary = make_investigation(investigation_id=INV_ID, status="investigating")
    secondary = make_investigation(investigation_id=INV_ID_2, status="new")

    db.execute = AsyncMock(side_effect=[
        scalar_result(primary),    # get primary
        scalar_result(secondary),  # get secondary
    ])

    from app.analyst.schemas import MergeRequest
    payload = MergeRequest(
        primary_investigation_id=INV_ID,
        secondary_investigation_ids=[INV_ID_2],
    )
    result = await CaseService.merge(db, TENANT_ID, ANALYST_ID, payload)

    assert result is primary
    assert secondary.status == "closed"


@pytest.mark.asyncio
async def test_merge_skips_secondary_if_same_as_primary():
    db = make_mock_db()
    primary = make_investigation(investigation_id=INV_ID, status="investigating")
    db.execute = AsyncMock(return_value=scalar_result(primary))

    from app.analyst.schemas import MergeRequest
    payload = MergeRequest(
        primary_investigation_id=INV_ID,
        secondary_investigation_ids=[INV_ID],  # same as primary
    )
    result = await CaseService.merge(db, TENANT_ID, ANALYST_ID, payload)
    assert result is primary
    assert primary.status == "investigating"  # unchanged


# ─── list_investigations ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_investigations_returns_rows():
    db = make_mock_db()
    inv1 = make_investigation(investigation_id="inv-aaa", status="new")
    inv2 = make_investigation(investigation_id="inv-bbb", status="investigating")
    db.execute = AsyncMock(return_value=scalars_result([inv1, inv2]))

    rows, next_cursor = await CaseService.list_investigations(db, TENANT_ID)
    assert len(rows) == 2
    assert next_cursor is None


@pytest.mark.asyncio
async def test_list_investigations_status_filter_applied():
    db = make_mock_db()
    inv = make_investigation(status="investigating")
    db.execute = AsyncMock(return_value=scalars_result([inv]))

    rows, _ = await CaseService.list_investigations(
        db, TENANT_ID, status="investigating"
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_list_investigations_generates_cursor_when_more():
    db = make_mock_db()
    invs = [make_investigation(investigation_id=f"inv-{i}") for i in range(51)]
    db.execute = AsyncMock(return_value=scalars_result(invs))

    rows, next_cursor = await CaseService.list_investigations(db, TENANT_ID, limit=50)

    assert len(rows) == 50
    assert next_cursor is not None


@pytest.mark.asyncio
async def test_list_investigations_empty():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalars_result([]))

    rows, next_cursor = await CaseService.list_investigations(db, TENANT_ID)
    assert rows == []
    assert next_cursor is None

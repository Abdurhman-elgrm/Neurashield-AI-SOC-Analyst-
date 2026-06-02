from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.analyst.verdicts import VerdictService
from app.analyst.schemas import InvestigationVerdict as VerdictEnum, VerdictCreate
from app.core.exceptions import NotFoundError

from .conftest import (
    ANALYST_ID, TENANT_ID, INV_ID, VERDICT_ID,
    make_mock_db, scalar_result, scalars_result,
    make_investigation, make_verdict_row,
)


# ─── set_verdict ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_set_verdict_creates_row():
    db = make_mock_db()
    inv = make_investigation(verdict=None)
    db.execute = AsyncMock(return_value=scalar_result(inv))

    payload = VerdictCreate(
        verdict=VerdictEnum.TRUE_POSITIVE,
        reasoning="Confirmed malicious activity",
    )

    with patch("app.analyst.verdicts.InvestigationVerdict") as MockVerdict:
        mock_row = MagicMock()
        mock_row.id = VERDICT_ID
        MockVerdict.return_value = mock_row

        result = await VerdictService.set_verdict(
            db, TENANT_ID, INV_ID, ANALYST_ID, payload
        )

    db.add.assert_called_once_with(mock_row)
    db.flush.assert_awaited()


@pytest.mark.asyncio
async def test_set_verdict_updates_investigation_fields():
    db = make_mock_db()
    inv = make_investigation(verdict=None)
    db.execute = AsyncMock(return_value=scalar_result(inv))

    payload = VerdictCreate(verdict=VerdictEnum.FALSE_POSITIVE)

    with patch("app.analyst.verdicts.InvestigationVerdict"):
        await VerdictService.set_verdict(db, TENANT_ID, INV_ID, ANALYST_ID, payload)

    assert inv.verdict == "false_positive"
    assert inv.verdict_set_by == ANALYST_ID
    assert inv.verdict_set_at is not None


@pytest.mark.asyncio
async def test_set_verdict_records_previous_verdict():
    db = make_mock_db()
    inv = make_investigation(verdict="suspicious")
    db.execute = AsyncMock(return_value=scalar_result(inv))

    payload = VerdictCreate(verdict=VerdictEnum.TRUE_POSITIVE)

    with patch("app.analyst.verdicts.InvestigationVerdict") as MockVerdict:
        mock_row = MagicMock()
        MockVerdict.return_value = mock_row

        await VerdictService.set_verdict(db, TENANT_ID, INV_ID, ANALYST_ID, payload)

    call_kwargs = MockVerdict.call_args.kwargs
    assert call_kwargs["previous_verdict"] == "suspicious"
    assert call_kwargs["new_verdict"] == "true_positive"


@pytest.mark.asyncio
async def test_set_verdict_raises_not_found():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    payload = VerdictCreate(verdict=VerdictEnum.TRUE_POSITIVE)
    with pytest.raises(NotFoundError):
        await VerdictService.set_verdict(db, TENANT_ID, INV_ID, ANALYST_ID, payload)


@pytest.mark.asyncio
async def test_set_verdict_preserves_reasoning():
    db = make_mock_db()
    inv = make_investigation(verdict=None)
    db.execute = AsyncMock(return_value=scalar_result(inv))

    payload = VerdictCreate(
        verdict=VerdictEnum.BENIGN_POSITIVE,
        reasoning="Authorized pen test",
    )

    with patch("app.analyst.verdicts.InvestigationVerdict") as MockVerdict:
        mock_row = MagicMock()
        MockVerdict.return_value = mock_row

        await VerdictService.set_verdict(db, TENANT_ID, INV_ID, ANALYST_ID, payload)

    call_kwargs = MockVerdict.call_args.kwargs
    assert call_kwargs["reasoning"] == "Authorized pen test"


@pytest.mark.asyncio
async def test_set_verdict_with_no_reasoning():
    db = make_mock_db()
    inv = make_investigation(verdict=None)
    db.execute = AsyncMock(return_value=scalar_result(inv))

    payload = VerdictCreate(verdict=VerdictEnum.INCONCLUSIVE)

    with patch("app.analyst.verdicts.InvestigationVerdict") as MockVerdict:
        mock_row = MagicMock()
        MockVerdict.return_value = mock_row

        await VerdictService.set_verdict(db, TENANT_ID, INV_ID, ANALYST_ID, payload)

    call_kwargs = MockVerdict.call_args.kwargs
    assert call_kwargs.get("reasoning") is None


# ─── get_current_verdict ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_current_verdict_returns_latest():
    db = make_mock_db()
    vrow = make_verdict_row(new_verdict="true_positive")
    db.execute = AsyncMock(return_value=scalar_result(vrow))

    result = await VerdictService.get_current_verdict(db, TENANT_ID, INV_ID)
    assert result is vrow


@pytest.mark.asyncio
async def test_get_current_verdict_returns_none_when_absent():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    result = await VerdictService.get_current_verdict(db, TENANT_ID, INV_ID)
    assert result is None


# ─── get_verdict_history ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_verdict_history_returns_all():
    db = make_mock_db()
    v1 = make_verdict_row(new_verdict="suspicious")
    v2 = make_verdict_row(new_verdict="true_positive")
    db.execute = AsyncMock(return_value=scalars_result([v2, v1]))

    history = await VerdictService.get_verdict_history(db, TENANT_ID, INV_ID)
    assert len(history) == 2


@pytest.mark.asyncio
async def test_get_verdict_history_empty():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalars_result([]))

    history = await VerdictService.get_verdict_history(db, TENANT_ID, INV_ID)
    assert history == []


# ─── is_valid_verdict ─────────────────────────────────────────────────────────

def test_is_valid_verdict_true_positive():
    assert VerdictService.is_valid_verdict("true_positive") is True


def test_is_valid_verdict_false_positive():
    assert VerdictService.is_valid_verdict("false_positive") is True


def test_is_valid_verdict_benign_positive():
    assert VerdictService.is_valid_verdict("benign_positive") is True


def test_is_valid_verdict_suspicious():
    assert VerdictService.is_valid_verdict("suspicious") is True


def test_is_valid_verdict_inconclusive():
    assert VerdictService.is_valid_verdict("inconclusive") is True


def test_is_valid_verdict_invalid_string():
    assert VerdictService.is_valid_verdict("definitely_malicious") is False


def test_is_valid_verdict_empty_string():
    assert VerdictService.is_valid_verdict("") is False


def test_all_enum_values_are_valid():
    for v in VerdictEnum:
        assert VerdictService.is_valid_verdict(v.value), f"{v.value!r} should be valid"

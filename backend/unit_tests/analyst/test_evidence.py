from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.analyst.evidence import EvidenceService
from app.analyst.schemas import EvidenceCreate, EvidenceType
from app.core.exceptions import NotFoundError

from .conftest import (
    ANALYST_ID, TENANT_ID, INV_ID, EVIDENCE_ID,
    make_mock_db, scalar_result, scalars_result,
    make_evidence,
)


# ─── attach ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_attach_evidence_calls_db_add():
    db = make_mock_db()
    payload = EvidenceCreate(
        evidence_type=EvidenceType.RAW_EVENT,
        title="Suspicious process tree",
    )

    with patch("app.analyst.evidence.InvestigationEvidence") as MockEv:
        mock_ev = MagicMock()
        mock_ev.id = EVIDENCE_ID
        MockEv.return_value = mock_ev

        result = await EvidenceService.attach(
            db, TENANT_ID, INV_ID, ANALYST_ID, payload
        )

    db.add.assert_called_once_with(mock_ev)
    db.flush.assert_awaited()


@pytest.mark.asyncio
async def test_attach_evidence_stores_type():
    db = make_mock_db()
    payload = EvidenceCreate(
        evidence_type=EvidenceType.IOC_REF,
        title="Malicious IP",
        reference_id="ioc-001",
    )

    with patch("app.analyst.evidence.InvestigationEvidence") as MockEv:
        mock_ev = MagicMock()
        mock_ev.id = EVIDENCE_ID
        MockEv.return_value = mock_ev

        await EvidenceService.attach(db, TENANT_ID, INV_ID, ANALYST_ID, payload)

    call_kwargs = MockEv.call_args.kwargs
    assert call_kwargs["evidence_type"] == "ioc_ref"
    assert call_kwargs["title"] == "Malicious IP"
    assert call_kwargs["reference_id"] == "ioc-001"


@pytest.mark.asyncio
async def test_attach_evidence_correlated_group_type():
    db = make_mock_db()
    payload = EvidenceCreate(
        evidence_type=EvidenceType.CORRELATED_GROUP,
        title="Alert group",
    )

    with patch("app.analyst.evidence.InvestigationEvidence") as MockEv:
        mock_ev = MagicMock()
        mock_ev.id = EVIDENCE_ID
        MockEv.return_value = mock_ev

        await EvidenceService.attach(db, TENANT_ID, INV_ID, ANALYST_ID, payload)

    call_kwargs = MockEv.call_args.kwargs
    assert call_kwargs["evidence_type"] == "correlated_group"


# ─── get_by_id ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_by_id_returns_evidence():
    db = make_mock_db()
    ev = make_evidence()
    db.execute = AsyncMock(return_value=scalar_result(ev))

    result = await EvidenceService.get_by_id(db, TENANT_ID, EVIDENCE_ID)
    assert result is ev


@pytest.mark.asyncio
async def test_get_by_id_returns_none_when_missing():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    result = await EvidenceService.get_by_id(db, TENANT_ID, EVIDENCE_ID)
    assert result is None


# ─── require_by_id ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_require_by_id_raises_not_found():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    with pytest.raises(NotFoundError):
        await EvidenceService.require_by_id(db, TENANT_ID, EVIDENCE_ID)


# ─── list_for_investigation ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_for_investigation_all_types():
    db = make_mock_db()
    ev1 = make_evidence(evidence_type="raw_event")
    ev2 = make_evidence(evidence_type="ioc_ref")
    db.execute = AsyncMock(return_value=scalars_result([ev1, ev2]))

    result = await EvidenceService.list_for_investigation(db, TENANT_ID, INV_ID)
    assert len(result) == 2


@pytest.mark.asyncio
async def test_list_for_investigation_with_valid_type_filter():
    db = make_mock_db()
    ev = make_evidence(evidence_type="raw_event")
    db.execute = AsyncMock(return_value=scalars_result([ev]))

    result = await EvidenceService.list_for_investigation(
        db, TENANT_ID, INV_ID, evidence_type="raw_event"
    )
    assert len(result) == 1


@pytest.mark.asyncio
async def test_list_for_investigation_invalid_type_ignored():
    db = make_mock_db()
    ev = make_evidence()
    db.execute = AsyncMock(return_value=scalars_result([ev]))

    result = await EvidenceService.list_for_investigation(
        db, TENANT_ID, INV_ID, evidence_type="not_a_real_type"
    )
    assert len(result) == 1


# ─── detach ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detach_calls_db_delete():
    db = make_mock_db()
    ev = make_evidence()
    db.execute = AsyncMock(return_value=scalar_result(ev))

    await EvidenceService.detach(db, TENANT_ID, EVIDENCE_ID)

    db.delete.assert_called_once()
    db.flush.assert_awaited()


@pytest.mark.asyncio
async def test_detach_raises_if_not_found():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(None))

    with pytest.raises(NotFoundError):
        await EvidenceService.detach(db, TENANT_ID, EVIDENCE_ID)


# ─── count ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_count_for_investigation_returns_int():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(3))

    count = await EvidenceService.count_for_investigation(db, TENANT_ID, INV_ID)
    assert count == 3


@pytest.mark.asyncio
async def test_count_for_investigation_zero():
    db = make_mock_db()
    db.execute = AsyncMock(return_value=scalar_result(0))

    count = await EvidenceService.count_for_investigation(db, TENANT_ID, INV_ID)
    assert count == 0

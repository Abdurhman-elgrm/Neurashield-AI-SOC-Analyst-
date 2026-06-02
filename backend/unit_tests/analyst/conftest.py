from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

TENANT_ID   = uuid.UUID("10000000-0000-0000-0000-000000000001")
ANALYST_ID  = uuid.UUID("20000000-0000-0000-0000-000000000002")
ANALYST2_ID = uuid.UUID("20000000-0000-0000-0000-000000000003")
ADMIN_ID    = uuid.UUID("20000000-0000-0000-0000-000000000004")
INV_ID      = "inv-group-aaaa-bbbb-cccc-dddd-eeee"
INV_ID_2    = "inv-group-ffff-gggg-hhhh-iiii-jjjj"
NOTE_ID     = uuid.UUID("30000000-0000-0000-0000-000000000005")
EVIDENCE_ID = uuid.UUID("40000000-0000-0000-0000-000000000006")
ASSIGN_ID   = uuid.UUID("50000000-0000-0000-0000-000000000007")
VERDICT_ID  = uuid.UUID("60000000-0000-0000-0000-000000000008")
HUNT_ID     = uuid.UUID("70000000-0000-0000-0000-000000000009")
NOW         = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


# ─── DB mock helpers ──────────────────────────────────────────────────────────

def make_mock_db():
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.delete = AsyncMock()
    return db


def scalar_result(value):
    r = MagicMock()
    r.scalar_one_or_none.return_value = value
    r.scalar_one.return_value = value
    return r


def scalars_result(values):
    r = MagicMock()
    sc = MagicMock()
    sc.all.return_value = values
    r.scalars.return_value = sc
    return r


# ─── ORM object factories ─────────────────────────────────────────────────────

def make_investigation(
    *,
    investigation_id: str = INV_ID,
    tenant_id: uuid.UUID = TENANT_ID,
    status: str = "new",
    verdict: str | None = None,
    threat_score: int = 75,
    confidence: str = "high",
    tp_probability: float = 0.8,
    fp_probability: float = 0.2,
    assigned_to: uuid.UUID | None = None,
    executive_summary: str = "Summary text",
    technical_summary: str = "Technical text",
):
    inv = MagicMock()
    inv.id = investigation_id
    inv.investigation_group_id = investigation_id
    inv.tenant_id = tenant_id
    inv.status = status
    inv.verdict = verdict
    inv.verdict_set_at = None
    inv.verdict_set_by = None
    inv.threat_score = threat_score
    inv.confidence = confidence
    inv.tp_probability = tp_probability
    inv.fp_probability = fp_probability
    inv.assigned_to = assigned_to
    inv.executive_summary = executive_summary
    inv.technical_summary = technical_summary
    inv.attack_progression = []
    inv.recommended_actions = []
    inv.timeline_json = None
    inv.graph_json = None
    inv.behaviors_json = None
    inv.context_json = None
    inv.created_at = NOW
    inv.updated_at = NOW
    return inv


def make_note(
    *,
    note_id: uuid.UUID = NOTE_ID,
    tenant_id: uuid.UUID = TENANT_ID,
    investigation_id: str = INV_ID,
    analyst_id: uuid.UUID = ANALYST_ID,
    content: str = "Test note content",
    pinned: bool = False,
    deleted_at=None,
):
    note = MagicMock()
    note.id = note_id
    note.tenant_id = tenant_id
    note.investigation_id = investigation_id
    note.analyst_id = analyst_id
    note.content = content
    note.pinned = pinned
    note.deleted_at = deleted_at
    note.created_at = NOW
    note.updated_at = NOW
    note.soft_delete = MagicMock()
    return note


def make_assignment(
    *,
    assign_id: uuid.UUID = ASSIGN_ID,
    tenant_id: uuid.UUID = TENANT_ID,
    investigation_id: str = INV_ID,
    assigned_to: uuid.UUID = ANALYST_ID,
    assigned_by: uuid.UUID = ADMIN_ID,
    is_active: bool = True,
    escalated: bool = False,
    escalation_reason: str | None = None,
):
    a = MagicMock()
    a.id = assign_id
    a.tenant_id = tenant_id
    a.investigation_id = investigation_id
    a.assigned_to = assigned_to
    a.assigned_by = assigned_by
    a.is_active = is_active
    a.escalated = escalated
    a.escalation_reason = escalation_reason
    a.severity = None
    a.assigned_at = NOW
    a.unassigned_at = None
    return a


def make_verdict_row(
    *,
    verdict_id: uuid.UUID = VERDICT_ID,
    tenant_id: uuid.UUID = TENANT_ID,
    investigation_id: str = INV_ID,
    analyst_id: uuid.UUID = ANALYST_ID,
    new_verdict: str = "true_positive",
    previous_verdict: str | None = None,
    reasoning: str = "Confirmed malicious",
):
    v = MagicMock()
    v.id = verdict_id
    v.tenant_id = tenant_id
    v.investigation_id = investigation_id
    v.analyst_id = analyst_id
    v.new_verdict = new_verdict
    v.previous_verdict = previous_verdict
    v.reasoning = reasoning
    v.containment_status = None
    v.created_at = NOW
    return v


def make_evidence(
    *,
    evidence_id: uuid.UUID = EVIDENCE_ID,
    tenant_id: uuid.UUID = TENANT_ID,
    investigation_id: str = INV_ID,
    analyst_id: uuid.UUID = ANALYST_ID,
    evidence_type: str = "raw_event",
    title: str = "Evidence title",
):
    ev = MagicMock()
    ev.id = evidence_id
    ev.tenant_id = tenant_id
    ev.investigation_id = investigation_id
    ev.analyst_id = analyst_id
    ev.evidence_type = evidence_type
    ev.title = title
    ev.description = None
    ev.reference_id = None
    ev.metadata = {}
    ev.created_at = NOW
    return ev


def make_activity(
    *,
    tenant_id: uuid.UUID = TENANT_ID,
    investigation_id: str = INV_ID,
    analyst_id: uuid.UUID = ANALYST_ID,
    action: str = "investigation.opened",
    target_id: str | None = None,
    metadata: dict | None = None,
):
    act = MagicMock()
    act.id = uuid.uuid4()
    act.tenant_id = tenant_id
    act.investigation_id = investigation_id
    act.analyst_id = analyst_id
    act.action = action
    act.target_id = target_id
    act.action_data = metadata or {}
    act.created_at = NOW
    return act


def make_saved_hunt(
    *,
    hunt_id: uuid.UUID = HUNT_ID,
    tenant_id: uuid.UUID = TENANT_ID,
    analyst_id: uuid.UUID = ANALYST_ID,
    name: str = "My Hunt",
    run_count: int = 0,
):
    h = MagicMock()
    h.id = hunt_id
    h.tenant_id = tenant_id
    h.analyst_id = analyst_id
    h.name = name
    h.description = None
    h.query_params = {}
    h.run_count = run_count
    h.created_at = NOW
    h.updated_at = NOW
    return h

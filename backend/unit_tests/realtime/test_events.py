from __future__ import annotations

"""Tests for realtime event constructors."""

import pytest

from app.realtime import channels as ch
from app.realtime import events as ev
from app.realtime.schemas import RealtimeEvent, RealtimeEventType

TENANT_ID  = "aaa00000-0000-0000-0000-000000000001"
ANALYST_ID = "ccc00000-0000-0000-0000-000000000001"
INV_ID     = "ddd00000-0000-0000-0000-000000000001"


def _assert_event(event: RealtimeEvent, event_type: str, channel: str) -> None:
    assert isinstance(event, RealtimeEvent)
    assert event.event_type == event_type
    assert event.channel == channel
    assert event.tenant_id == TENANT_ID
    assert event.v == 2
    assert event.event_id != ""


# ─── Alert events ─────────────────────────────────────────────────────────────

def test_realtime_alert_created():
    payload = {"alert_id": "a1", "severity": "high"}
    event = ev.realtime_alert_created(TENANT_ID, ANALYST_ID, payload)
    _assert_event(event, "alert.created", ch.ALERTS)
    assert event.actor_id == ANALYST_ID
    assert event.payload["alert_id"] == "a1"


def test_realtime_alert_updated():
    event = ev.realtime_alert_updated(TENANT_ID, "system", {"alert_id": "a2"})
    _assert_event(event, "alert.updated", ch.ALERTS)


# ─── Investigation events ─────────────────────────────────────────────────────

def test_realtime_investigation_created():
    event = ev.realtime_investigation_created(
        TENANT_ID, "system", INV_ID, 85, "high", "open"
    )
    _assert_event(event, "investigation.created", ch.INVESTIGATIONS)
    p = event.payload
    assert p["investigation_id"] == INV_ID
    assert p["threat_score"] == 85
    assert p["confidence"] == "high"
    assert p["status"] == "open"


def test_realtime_investigation_updated():
    event = ev.realtime_investigation_updated(
        TENANT_ID, ANALYST_ID, INV_ID, {"status": "closed"}
    )
    _assert_event(event, "investigation.updated", ch.INVESTIGATIONS)
    assert event.payload["investigation_id"] == INV_ID
    assert event.payload["status"] == "closed"


def test_realtime_investigation_assigned():
    event = ev.realtime_investigation_assigned(
        TENANT_ID, ANALYST_ID, INV_ID, ANALYST_ID, False, None
    )
    _assert_event(event, "investigation.assigned", ch.INVESTIGATIONS)
    assert event.payload["assigned_to"] == ANALYST_ID
    assert event.payload["escalated"] is False
    assert event.payload["escalation_reason"] is None


def test_realtime_investigation_assigned_escalated():
    event = ev.realtime_investigation_assigned(
        TENANT_ID, ANALYST_ID, INV_ID, "admin", True, "Severity 1"
    )
    assert event.payload["escalated"] is True
    assert event.payload["escalation_reason"] == "Severity 1"


def test_realtime_verdict_changed():
    event = ev.realtime_verdict_changed(
        TENANT_ID, ANALYST_ID, INV_ID, "true_positive", "unknown", "confirmed C2"
    )
    _assert_event(event, "investigation.verdict_changed", ch.INVESTIGATIONS)
    p = event.payload
    assert p["new_verdict"] == "true_positive"
    assert p["previous_verdict"] == "unknown"
    assert p["reasoning"] == "confirmed C2"


def test_realtime_verdict_changed_no_previous():
    event = ev.realtime_verdict_changed(TENANT_ID, ANALYST_ID, INV_ID, "benign", None, None)
    assert event.payload["previous_verdict"] is None


# ─── Note events ──────────────────────────────────────────────────────────────

def test_realtime_note_created():
    event = ev.realtime_note_created(
        TENANT_ID, ANALYST_ID, INV_ID, "note-1", "Suspicious process", False
    )
    _assert_event(event, "note.created", ch.ACTIVITY)
    assert event.payload["note_id"] == "note-1"
    assert event.payload["content_preview"] == "Suspicious process"
    assert event.payload["pinned"] is False


def test_realtime_note_created_truncates_preview():
    long_preview = "x" * 300
    event = ev.realtime_note_created(
        TENANT_ID, ANALYST_ID, INV_ID, "note-2", long_preview, True
    )
    assert len(event.payload["content_preview"]) == 200


def test_realtime_note_updated():
    event = ev.realtime_note_updated(TENANT_ID, ANALYST_ID, INV_ID, "note-3")
    _assert_event(event, "note.updated", ch.ACTIVITY)
    assert event.payload["note_id"] == "note-3"


# ─── Evidence events ──────────────────────────────────────────────────────────

def test_realtime_evidence_added():
    event = ev.realtime_evidence_added(
        TENANT_ID, ANALYST_ID, INV_ID, "ev-1", "Process dump", "file"
    )
    _assert_event(event, "evidence.added", ch.ACTIVITY)
    p = event.payload
    assert p["evidence_id"] == "ev-1"
    assert p["title"] == "Process dump"
    assert p["evidence_type"] == "file"


# ─── Case events ──────────────────────────────────────────────────────────────

def test_realtime_case_merged():
    event = ev.realtime_case_merged(
        TENANT_ID, ANALYST_ID, INV_ID, ["inv-2", "inv-3"], "duplicate alerts"
    )
    _assert_event(event, "case.merged", ch.CASES)
    p = event.payload
    assert p["primary_investigation_id"] == INV_ID
    assert "inv-2" in p["secondary_investigation_ids"]
    assert p["reason"] == "duplicate alerts"


def test_realtime_case_closed():
    event = ev.realtime_case_closed(TENANT_ID, ANALYST_ID, INV_ID, "true_positive")
    _assert_event(event, "case.closed", ch.CASES)
    assert event.payload["verdict"] == "true_positive"


def test_realtime_case_closed_no_verdict():
    event = ev.realtime_case_closed(TENANT_ID, ANALYST_ID, INV_ID, None)
    assert event.payload["verdict"] is None


# ─── Presence events ──────────────────────────────────────────────────────────

def test_realtime_analyst_joined():
    event = ev.realtime_analyst_joined(TENANT_ID, ANALYST_ID, "Alice", "dashboard")
    _assert_event(event, "analyst.joined", ch.PRESENCE)
    assert event.payload["analyst_id"] == ANALYST_ID
    assert event.payload["display_name"] == "Alice"
    assert event.payload["workspace"] == "dashboard"


def test_realtime_analyst_left():
    event = ev.realtime_analyst_left(TENANT_ID, ANALYST_ID)
    _assert_event(event, "analyst.left", ch.PRESENCE)
    assert event.payload["analyst_id"] == ANALYST_ID


def test_realtime_analyst_typing():
    event = ev.realtime_analyst_typing(TENANT_ID, ANALYST_ID, INV_ID)
    _assert_event(event, "analyst.typing", ch.PRESENCE)
    assert event.payload["analyst_id"] == ANALYST_ID
    assert event.payload["investigation_id"] == INV_ID


# ─── Hunt events ──────────────────────────────────────────────────────────────

def test_realtime_hunt_completed():
    event = ev.realtime_hunt_completed(
        TENANT_ID, ANALYST_ID, "hunt-1", 42, "process.name:powershell"
    )
    _assert_event(event, "hunt.completed", ch.HUNTS)
    p = event.payload
    assert p["hunt_id"] == "hunt-1"
    assert p["result_count"] == 42
    assert p["query_summary"] == "process.name:powershell"


def test_realtime_hunt_completed_no_hunt_id():
    event = ev.realtime_hunt_completed(TENANT_ID, ANALYST_ID, None, 0, "")
    assert event.payload["hunt_id"] is None

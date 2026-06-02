from __future__ import annotations

"""Tests for SyncEngine — verifies correct event type, channel, and payload for each method."""

from unittest.mock import AsyncMock, patch

import pytest

from app.realtime import channels as ch
from app.realtime.schemas import RealtimeEvent, RealtimeEventType
from app.realtime.sync import SyncEngine

from unit_tests.realtime.conftest import (
    ANALYST_ID,
    ANALYST2_ID,
    TENANT_ID,
    INV_ID,
    INV_ID_2,
)


def _capture_broadcast():
    """Return a context manager that captures the broadcast_event call args."""
    return patch(
        "app.realtime.sync.RealtimeBroadcaster.broadcast_event",
        new_callable=AsyncMock,
    )


# ─── Investigation events ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_on_investigation_created(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_investigation_created(
            rt_client, TENANT_ID, "system", INV_ID, 85, "high", "open"
        )
        mock_bc.assert_called_once()
        event: RealtimeEvent = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.INVESTIGATION_CREATED
        assert event.channel == ch.INVESTIGATIONS
        assert event.payload["investigation_id"] == INV_ID
        assert event.payload["threat_score"] == 85


@pytest.mark.asyncio
async def test_on_investigation_updated(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_investigation_updated(
            rt_client, TENANT_ID, ANALYST_ID, INV_ID, {"status": "reviewing"}
        )
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.INVESTIGATION_UPDATED
        assert event.channel == ch.INVESTIGATIONS
        assert event.payload["status"] == "reviewing"


@pytest.mark.asyncio
async def test_on_verdict_changed(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_verdict_changed(
            rt_client, TENANT_ID, ANALYST_ID, INV_ID,
            "true_positive", "unknown", "confirmed lateral movement"
        )
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.INVESTIGATION_VERDICT_CHANGED
        assert event.channel == ch.INVESTIGATIONS
        assert event.payload["new_verdict"] == "true_positive"
        assert event.payload["previous_verdict"] == "unknown"
        assert event.payload["reasoning"] == "confirmed lateral movement"


@pytest.mark.asyncio
async def test_on_assignment_changed(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_assignment_changed(
            rt_client, TENANT_ID, ANALYST_ID, INV_ID, ANALYST2_ID, False, None
        )
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.INVESTIGATION_ASSIGNED
        assert event.channel == ch.INVESTIGATIONS
        assert event.payload["assigned_to"] == ANALYST2_ID
        assert event.payload["escalated"] is False


@pytest.mark.asyncio
async def test_on_assignment_changed_escalated(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_assignment_changed(
            rt_client, TENANT_ID, ANALYST_ID, INV_ID, "admin", True, "Tier 2 required"
        )
        event = mock_bc.call_args[0][1]
        assert event.payload["escalated"] is True
        assert event.payload["escalation_reason"] == "Tier 2 required"


@pytest.mark.asyncio
async def test_on_status_changed(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_status_changed(
            rt_client, TENANT_ID, ANALYST_ID, INV_ID, "closed", "resolved"
        )
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.INVESTIGATION_UPDATED
        assert event.channel == ch.INVESTIGATIONS
        assert event.payload["new_status"] == "closed"
        assert event.payload["reason"] == "resolved"


# ─── Note events ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_on_note_added(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_note_added(
            rt_client, TENANT_ID, ANALYST_ID, INV_ID, "note-1", "Suspicious PS", True
        )
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.NOTE_CREATED
        assert event.channel == ch.ACTIVITY
        assert event.payload["note_id"] == "note-1"
        assert event.payload["pinned"] is True


@pytest.mark.asyncio
async def test_on_note_updated(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_note_updated(rt_client, TENANT_ID, ANALYST_ID, INV_ID, "note-2")
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.NOTE_UPDATED
        assert event.channel == ch.ACTIVITY
        assert event.payload["note_id"] == "note-2"


# ─── Evidence events ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_on_evidence_added(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_evidence_added(
            rt_client, TENANT_ID, ANALYST_ID, INV_ID, "ev-1", "Memory dump", "file"
        )
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.EVIDENCE_ADDED
        assert event.channel == ch.ACTIVITY
        assert event.payload["evidence_id"] == "ev-1"
        assert event.payload["evidence_type"] == "file"


# ─── Case events ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_on_case_merged(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_case_merged(
            rt_client, TENANT_ID, ANALYST_ID, INV_ID, [INV_ID_2], "duplicates"
        )
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.CASE_MERGED
        assert event.channel == ch.CASES
        assert INV_ID_2 in event.payload["secondary_investigation_ids"]


@pytest.mark.asyncio
async def test_on_case_closed(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_case_closed(rt_client, TENANT_ID, ANALYST_ID, INV_ID, "benign")
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.CASE_CLOSED
        assert event.channel == ch.CASES
        assert event.payload["verdict"] == "benign"


# ─── Hunt events ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_on_hunt_completed(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_hunt_completed(
            rt_client, TENANT_ID, ANALYST_ID, 10, "hunt-7", "proc:powershell"
        )
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.HUNT_COMPLETED
        assert event.channel == ch.HUNTS
        assert event.payload["result_count"] == 10


# ─── Analyst presence events ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_on_analyst_joined(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_analyst_joined(
            rt_client, TENANT_ID, ANALYST_ID, "Alice", "investigations"
        )
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.ANALYST_JOINED
        assert event.channel == ch.PRESENCE
        assert event.payload["display_name"] == "Alice"
        assert event.payload["workspace"] == "investigations"


@pytest.mark.asyncio
async def test_on_analyst_left(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_analyst_left(rt_client, TENANT_ID, ANALYST_ID)
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.ANALYST_LEFT
        assert event.channel == ch.PRESENCE
        assert event.payload["analyst_id"] == ANALYST_ID


@pytest.mark.asyncio
async def test_on_analyst_typing(rt_client):
    with _capture_broadcast() as mock_bc:
        await SyncEngine.on_analyst_typing(rt_client, TENANT_ID, ANALYST_ID, INV_ID)
        event = mock_bc.call_args[0][1]
        assert event.event_type == RealtimeEventType.ANALYST_TYPING
        assert event.channel == ch.PRESENCE
        assert event.payload["investigation_id"] == INV_ID


# ─── Broadcast error propagation ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sync_engine_propagates_broadcast_error(rt_client):
    """SyncEngine does not swallow errors — caller's try/except handles it."""
    with patch(
        "app.realtime.sync.RealtimeBroadcaster.broadcast_event",
        new_callable=AsyncMock,
        side_effect=Exception("Redis unavailable"),
    ):
        with pytest.raises(Exception, match="Redis unavailable"):
            await SyncEngine.on_analyst_left(rt_client, TENANT_ID, ANALYST_ID)

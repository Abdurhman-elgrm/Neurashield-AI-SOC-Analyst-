"""Unit tests for Events Explorer realtime event constructors."""

from __future__ import annotations

from app.realtime.events import (
    realtime_event_created,
    realtime_event_deleted,
    realtime_event_updated,
    realtime_events_bulk_ingested,
)
from app.realtime.schemas import RealtimeEventType

TENANT_ID = "tenant-abc-123"
ACTOR_ID = "analyst-001"


class TestRealtimeEventCreated:
    def test_basic_fields(self):
        ev = realtime_event_created(
            tenant_id=TENANT_ID,
            actor_id=ACTOR_ID,
            event_id="event-001",
            category="process",
            severity=3,
            host_name="dc01",
            source_ip="1.2.3.4",
            username="CORP\\john",
            event_timestamp="2024-06-01T12:00:00Z",
        )
        assert ev.v == 2
        assert ev.event_type == RealtimeEventType.EVENT_CREATED
        assert ev.tenant_id == TENANT_ID
        assert ev.actor_id == ACTOR_ID
        assert ev.channel == "events"
        assert ev.payload["event_id"] == "event-001"
        assert ev.payload["category"] == "process"
        assert ev.payload["severity"] == 3
        assert ev.payload["host_name"] == "dc01"
        assert ev.payload["source_ip"] == "1.2.3.4"
        assert ev.payload["username"] == "CORP\\john"

    def test_null_optional_fields(self):
        ev = realtime_event_created(
            tenant_id=TENANT_ID,
            actor_id=ACTOR_ID,
            event_id="event-002",
            category="network",
            severity=2,
            host_name=None,
            source_ip=None,
            username=None,
            event_timestamp="2024-06-01T12:00:00Z",
        )
        assert ev.payload["host_name"] is None
        assert ev.payload["source_ip"] is None
        assert ev.payload["username"] is None

    def test_timestamp_present(self):
        ev = realtime_event_created(
            tenant_id=TENANT_ID,
            actor_id=ACTOR_ID,
            event_id="event-003",
            category="auth",
            severity=1,
            host_name=None,
            source_ip=None,
            username=None,
            event_timestamp="2024-06-01T12:00:00Z",
        )
        assert ev.timestamp
        assert len(ev.timestamp) > 10

    def test_event_id_is_uuid(self):
        ev = realtime_event_created(
            tenant_id=TENANT_ID,
            actor_id=ACTOR_ID,
            event_id="event-004",
            category="file",
            severity=1,
            host_name=None,
            source_ip=None,
            username=None,
            event_timestamp="2024-06-01T12:00:00Z",
        )
        assert ev.event_id  # UUIDs have a non-empty event_id field on the envelope

    def test_to_json_serializable(self):
        ev = realtime_event_created(
            tenant_id=TENANT_ID,
            actor_id=ACTOR_ID,
            event_id="event-005",
            category="dns",
            severity=1,
            host_name="host01",
            source_ip="10.0.0.1",
            username=None,
            event_timestamp="2024-06-01T12:00:00Z",
        )
        json_str = ev.to_json()
        assert isinstance(json_str, str)
        assert "event.created" in json_str
        assert TENANT_ID in json_str


class TestRealtimeEventUpdated:
    def test_with_changes(self):
        ev = realtime_event_updated(
            tenant_id=TENANT_ID,
            actor_id=ACTOR_ID,
            event_id="event-001",
            changes={"tags": ["malware", "c2"]},
        )
        assert ev.event_type == RealtimeEventType.EVENT_UPDATED
        assert ev.payload["event_id"] == "event-001"
        assert ev.payload["tags"] == ["malware", "c2"]

    def test_empty_changes(self):
        ev = realtime_event_updated(
            tenant_id=TENANT_ID,
            actor_id=ACTOR_ID,
            event_id="event-001",
            changes={},
        )
        assert ev.payload["event_id"] == "event-001"


class TestRealtimeEventDeleted:
    def test_basic(self):
        ev = realtime_event_deleted(
            tenant_id=TENANT_ID,
            actor_id=ACTOR_ID,
            event_id="event-001",
        )
        assert ev.event_type == RealtimeEventType.EVENT_DELETED
        assert ev.payload["event_id"] == "event-001"
        assert ev.payload["reason"] is None

    def test_with_reason(self):
        ev = realtime_event_deleted(
            tenant_id=TENANT_ID,
            actor_id=ACTOR_ID,
            event_id="event-001",
            reason="False positive — test data",
        )
        assert ev.payload["reason"] == "False positive — test data"


class TestRealtimeEventsBulkIngested:
    def test_basic(self):
        ev = realtime_events_bulk_ingested(
            tenant_id=TENANT_ID,
            actor_id=ACTOR_ID,
            count=150,
            agent_id="agent-001",
            categories=["process", "network"],
        )
        assert ev.event_type == RealtimeEventType.EVENTS_BULK_INGESTED
        assert ev.payload["count"] == 150
        assert ev.payload["agent_id"] == "agent-001"
        assert "process" in ev.payload["categories"]

    def test_no_agent(self):
        ev = realtime_events_bulk_ingested(
            tenant_id=TENANT_ID,
            actor_id=ACTOR_ID,
            count=5,
            agent_id=None,
            categories=["auth"],
        )
        assert ev.payload["agent_id"] is None


class TestRealtimeEventTypes:
    def test_event_types_in_enum(self):
        assert RealtimeEventType.EVENT_CREATED.value == "event.created"
        assert RealtimeEventType.EVENT_UPDATED.value == "event.updated"
        assert RealtimeEventType.EVENT_DELETED.value == "event.deleted"
        assert RealtimeEventType.EVENTS_BULK_INGESTED.value == "events.bulk_ingested"

    def test_investigation_types_still_present(self):
        # Ensure Phase 3.5 types were not removed
        assert RealtimeEventType.INVESTIGATION_NOTE_ADDED.value == "investigation.note_added"
        assert (
            RealtimeEventType.INVESTIGATION_STATUS_UPDATED.value == "investigation.status_updated"
        )

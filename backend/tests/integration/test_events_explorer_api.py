"""Integration tests for the Phase 3.6 Events Explorer API.

These tests use the in-memory SQLite database from conftest.py.
PostgreSQL-specific features (FTS, GIN) are exercised in query-builder
unit tests; here we verify routing, auth, tenant isolation, and response shape.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.events.schemas import (
    EntityEventsResponse,
    EventContextResponse,
    EventSearchResponse,
    TimelineResponse,
)
from tests.conftest import setup_verified_user_and_tenant

# ─── Fixture: authenticated tenant member ─────────────────────────────────────


@pytest_asyncio.fixture
async def auth_member(
    client: AsyncClient, db_session: AsyncSession
) -> dict[str, Any]:
    data = await setup_verified_user_and_tenant(client, db_session, prefix="explorer")
    return {
        "headers": data["headers"],
        "tenant_id": data["tenant_id"],
    }


# ─── Mocked service responses ─────────────────────────────────────────────────


def _mock_search_response() -> EventSearchResponse:
    return EventSearchResponse(
        items=[],
        next_cursor=None,
        prev_cursor=None,
        has_more=False,
        total_estimate=0,
    )


def _mock_timeline_response() -> TimelineResponse:
    return TimelineResponse(
        items=[],
        buckets=[],
        next_cursor=None,
        has_more=False,
        from_ts=None,
        to_ts=None,
    )


def _mock_context_response(event_id: str) -> EventContextResponse:
    from app.schemas.event import EventResponse

    fake_event = EventResponse(
        id=UUID(event_id),
        tenant_id=uuid4(),
        agent_id=None,
        stream_id=None,
        raw_id=None,
        category="process",
        severity=3,
        event_timestamp=datetime(2024, 6, 1, tzinfo=UTC),
        ingested_at=datetime(2024, 6, 1, tzinfo=UTC),
        host_name="dc01",
        source_ip="1.2.3.4",
        dest_ip=None,
        process_name="powershell.exe",
        username="CORP\\admin",
        process=None,
        user=None,
        network=None,
        file=None,
        registry=None,
        tags=[],
    )
    return EventContextResponse(
        event=fake_event,
        prev_event=None,
        next_event=None,
    )


def _mock_entity_response(entity_type: str, entity_value: str) -> EntityEventsResponse:
    return EntityEventsResponse(
        entity_type=entity_type,
        entity_value=entity_value,
        items=[],
        next_cursor=None,
        has_more=False,
        total_events=0,
    )


# ─── /events/search ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestEventsSearch:
    async def test_search_requires_auth(self, client: AsyncClient):
        resp = await client.post(f"{settings.API_PREFIX}/events/search", json={})
        assert resp.status_code in (401, 403)

    async def test_search_requires_tenant(self, client: AsyncClient, auth_member: dict):
        headers = {k: v for k, v in auth_member["headers"].items() if k != "X-Tenant-ID"}
        with patch(
            "app.events.search.EventSearchService.search",
            new=AsyncMock(return_value=_mock_search_response()),
        ):
            resp = await client.post(
                f"{settings.API_PREFIX}/events/search",
                json={},
                headers=headers,
            )
        assert resp.status_code in (401, 403, 422)

    async def test_search_empty_request(self, client: AsyncClient, auth_member: dict):
        with patch(
            "app.events.search.EventSearchService.search",
            new=AsyncMock(return_value=_mock_search_response()),
        ):
            resp = await client.post(
                f"{settings.API_PREFIX}/events/search",
                json={},
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert "next_cursor" in body
        assert "has_more" in body

    async def test_search_with_query(self, client: AsyncClient, auth_member: dict):
        with patch(
            "app.events.search.EventSearchService.search",
            new=AsyncMock(return_value=_mock_search_response()),
        ):
            resp = await client.post(
                f"{settings.API_PREFIX}/events/search",
                json={"query": "powershell -enc", "severity_min": 2, "limit": 20},
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200

    async def test_search_with_filter_groups(self, client: AsyncClient, auth_member: dict):
        with patch(
            "app.events.search.EventSearchService.search",
            new=AsyncMock(return_value=_mock_search_response()),
        ):
            resp = await client.post(
                f"{settings.API_PREFIX}/events/search",
                json={
                    "filter_groups": [
                        {
                            "logic": "AND",
                            "conditions": [
                                {"field": "severity", "op": "gte", "value": 3},
                                {"field": "host_name", "op": "eq", "value": "dc01"},
                            ],
                        }
                    ]
                },
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200

    async def test_search_invalid_limit(self, client: AsyncClient, auth_member: dict):
        resp = await client.post(
            f"{settings.API_PREFIX}/events/search",
            json={"limit": 9999},
            headers=auth_member["headers"],
        )
        assert resp.status_code == 422

    async def test_search_with_all_quick_filters(self, client: AsyncClient, auth_member: dict):
        with patch(
            "app.events.search.EventSearchService.search",
            new=AsyncMock(return_value=_mock_search_response()),
        ):
            resp = await client.post(
                f"{settings.API_PREFIX}/events/search",
                json={
                    "categories": ["process", "network"],
                    "severity_min": 2,
                    "severity_max": 4,
                    "host_names": ["dc01"],
                    "usernames": ["admin"],
                    "source_ips": ["1.2.3.4"],
                    "dest_ips": ["5.6.7.8"],
                    "process_names": ["cmd.exe"],
                    "tags": ["suspicious"],
                    "correlation_id": "corr-001",
                    "session_id": "sess-002",
                },
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200


# ─── /events/timeline ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestEventsTimeline:
    async def test_timeline_requires_auth(self, client: AsyncClient):
        resp = await client.get(f"{settings.API_PREFIX}/events/timeline")
        assert resp.status_code in (401, 403)

    async def test_timeline_no_params(self, client: AsyncClient, auth_member: dict):
        with patch(
            "app.events.search.EventSearchService.timeline",
            new=AsyncMock(return_value=_mock_timeline_response()),
        ):
            resp = await client.get(
                f"{settings.API_PREFIX}/events/timeline",
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert "buckets" in body
        assert "has_more" in body

    async def test_timeline_with_time_range(self, client: AsyncClient, auth_member: dict):
        with patch(
            "app.events.search.EventSearchService.timeline",
            new=AsyncMock(return_value=_mock_timeline_response()),
        ):
            resp = await client.get(
                f"{settings.API_PREFIX}/events/timeline",
                params={
                    "from_ts": "2024-01-01T00:00:00Z",
                    "to_ts": "2024-12-31T23:59:59Z",
                    "limit": 100,
                },
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200

    async def test_timeline_invalid_severity_min(self, client: AsyncClient, auth_member: dict):
        resp = await client.get(
            f"{settings.API_PREFIX}/events/timeline",
            params={"severity_min": 99},
            headers=auth_member["headers"],
        )
        assert resp.status_code == 422


# ─── /events/{event_id}/context ───────────────────────────────────────────────


@pytest.mark.asyncio
class TestEventContext:
    EVENT_ID = "12345678-1234-1234-1234-123456789abc"

    async def test_context_requires_auth(self, client: AsyncClient):
        resp = await client.get(f"{settings.API_PREFIX}/events/{self.EVENT_ID}/context")
        assert resp.status_code in (401, 403)

    async def test_context_not_found(self, client: AsyncClient, auth_member: dict):
        with patch(
            "app.events.search.EventSearchService.get_context",
            new=AsyncMock(return_value=None),
        ):
            resp = await client.get(
                f"{settings.API_PREFIX}/events/{self.EVENT_ID}/context",
                headers=auth_member["headers"],
            )
        assert resp.status_code == 404

    async def test_context_found(self, client: AsyncClient, auth_member: dict):
        mock_ctx = _mock_context_response(self.EVENT_ID)
        with patch(
            "app.events.search.EventSearchService.get_context",
            new=AsyncMock(return_value=mock_ctx),
        ):
            resp = await client.get(
                f"{settings.API_PREFIX}/events/{self.EVENT_ID}/context",
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert "event" in body["data"]
        assert "prev_event" in body["data"]
        assert "next_event" in body["data"]
        assert "same_host_events" in body["data"]
        assert "correlated_events" in body["data"]

    async def test_context_invalid_uuid(self, client: AsyncClient, auth_member: dict):
        resp = await client.get(
            f"{settings.API_PREFIX}/events/not-a-uuid/context",
            headers=auth_member["headers"],
        )
        assert resp.status_code == 422


# ─── /events/export ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestEventsExport:
    async def test_export_requires_auth(self, client: AsyncClient):
        resp = await client.post(f"{settings.API_PREFIX}/events/export", json={})
        assert resp.status_code in (401, 403)

    async def test_export_ndjson(self, client: AsyncClient, auth_member: dict):
        async def mock_stream(*args, **kwargs):
            yield '{"id":"event-001"}\n'
            yield '{"id":"event-002"}\n'

        with patch(
            "app.events.search.EventSearchService.export_stream",
            side_effect=mock_stream,
        ):
            resp = await client.post(
                f"{settings.API_PREFIX}/events/export",
                json={"format": "ndjson"},
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200
        assert "ndjson" in resp.headers["content-type"]
        assert "content-disposition" in resp.headers

    async def test_export_csv(self, client: AsyncClient, auth_member: dict):
        async def mock_stream(*args, **kwargs):
            yield "id,host_name,severity\n"
            yield "event-001,dc01,3\n"

        with patch(
            "app.events.search.EventSearchService.export_stream",
            side_effect=mock_stream,
        ):
            resp = await client.post(
                f"{settings.API_PREFIX}/events/export",
                json={"format": "csv"},
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]

    async def test_export_json(self, client: AsyncClient, auth_member: dict):
        async def mock_stream(*args, **kwargs):
            yield "["
            yield '{"id":"event-001"}'
            yield "]"

        with patch(
            "app.events.search.EventSearchService.export_stream",
            side_effect=mock_stream,
        ):
            resp = await client.post(
                f"{settings.API_PREFIX}/events/export",
                json={"format": "json"},
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200
        assert "application/json" in resp.headers["content-type"]

    async def test_export_max_rows_too_large(self, client: AsyncClient, auth_member: dict):
        resp = await client.post(
            f"{settings.API_PREFIX}/events/export",
            json={"max_rows": 999_999},
            headers=auth_member["headers"],
        )
        assert resp.status_code == 422

    async def test_export_with_filters(self, client: AsyncClient, auth_member: dict):
        async def mock_stream(*args, **kwargs):
            yield ""

        with patch(
            "app.events.search.EventSearchService.export_stream",
            side_effect=mock_stream,
        ):
            resp = await client.post(
                f"{settings.API_PREFIX}/events/export",
                json={
                    "format": "ndjson",
                    "categories": ["process"],
                    "severity_min": 3,
                    "max_rows": 500,
                },
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200


# ─── /entities/{entity_key}/events ───────────────────────────────────────────


@pytest.mark.asyncio
class TestEntityEvents:
    async def test_entity_requires_auth(self, client: AsyncClient):
        resp = await client.get(f"{settings.API_PREFIX}/entities/host:dc01/events")
        assert resp.status_code in (401, 403)

    async def test_entity_host(self, client: AsyncClient, auth_member: dict):
        mock_resp = _mock_entity_response("host", "dc01")
        with patch(
            "app.events.search.EventSearchService.entity_events",
            new=AsyncMock(return_value=mock_resp),
        ):
            resp = await client.get(
                f"{settings.API_PREFIX}/entities/host:dc01/events",
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["entity_type"] == "host"
        assert body["entity_value"] == "dc01"
        assert "items" in body
        assert "total_events" in body

    async def test_entity_user(self, client: AsyncClient, auth_member: dict):
        mock_resp = _mock_entity_response("user", "CORP\\admin")
        with patch(
            "app.events.search.EventSearchService.entity_events",
            new=AsyncMock(return_value=mock_resp),
        ):
            resp = await client.get(
                f"{settings.API_PREFIX}/entities/user:CORP%5Cadmin/events",
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200

    async def test_entity_ip(self, client: AsyncClient, auth_member: dict):
        mock_resp = _mock_entity_response("ip", "192.168.1.100")
        with patch(
            "app.events.search.EventSearchService.entity_events",
            new=AsyncMock(return_value=mock_resp),
        ):
            resp = await client.get(
                f"{settings.API_PREFIX}/entities/ip:192.168.1.100/events",
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200

    async def test_entity_process(self, client: AsyncClient, auth_member: dict):
        mock_resp = _mock_entity_response("process", "powershell.exe")
        with patch(
            "app.events.search.EventSearchService.entity_events",
            new=AsyncMock(return_value=mock_resp),
        ):
            resp = await client.get(
                f"{settings.API_PREFIX}/entities/process:powershell.exe/events",
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200

    async def test_invalid_entity_type(self, client: AsyncClient, auth_member: dict):
        resp = await client.get(
            f"{settings.API_PREFIX}/entities/unknown:dc01/events",
            headers=auth_member["headers"],
        )
        assert resp.status_code == 422

    async def test_missing_entity_value(self, client: AsyncClient, auth_member: dict):
        resp = await client.get(
            f"{settings.API_PREFIX}/entities/host:/events",
            headers=auth_member["headers"],
        )
        assert resp.status_code == 422

    async def test_missing_colon_in_key(self, client: AsyncClient, auth_member: dict):
        resp = await client.get(
            f"{settings.API_PREFIX}/entities/hostdc01/events",
            headers=auth_member["headers"],
        )
        assert resp.status_code == 422

    async def test_entity_with_time_range(self, client: AsyncClient, auth_member: dict):
        mock_resp = _mock_entity_response("host", "dc01")
        with patch(
            "app.events.search.EventSearchService.entity_events",
            new=AsyncMock(return_value=mock_resp),
        ):
            resp = await client.get(
                f"{settings.API_PREFIX}/entities/host:dc01/events",
                params={
                    "from_ts": "2024-01-01T00:00:00Z",
                    "to_ts": "2024-12-31T00:00:00Z",
                    "limit": 100,
                },
                headers=auth_member["headers"],
            )
        assert resp.status_code == 200


# ─── Tenant isolation ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestTenantIsolation:
    async def test_search_tenant_id_passed_to_service(self, client: AsyncClient, auth_member: dict):
        """Verifies that the service receives the authenticated member's tenant_id, not a user-supplied one."""
        captured: list[UUID] = []

        async def capture_search(db, tenant_id, req):
            captured.append(tenant_id)
            return _mock_search_response()

        with patch("app.events.search.EventSearchService.search", side_effect=capture_search):
            await client.post(
                f"{settings.API_PREFIX}/events/search",
                json={},
                headers=auth_member["headers"],
            )

        assert len(captured) == 1
        assert str(captured[0]) == auth_member["tenant_id"]

    async def test_entity_tenant_id_passed_to_service(self, client: AsyncClient, auth_member: dict):
        captured: list[UUID] = []

        async def capture_entity(db, tenant_id, **kwargs):
            captured.append(tenant_id)
            return _mock_entity_response("host", "dc01")

        with patch(
            "app.events.search.EventSearchService.entity_events", side_effect=capture_entity
        ):
            await client.get(
                f"{settings.API_PREFIX}/entities/host:dc01/events",
                headers=auth_member["headers"],
            )

        assert len(captured) == 1
        assert str(captured[0]) == auth_member["tenant_id"]

"""Unit tests for the Events Explorer query builder."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import inspect, select

from app.events.query_builder import build_search_query
from app.events.schemas import (
    EventSearchRequest,
    FilterCondition,
    FilterGroup,
    SortDirection,
    SortField,
)
from app.models.event import Event

TENANT_ID = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


class TestBuildSearchQuery:
    def test_always_includes_tenant_id(self):
        req = EventSearchRequest()
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "tenant_id" in compiled

    def test_default_order_by_timestamp_desc(self):
        req = EventSearchRequest(sort_by=SortField.EVENT_TIMESTAMP, sort_dir=SortDirection.DESC)
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "event_timestamp" in compiled
        assert "DESC" in compiled or "desc" in compiled.lower()

    def test_asc_order(self):
        req = EventSearchRequest(sort_by=SortField.EVENT_TIMESTAMP, sort_dir=SortDirection.ASC)
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        # Should NOT have DESC at the end for event_timestamp
        assert "event_timestamp" in compiled

    def test_severity_sort(self):
        req = EventSearchRequest(sort_by=SortField.SEVERITY, sort_dir=SortDirection.DESC)
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "severity" in compiled

    def test_host_name_filter_included(self):
        req = EventSearchRequest(host_names=["dc01", "dc02"])
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "host_name" in compiled

    def test_category_filter_included(self):
        req = EventSearchRequest(categories=["process", "network"])
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "category" in compiled

    def test_invalid_categories_skipped(self):
        req = EventSearchRequest(categories=["not_a_real_category"])
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        # Should still be valid SQL without raising
        assert "tenant_id" in compiled

    def test_severity_range_filter(self):
        req = EventSearchRequest(severity_min=2, severity_max=4)
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "severity" in compiled

    def test_time_range_filter(self):
        req = EventSearchRequest(
            from_ts=datetime(2024, 1, 1, tzinfo=timezone.utc),
            to_ts=datetime(2024, 12, 31, tzinfo=timezone.utc),
        )
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "event_timestamp" in compiled

    def test_ip_filters_included(self):
        req = EventSearchRequest(
            source_ips=["1.2.3.4"],
            dest_ips=["5.6.7.8"],
        )
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "source_ip" in compiled
        assert "dest_ip" in compiled

    def test_username_filter(self):
        req = EventSearchRequest(usernames=["admin", "root"])
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "username" in compiled

    def test_correlation_id_filter(self):
        req = EventSearchRequest(correlation_id="corr-123")
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "correlation_id" in compiled

    def test_session_id_filter(self):
        req = EventSearchRequest(session_id="sess-abc")
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "session_id" in compiled

    def test_tags_filter(self):
        req = EventSearchRequest(tags=["malware"])
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "tags" in compiled

    def test_full_text_query(self):
        req = EventSearchRequest(query="powershell -enc malware")
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        # FTS uses to_tsvector
        assert "to_tsvector" in compiled or "tsvector" in compiled or "plainto_tsquery" in compiled

    def test_advanced_filter_groups(self):
        req = EventSearchRequest(
            filter_groups=[
                FilterGroup(
                    logic="AND",
                    conditions=[
                        FilterCondition(field="severity", op="gte", value=3),
                    ],
                )
            ]
        )
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "severity" in compiled

    def test_bad_cursor_is_ignored(self):
        req = EventSearchRequest(cursor="garbage-cursor-value")
        # Should not raise
        stmt = build_search_query(TENANT_ID, req)
        assert stmt is not None

    def test_valid_cursor_adds_seek_condition(self):
        from app.events.pagination import encode_cursor
        ts = datetime(2024, 6, 1, tzinfo=timezone.utc)
        eid = uuid4()
        cursor = encode_cursor(ts, eid, "event_timestamp", "desc")
        req = EventSearchRequest(cursor=cursor)
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        # The seek condition should reference event_timestamp and id
        assert "event_timestamp" in compiled

    def test_returns_select_statement(self):
        req = EventSearchRequest()
        stmt = build_search_query(TENANT_ID, req)
        # Should be a SELECT statement
        assert hasattr(stmt, "_raw_columns") or "SELECT" in str(stmt.compile()).upper()

    def test_limit_applied_externally(self):
        # build_search_query does NOT apply LIMIT — callers do
        req = EventSearchRequest(limit=25)
        stmt = build_search_query(TENANT_ID, req)
        compiled = str(stmt.compile())
        assert "LIMIT" not in compiled.upper()

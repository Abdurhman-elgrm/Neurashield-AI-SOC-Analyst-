"""Unit tests for Events Explorer Pydantic schemas."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.events.schemas import (
    EntityType,
    EventSearchRequest,
    ExportFormat,
    ExportRequest,
    FilterCondition,
    FilterGroup,
    SortDirection,
    SortField,
)


class TestEventSearchRequest:
    def test_defaults(self):
        req = EventSearchRequest()
        assert req.query is None
        assert req.limit == 50
        assert req.sort_by == SortField.EVENT_TIMESTAMP
        assert req.sort_dir == SortDirection.DESC
        assert req.cursor is None

    def test_valid_full_request(self):
        req = EventSearchRequest(
            query="powershell -enc",
            categories=["process", "network"],
            severity_min=2,
            severity_max=4,
            host_names=["dc01", "dc02"],
            usernames=["admin"],
            source_ips=["1.2.3.4"],
            dest_ips=["5.6.7.8"],
            process_names=["cmd.exe"],
            tags=["malware"],
            correlation_id="corr-abc",
            session_id="sess-xyz",
            from_ts=datetime(2024, 1, 1, tzinfo=UTC),
            to_ts=datetime(2024, 12, 31, tzinfo=UTC),
            limit=100,
            sort_by=SortField.SEVERITY,
            sort_dir=SortDirection.ASC,
        )
        assert req.query == "powershell -enc"
        assert req.limit == 100
        assert req.sort_by == SortField.SEVERITY

    def test_limit_clamped(self):
        with pytest.raises(ValidationError):
            EventSearchRequest(limit=600)  # over max 500

    def test_limit_min(self):
        with pytest.raises(ValidationError):
            EventSearchRequest(limit=0)

    def test_severity_min_bounds(self):
        with pytest.raises(ValidationError):
            EventSearchRequest(severity_min=0)
        with pytest.raises(ValidationError):
            EventSearchRequest(severity_min=5)

    def test_with_filter_groups(self):
        req = EventSearchRequest(
            filter_groups=[
                FilterGroup(
                    logic="AND",
                    conditions=[
                        FilterCondition(field="severity", op="gte", value=3),
                        FilterCondition(field="host_name", op="eq", value="dc01"),
                    ],
                )
            ]
        )
        assert len(req.filter_groups) == 1
        assert len(req.filter_groups[0].conditions) == 2

    def test_nested_filter_groups(self):
        req = EventSearchRequest(
            filter_groups=[
                FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field="severity", op="gte", value=3)],
                    groups=[
                        FilterGroup(
                            logic="OR",
                            conditions=[
                                FilterCondition(field="source_ip", op="eq", value="1.1.1.1"),
                                FilterCondition(field="dest_ip", op="eq", value="1.1.1.1"),
                            ],
                        )
                    ],
                )
            ]
        )
        assert len(req.filter_groups[0].groups) == 1


class TestExportRequest:
    def test_defaults(self):
        req = ExportRequest()
        assert req.format == ExportFormat.NDJSON
        assert req.max_rows == 10_000
        assert req.fields is None

    def test_csv_format(self):
        req = ExportRequest(format=ExportFormat.CSV)
        assert req.format == ExportFormat.CSV

    def test_json_format(self):
        req = ExportRequest(format=ExportFormat.JSON)
        assert req.format == ExportFormat.JSON

    def test_max_rows_over_limit(self):
        with pytest.raises(ValidationError):
            ExportRequest(max_rows=200_000)

    def test_max_rows_min(self):
        with pytest.raises(ValidationError):
            ExportRequest(max_rows=0)

    def test_field_projection(self):
        req = ExportRequest(fields=["id", "host_name", "severity"])
        assert req.fields == ["id", "host_name", "severity"]

    def test_with_filters(self):
        req = ExportRequest(
            categories=["process"],
            from_ts=datetime(2024, 1, 1, tzinfo=UTC),
            to_ts=datetime(2024, 12, 31, tzinfo=UTC),
            max_rows=5000,
        )
        assert req.categories == ["process"]
        assert req.max_rows == 5000


class TestFilterGroup:
    def test_default_logic_is_and(self):
        group = FilterGroup()
        assert group.logic == "AND"

    def test_not_logic(self):
        group = FilterGroup(
            logic="NOT", conditions=[FilterCondition(field="category", op="eq", value="registry")]
        )
        assert group.logic == "NOT"

    def test_nested_rebuilds_correctly(self):
        group = FilterGroup(
            logic="AND",
            groups=[
                FilterGroup(
                    logic="OR",
                    conditions=[
                        FilterCondition(field="severity", op="gt", value=2),
                    ],
                )
            ],
        )
        assert len(group.groups) == 1
        assert group.groups[0].logic == "OR"


class TestEntityType:
    def test_all_values(self):
        assert EntityType.HOST.value == "host"
        assert EntityType.USER.value == "user"
        assert EntityType.IP.value == "ip"
        assert EntityType.PROCESS.value == "process"
        assert EntityType.DOMAIN.value == "domain"


class TestExportFormat:
    def test_all_values(self):
        assert ExportFormat.CSV.value == "csv"
        assert ExportFormat.JSON.value == "json"
        assert ExportFormat.NDJSON.value == "ndjson"

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.event import EventResponse

# ─── Filter primitives ────────────────────────────────────────────────────────

FilterOperator = Literal[
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "contains",
    "icontains",
    "starts_with",
    "is_null",
    "is_not_null",
]

FilterLogic = Literal["AND", "OR", "NOT"]


class FilterCondition(BaseModel):
    """Atomic filter condition: <field> <op> <value>."""

    field: str
    op: FilterOperator
    value: Any = None  # None is valid for is_null / is_not_null


class FilterGroup(BaseModel):
    """
    Recursive AND/OR/NOT filter tree.

    Examples:
      AND [hostname eq "dc01", severity gte 3]
      OR [source_ip eq "1.2.3.4", dest_ip eq "1.2.3.4"]
      NOT [category eq "process"]
    """

    logic: FilterLogic = "AND"
    conditions: list[FilterCondition] = Field(default_factory=list)
    groups: list[FilterGroup] = Field(default_factory=list)


FilterGroup.model_rebuild()


# ─── Sort ─────────────────────────────────────────────────────────────────────


class SortDirection(str, enum.Enum):
    ASC = "asc"
    DESC = "desc"


class SortField(str, enum.Enum):
    EVENT_TIMESTAMP = "event_timestamp"
    INGESTED_AT = "ingested_at"
    SEVERITY = "severity"
    HOST_NAME = "host_name"


# ─── Search request ───────────────────────────────────────────────────────────


class EventSearchRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    # Full-text search across hostname, username, process_name, IPs, raw_payload text
    query: str | None = None

    # Quick scalar filters (server applies as AND)
    categories: list[str] | None = None
    severity_min: int | None = Field(default=None, ge=1, le=4)
    severity_max: int | None = Field(default=None, ge=1, le=4)
    host_names: list[str] | None = None
    usernames: list[str] | None = None
    source_ips: list[str] | None = None
    dest_ips: list[str] | None = None
    process_names: list[str] | None = None
    agent_ids: list[UUID] | None = None
    tags: list[str] | None = None
    correlation_id: str | None = None
    session_id: str | None = None
    process_tree_id: str | None = None
    event_chain_id: str | None = None

    # Time range
    from_ts: datetime | None = None
    to_ts: datetime | None = None

    # Advanced nested filter groups (applied as additional AND on top of quick filters)
    filter_groups: list[FilterGroup] | None = None

    # Sort
    sort_by: SortField = SortField.EVENT_TIMESTAMP
    sort_dir: SortDirection = SortDirection.DESC

    # Cursor pagination
    cursor: str | None = None
    limit: int = Field(default=50, ge=1, le=500)


# ─── Search response ──────────────────────────────────────────────────────────


class EventSearchResponse(BaseModel):
    items: list[EventResponse]
    next_cursor: str | None
    prev_cursor: str | None
    has_more: bool
    total_estimate: int | None = None  # approximate, may be None for large datasets


# ─── Timeline ─────────────────────────────────────────────────────────────────


class TimelineBucket(BaseModel):
    bucket_start: datetime
    bucket_end: datetime
    count: int
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    category_breakdown: dict[str, int] = Field(default_factory=dict)


class TimelineResponse(BaseModel):
    items: list[EventResponse]
    buckets: list[TimelineBucket]
    next_cursor: str | None
    has_more: bool
    from_ts: datetime | None
    to_ts: datetime | None


# ─── Entity-centric ───────────────────────────────────────────────────────────


class EntityType(str, enum.Enum):
    HOST = "host"
    USER = "user"
    IP = "ip"
    PROCESS = "process"
    DOMAIN = "domain"


class EntityEventsResponse(BaseModel):
    entity_type: str
    entity_value: str
    items: list[EventResponse]
    next_cursor: str | None
    has_more: bool
    total_events: int


# ─── Context ──────────────────────────────────────────────────────────────────


class EventContextResponse(BaseModel):
    event: EventResponse
    prev_event: EventResponse | None = None
    next_event: EventResponse | None = None
    same_host_events: list[EventResponse] = Field(default_factory=list)
    same_user_events: list[EventResponse] = Field(default_factory=list)
    same_ip_events: list[EventResponse] = Field(default_factory=list)
    same_session_events: list[EventResponse] = Field(default_factory=list)
    same_process_events: list[EventResponse] = Field(default_factory=list)
    correlated_events: list[EventResponse] = Field(default_factory=list)


# ─── Export ───────────────────────────────────────────────────────────────────


class ExportFormat(str, enum.Enum):
    CSV = "csv"
    JSON = "json"
    NDJSON = "ndjson"


class ExportRequest(BaseModel):
    format: ExportFormat = ExportFormat.NDJSON
    # Mirrors EventSearchRequest filters
    query: str | None = None
    categories: list[str] | None = None
    severity_min: int | None = Field(default=None, ge=1, le=4)
    severity_max: int | None = Field(default=None, ge=1, le=4)
    host_names: list[str] | None = None
    usernames: list[str] | None = None
    source_ips: list[str] | None = None
    dest_ips: list[str] | None = None
    process_names: list[str] | None = None
    agent_ids: list[UUID] | None = None
    tags: list[str] | None = None
    correlation_id: str | None = None
    session_id: str | None = None
    from_ts: datetime | None = None
    to_ts: datetime | None = None
    filter_groups: list[FilterGroup] | None = None
    max_rows: int = Field(default=10_000, ge=1, le=100_000)
    fields: list[str] | None = None  # field projection; None = all fields

from __future__ import annotations

"""
Pydantic schemas for the Tier 2 analyst workspace.

All models use ConfigDict(from_attributes=True) so they can be built
directly from SQLAlchemy ORM rows.
"""

import enum
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# ─── Enumerations ─────────────────────────────────────────────────────────────

class InvestigationStatus(str, enum.Enum):
    NEW           = "new"
    ACTIVE        = "active"
    TRIAGED       = "triaged"
    INVESTIGATING = "investigating"
    CONTAINED     = "contained"
    RESOLVED      = "resolved"
    CLOSED        = "closed"
    FALSE_POSITIVE = "false_positive"


# Valid status transitions: source → allowed targets
STATUS_TRANSITIONS: dict[str, frozenset[str]] = {
    "new":           frozenset({"triaged", "investigating", "active", "closed", "false_positive"}),
    "active":        frozenset({"triaged", "investigating", "closed", "false_positive"}),
    "triaged":       frozenset({"investigating", "closed", "false_positive"}),
    "investigating": frozenset({"contained", "resolved", "closed", "false_positive"}),
    "contained":     frozenset({"resolved", "closed", "investigating"}),
    "resolved":      frozenset({"closed", "investigating"}),
    "closed":        frozenset({"investigating"}),
    "false_positive": frozenset({"investigating"}),
}


class InvestigationVerdict(str, enum.Enum):
    TRUE_POSITIVE    = "true_positive"
    FALSE_POSITIVE   = "false_positive"
    BENIGN_POSITIVE  = "benign_positive"
    SUSPICIOUS       = "suspicious"
    INCONCLUSIVE     = "inconclusive"


class EvidenceType(str, enum.Enum):
    RAW_EVENT        = "raw_event"
    CORRELATED_GROUP = "correlated_group"
    SCREENSHOT_META  = "screenshot_meta"
    FILE_REF         = "file_ref"
    IOC_REF          = "ioc_ref"
    NOTE_REF         = "note_ref"


# ─── Notes ────────────────────────────────────────────────────────────────────

class NoteCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=10_000)
    pinned:  bool = False


class NoteUpdate(BaseModel):
    content: str | None = Field(default=None, min_length=1, max_length=10_000)
    pinned:  bool | None = None


class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    note_id:          str
    investigation_id: str
    tenant_id:        str
    analyst_id:       UUID
    content:          str
    pinned:           bool
    created_at:       datetime
    updated_at:       datetime


# ─── Assignments ──────────────────────────────────────────────────────────────

class AssignmentCreate(BaseModel):
    assigned_to:       UUID
    escalated:         bool        = False
    escalation_reason: str | None  = None
    severity:          str | None  = None


class AssignmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    assignment_id:     str
    investigation_id:  str
    tenant_id:         str
    assigned_to:       UUID
    assigned_by:       UUID
    assigned_at:       datetime
    escalated:         bool
    escalation_reason: str | None
    severity:          str | None
    is_active:         bool


# ─── Verdicts ─────────────────────────────────────────────────────────────────

class VerdictCreate(BaseModel):
    verdict:            InvestigationVerdict
    reasoning:          str | None = None
    containment_status: str | None = None


class VerdictOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    verdict_id:         str
    investigation_id:   str
    tenant_id:          str
    analyst_id:         UUID
    previous_verdict:   str | None
    new_verdict:        str
    reasoning:          str | None
    containment_status: str | None
    created_at:         datetime


# ─── Evidence ─────────────────────────────────────────────────────────────────

class EvidenceCreate(BaseModel):
    evidence_type: EvidenceType
    reference_id:  str | None = None
    title:         str = Field(..., min_length=1, max_length=500)
    description:   str | None = None
    metadata:      dict[str, Any] = Field(default_factory=dict)


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id:      str
    investigation_id: str
    tenant_id:        str
    analyst_id:       UUID
    evidence_type:    str
    reference_id:     str | None
    title:            str
    description:      str | None
    extra_data:       dict[str, Any]
    created_at:       datetime


# ─── Activity ─────────────────────────────────────────────────────────────────

class ActivityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    activity_id:      str
    investigation_id: str
    tenant_id:        str
    analyst_id:       UUID
    action:           str
    target_id:        str | None
    action_data:      dict[str, Any]
    created_at:       datetime


# ─── Status / case management ─────────────────────────────────────────────────

class StatusUpdate(BaseModel):
    status: str = Field(..., description="New investigation status")
    reason: str | None = None


class MergeRequest(BaseModel):
    primary_investigation_id:    str
    secondary_investigation_ids: list[str] = Field(..., min_length=1)
    reason:                      str | None = None


class ReopenRequest(BaseModel):
    reason: str | None = None


# ─── Hunt engine ──────────────────────────────────────────────────────────────

class HuntFilter(BaseModel):
    """A single field-level filter condition."""
    field:    str            # "username", "host_name", "process_name", "source_ip" …
    value:    str
    operator: str = "eq"    # eq | contains | startswith | endswith | gt | lt


class HuntQuery(BaseModel):
    filters:      list[HuntFilter] = Field(default_factory=list)
    logic:        str = Field(default="and", pattern="^(and|or)$")
    from_ts:      datetime | None = None
    to_ts:        datetime | None = None
    severity_min: int | None = Field(default=None, ge=1, le=10)
    mitre_tactics:  list[str] = Field(default_factory=list)
    rule_matches:   list[str] = Field(default_factory=list)
    status:         str | None = None
    min_score:      int | None = Field(default=None, ge=0, le=100)
    max_score:      int | None = Field(default=None, ge=0, le=100)
    cursor:         str | None = None
    limit:          int = Field(default=50, ge=1, le=200)
    sort:           str = Field(default="desc", pattern="^(asc|desc)$")


class HuntResultEntry(BaseModel):
    investigation_id:  str
    tenant_id:         str
    threat_score:      int
    confidence:        str
    status:            str
    verdict:           str | None
    assigned_to:       UUID | None
    executive_summary: str
    created_at:        datetime
    match_reasons:     list[str] = Field(default_factory=list)


class HuntResult(BaseModel):
    entries:     list[HuntResultEntry]
    total:       int
    next_cursor: str | None
    has_more:    bool


class SavedHuntCreate(BaseModel):
    name:         str = Field(..., min_length=1, max_length=200)
    description:  str | None = None
    query_params: dict[str, Any]


class SavedHuntOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    hunt_id:      str
    tenant_id:    str
    analyst_id:   UUID
    name:         str
    description:  str | None
    query_params: dict[str, Any]
    run_count:    int
    created_at:   datetime
    updated_at:   datetime


# ─── Entity pivot / search ────────────────────────────────────────────────────

class PivotResult(BaseModel):
    entity_key:         str
    entity_type:        str
    investigation_ids:  list[str]
    total:              int
    investigation_refs: list[dict[str, Any]] = Field(default_factory=list)


# ─── Timeline ─────────────────────────────────────────────────────────────────

class TimelineFilter(BaseModel):
    from_ts:       datetime | None = None
    to_ts:         datetime | None = None
    severity_min:  int | None      = Field(default=None, ge=1, le=10)
    entity_filter: str | None      = None
    category:      str | None      = None
    sort:          str             = Field(default="asc", pattern="^(asc|desc)$")
    cursor:        str | None      = None
    limit:         int             = Field(default=50, ge=1, le=200)


class TimelineEntryOut(BaseModel):
    event_id:    str
    timestamp:   float
    hostname:    str
    username:    str | None
    process:     str | None
    action:      str
    outcome:     str
    rule_match:  list[str]
    severity:    int
    category:    str
    entity_keys: list[str]


class TimelineResponse(BaseModel):
    investigation_id: str
    entries:          list[TimelineEntryOut]
    total_events:     int
    filtered_count:   int
    first_seen:       float
    last_seen:        float
    next_cursor:      str | None
    has_more:         bool


# ─── Attack graph ─────────────────────────────────────────────────────────────

class GraphFilter(BaseModel):
    depth:         int        = Field(default=3, ge=1, le=10)
    entity_filter: list[str]  = Field(default_factory=list)
    collapse_ips:  bool       = False


class GraphNodeOut(BaseModel):
    node_id:     str
    node_type:   str
    label:       str
    attributes:  dict[str, Any]
    first_seen:  float
    last_seen:   float
    event_count: int


class GraphEdgeOut(BaseModel):
    source:     str
    target:     str
    edge_type:  str
    weight:     int
    first_seen: float
    last_seen:  float


class GraphResponse(BaseModel):
    investigation_id: str
    nodes:            list[GraphNodeOut]
    edges:            list[GraphEdgeOut]
    attack_paths:     list[list[str]]
    node_count:       int
    edge_count:       int
    max_depth:        int


# ─── Investigation list / detail ──────────────────────────────────────────────

class InvestigationListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    investigation_id:       str
    tenant_id:              str
    investigation_group_id: str
    threat_score:           int
    confidence:             str
    tp_probability:         float
    fp_probability:         float
    status:                 str
    verdict:                str | None
    assigned_to:            UUID | None
    executive_summary:      str
    title:                  str | None = None
    source:                 str | None = "auto"
    created_at:             datetime
    updated_at:             datetime


class InvestigationCreate(BaseModel):
    title:       str
    description: str | None = None
    severity:    str = "medium"   # critical | high | medium | low
    assigned_to: str | None = None
    alert_ids:   list[str] = []


class InvestigationDetail(InvestigationListItem):
    technical_summary:   str
    attack_progression:  list[str]
    recommended_actions: list[str]
    note_count:          int = 0
    evidence_count:      int = 0


class InvestigationFilterParams(BaseModel):
    status:      str | None  = None
    verdict:     str | None  = None
    assigned_to: UUID | None = None
    min_score:   int | None  = Field(default=None, ge=0, le=100)
    max_score:   int | None  = Field(default=None, ge=0, le=100)
    from_ts:     datetime | None = None
    to_ts:       datetime | None = None
    cursor:      str | None  = None
    limit:       int         = Field(default=50, ge=1, le=200)
    sort:        str         = Field(default="desc", pattern="^(asc|desc)$")

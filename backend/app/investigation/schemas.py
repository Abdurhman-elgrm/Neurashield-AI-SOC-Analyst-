from __future__ import annotations

"""
Pydantic schemas for the investigation layer.

All models are immutable (model_config frozen=True where appropriate).
Every field has a default so partial construction is safe throughout the engine.
"""

import enum
from typing import Any

from pydantic import BaseModel, Field


# ─── MITRE ATT&CK tactics ─────────────────────────────────────────────────────

class MitreTactic(str, enum.Enum):
    INITIAL_ACCESS       = "TA0001"
    EXECUTION            = "TA0002"
    PERSISTENCE          = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION      = "TA0005"
    CREDENTIAL_ACCESS    = "TA0006"
    DISCOVERY            = "TA0007"
    LATERAL_MOVEMENT     = "TA0008"
    COLLECTION           = "TA0009"
    EXFILTRATION         = "TA0010"
    COMMAND_AND_CONTROL  = "TA0011"
    IMPACT               = "TA0040"


MITRE_TACTIC_NAMES: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


# ─── Graph node / edge types ──────────────────────────────────────────────────

class GraphNodeType(str, enum.Enum):
    USER    = "user"
    HOST    = "host"
    IP      = "ip"
    PROCESS = "process"
    HASH    = "hash"
    DOMAIN  = "domain"


class GraphEdgeType(str, enum.Enum):
    EXECUTED_ON      = "executed_on"
    CONNECTED_TO     = "connected_to"
    AUTHENTICATED_TO = "authenticated_to"
    SPAWNED          = "spawned"
    DOWNLOADED       = "downloaded"
    RESOLVED         = "resolved"
    PARENT_OF        = "parent_of"


# ─── Timeline ─────────────────────────────────────────────────────────────────

class TimelineEntry(BaseModel):
    event_id:    str
    timestamp:   float
    hostname:    str = ""
    username:    str | None = None
    process:     str | None = None
    action:      str = ""
    outcome:     str = ""
    rule_match:  list[str] = Field(default_factory=list)
    severity:    int = 1
    category:    str = ""
    entity_keys: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class AttackTimeline(BaseModel):
    investigation_id:    str
    tenant_id:           str
    first_seen:          float = 0.0
    last_seen:           float = 0.0
    duration_seconds:    float = 0.0
    total_events:        int = 0
    distinct_hosts:      int = 0
    distinct_users:      int = 0
    distinct_ips:        int = 0
    distinct_processes:  int = 0
    entries:             list[TimelineEntry] = Field(default_factory=list)
    session_groups:      dict[str, list[str]] = Field(default_factory=dict)
    process_tree_groups: dict[str, list[str]] = Field(default_factory=dict)
    correlation_groups:  dict[str, list[str]] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


# ─── Attack graph ─────────────────────────────────────────────────────────────

class GraphNode(BaseModel):
    node_id:     str
    node_type:   GraphNodeType
    label:       str
    attributes:  dict[str, Any] = Field(default_factory=dict)
    first_seen:  float = 0.0
    last_seen:   float = 0.0
    event_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class GraphEdge(BaseModel):
    source:     str
    target:     str
    edge_type:  GraphEdgeType
    weight:     int = 1
    first_seen: float = 0.0
    last_seen:  float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class AttackGraph(BaseModel):
    investigation_id: str
    nodes:            list[GraphNode] = Field(default_factory=list)
    edges:            list[GraphEdge] = Field(default_factory=list)
    node_count:       int = 0
    edge_count:       int = 0
    max_depth:        int = 0

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


# ─── Behavior analysis ────────────────────────────────────────────────────────

class DetectedBehavior(BaseModel):
    behavior_name:  str
    mitre_tactics:  list[str] = Field(default_factory=list)
    confidence:     float = 0.0
    evidence:       list[str] = Field(default_factory=list)
    event_ids:      list[str] = Field(default_factory=list)
    first_seen:     float = 0.0
    last_seen:      float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class BehaviorAnalysis(BaseModel):
    investigation_id:   str
    detected_behaviors: list[DetectedBehavior] = Field(default_factory=list)
    mitre_tactics:      list[str] = Field(default_factory=list)
    max_confidence:     float = 0.0
    behavior_count:     int = 0

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


# ─── Investigation context ────────────────────────────────────────────────────

class InvestigationContext(BaseModel):
    investigation_id:    str
    tenant_id:           str
    involved_users:      list[str] = Field(default_factory=list)
    involved_hosts:      list[str] = Field(default_factory=list)
    involved_ips:        list[str] = Field(default_factory=list)
    suspicious_processes: list[str] = Field(default_factory=list)
    suspicious_commands: list[str] = Field(default_factory=list)
    suspicious_domains:  list[str] = Field(default_factory=list)
    suspicious_hashes:   list[str] = Field(default_factory=list)
    related_alerts:      list[str] = Field(default_factory=list)
    related_events:      list[str] = Field(default_factory=list)
    attack_paths:        list[list[str]] = Field(default_factory=list)
    historical_group_ids: list[str] = Field(default_factory=list)
    entity_frequency:    dict[str, int] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


# ─── Investigation scoring ────────────────────────────────────────────────────

class InvestigationScore(BaseModel):
    threat_score:     int = 0
    tp_probability:   float = 0.0
    fp_probability:   float = 1.0
    confidence:       str = "low"
    scoring_factors:  dict[str, float] = Field(default_factory=dict)
    score_breakdown:  list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


# ─── Investigation summary ────────────────────────────────────────────────────

class InvestigationSummary(BaseModel):
    investigation_id:           str
    executive_summary:          str = ""
    technical_summary:          str = ""
    attack_progression:         list[str] = Field(default_factory=list)
    suspected_root_cause:       str = ""
    impacted_assets:            list[str] = Field(default_factory=list)
    recommended_actions:        list[str] = Field(default_factory=list)
    analyst_notes:              list[str] = Field(default_factory=list)
    containment_recommendations: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


# ─── Full investigation result ────────────────────────────────────────────────

class InvestigationResult(BaseModel):
    investigation_id:       str
    tenant_id:              str
    investigation_group_id: str
    status:                 str = "new"
    timeline:               AttackTimeline
    graph:                  AttackGraph
    behaviors:              BehaviorAnalysis
    context:                InvestigationContext
    score:                  InvestigationScore
    summary:                InvestigationSummary
    created_at:             float = 0.0
    updated_at:             float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

    def to_db_dict(self) -> dict[str, Any]:
        """Flatten for DB upsert (only persisted fields)."""
        return {
            "investigation_id":       self.investigation_id,
            "tenant_id":              self.tenant_id,
            "investigation_group_id": self.investigation_group_id,
            "threat_score":           self.score.threat_score,
            "confidence":             self.score.confidence,
            "tp_probability":         self.score.tp_probability,
            "fp_probability":         self.score.fp_probability,
            "executive_summary":      self.summary.executive_summary,
            "technical_summary":      self.summary.technical_summary,
            "attack_progression":     self.summary.attack_progression,
            "recommended_actions":    self.summary.recommended_actions,
            "status":                 self.status,
        }

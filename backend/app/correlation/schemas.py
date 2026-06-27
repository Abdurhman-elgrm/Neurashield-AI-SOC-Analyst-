"""
Aggregate output schemas for the correlation layer.

ExtractionResult is the single top-level value produced by EntityExtractor.
It is JSON-serializable (via model_dump()) and safe to embed directly in the
normalized_events Redis stream payload.

EntitySet groups entities by type exactly as specified by the platform's
entity output format contract:
    {"users": [], "hosts": [], "ips": [], "domains": [], "processes": [], "hashes": []}

CorrelationMetadata holds the deterministic cross-event linkage identifiers.
All IDs are UUID5 strings — stable across pipeline replays.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.correlation.entities import (
    DomainEntity,
    HashEntity,
    HostEntity,
    IPEntity,
    ProcessEntity,
    UserEntity,
)


class EntitySet(BaseModel):
    """All entities extracted from a single normalized event, grouped by type."""

    users: list[UserEntity] = Field(default_factory=list)
    hosts: list[HostEntity] = Field(default_factory=list)
    ips: list[IPEntity] = Field(default_factory=list)
    domains: list[DomainEntity] = Field(default_factory=list)
    processes: list[ProcessEntity] = Field(default_factory=list)
    hashes: list[HashEntity] = Field(default_factory=list)


class CorrelationMetadata(BaseModel):
    """
    Deterministic identifiers linking this event into broader correlation chains.

    correlation_id   – tenant + host + optional logon session.  Groups all
                       events from the same activity session on a host.
    session_id       – tenant + host + logon session.  None when no logon
                       context is available (non-auth events without LogonId).
    process_tree_id  – tenant + host + process lineage root.  Groups a parent
                       process and all its spawned children.  None when no
                       process anchor (GUID or ppid) is present.
    event_chain_id   – tenant + host + process GUID (or host alone as fallback).
                       Finer-grained than correlation_id; one chain per process.
    related_entity_keys – flat list of every entity key from this event for
                          fast reverse lookups (populated by enrich_normalized_payload).
    parent_event_id  – Sysmon ParentProcessGuid or equivalent lineage reference.
                       Not a DB foreign key — use it to JOIN on process_guid in
                       a future correlation query.
    """

    correlation_id: str
    session_id: str | None
    process_tree_id: str | None
    event_chain_id: str
    related_entity_keys: list[str] = Field(default_factory=list)
    parent_event_id: str | None


class ExtractionResult(BaseModel):
    """
    Complete output of EntityExtractor.extract() for one event.
    Embed in the normalized event stream payload via enrich_normalized_payload().
    """

    event_id: str
    tenant_id: str
    entities: EntitySet
    correlation_metadata: CorrelationMetadata

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

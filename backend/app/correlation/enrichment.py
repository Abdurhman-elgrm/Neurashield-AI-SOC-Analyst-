"""
Enrichment helpers: merge ExtractionResult data into a normalized event payload.

Called from the normalization worker after entity extraction to add entity and
correlation fields to the Redis stream message before it is published.

All functions mutate the payload dict in-place and return it — zero extra
allocations beyond the data that must be added regardless.
"""

from __future__ import annotations

from typing import Any

from app.correlation.schemas import ExtractionResult


def enrich_normalized_payload(
    payload: dict[str, Any],
    extraction: ExtractionResult,
) -> dict[str, Any]:
    """
    Merge entity extraction results into a normalized event payload dict.

    Mutates `payload` in-place.  Returns the same dict so callers can chain:
        payload = enrich_normalized_payload(normalized.to_dict(), result)

    Fields added
    ────────────
    entities           – serialized EntitySet (users/hosts/ips/domains/processes/hashes)
    correlation_id     – tenant+host+session deterministic UUID5
    session_id         – logon-session-scoped UUID5, or None
    process_tree_id    – process-lineage-scoped UUID5, or None
    event_chain_id     – per-process event chain UUID5
    related_entity_keys – flat list of all entity keys for reverse lookup
    parent_event_id    – Sysmon ParentProcessGuid (lineage reference), or None
    """
    entity_set = extraction.entities
    meta = extraction.correlation_metadata

    # Build the flat key list that goes into related_entity_keys.
    # We collect from all groups in one pass to avoid multiple iterations.
    all_keys: list[str] = []
    for group in (
        entity_set.users,
        entity_set.hosts,
        entity_set.ips,
        entity_set.domains,
        entity_set.processes,
        entity_set.hashes,
    ):
        for entity in group:
            all_keys.append(entity.key)

    # Flat list so the correlation engine can iterate with entity.get("key")
    flat_entities: list[dict] = []
    for group in (
        entity_set.users,
        entity_set.hosts,
        entity_set.ips,
        entity_set.domains,
        entity_set.processes,
        entity_set.hashes,
    ):
        for entity in group:
            flat_entities.append(entity.model_dump())
    payload["entities"] = flat_entities
    payload["correlation_id"] = meta.correlation_id
    payload["session_id"] = meta.session_id
    payload["process_tree_id"] = meta.process_tree_id
    payload["event_chain_id"] = meta.event_chain_id
    payload["related_entity_keys"] = all_keys
    payload["parent_event_id"] = meta.parent_event_id

    return payload


def collect_entity_keys(extraction: ExtractionResult) -> list[str]:
    """
    Return a flat list of all entity keys from an ExtractionResult.

    Useful for building search indexes or cache invalidation lists without
    needing to serialize the full payload.
    """
    keys: list[str] = []
    entity_set = extraction.entities
    for group in (
        entity_set.users,
        entity_set.hosts,
        entity_set.ips,
        entity_set.domains,
        entity_set.processes,
        entity_set.hashes,
    ):
        for entity in group:
            keys.append(entity.key)
    return keys


def entity_counts(extraction: ExtractionResult) -> dict[str, int]:
    """
    Return a dict of entity group → count.  Useful for structured logging
    without serializing the full entity payload.
    """
    e = extraction.entities
    return {
        "users": len(e.users),
        "hosts": len(e.hosts),
        "ips": len(e.ips),
        "domains": len(e.domains),
        "processes": len(e.processes),
        "hashes": len(e.hashes),
    }

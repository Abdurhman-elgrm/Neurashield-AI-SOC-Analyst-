"""
Unit tests for app.correlation.enrichment
"""
from __future__ import annotations

import pytest

from app.correlation.enrichment import (
    collect_entity_keys,
    enrich_normalized_payload,
    entity_counts,
)
from app.correlation.extractor import extract_entities
from app.normalization.models import NormalizedNetwork, NormalizedProcess, NormalizedUser
from unit_tests.correlation.conftest import make_event, sysmon_eid1


# ─── enrich_normalized_payload ────────────────────────────────────────────────

class TestEnrichNormalizedPayload:
    def _enriched(self, **event_kwargs):
        event = make_event(**event_kwargs)
        result = extract_entities(event)
        payload: dict = {"some": "existing_field"}
        return enrich_normalized_payload(payload, result), result

    def test_returns_same_dict_object(self):
        event = make_event()
        result = extract_entities(event)
        payload = {}
        returned = enrich_normalized_payload(payload, result)
        assert returned is payload

    def test_existing_fields_preserved(self):
        event = make_event()
        result = extract_entities(event)
        payload = {"event_db_id": "some-uuid", "stream_id": "1234-5"}
        enrich_normalized_payload(payload, result)
        assert payload["event_db_id"] == "some-uuid"
        assert payload["stream_id"] == "1234-5"

    def test_entities_key_added(self):
        payload, _ = self._enriched()
        assert "entities" in payload
        e = payload["entities"]
        assert "users" in e
        assert "hosts" in e
        assert "ips" in e
        assert "domains" in e
        assert "processes" in e
        assert "hashes" in e

    def test_correlation_id_added(self):
        payload, _ = self._enriched()
        assert "correlation_id" in payload
        assert payload["correlation_id"]

    def test_session_id_added(self):
        payload, _ = self._enriched(raw=sysmon_eid1(logon_id="0x3e9"))
        assert "session_id" in payload

    def test_session_id_none_when_no_logon(self):
        payload, _ = self._enriched()
        assert payload.get("session_id") is None

    def test_process_tree_id_added(self):
        payload, _ = self._enriched(raw=sysmon_eid1())
        assert "process_tree_id" in payload
        assert payload["process_tree_id"] is not None

    def test_event_chain_id_added(self):
        payload, _ = self._enriched(raw=sysmon_eid1())
        assert "event_chain_id" in payload

    def test_related_entity_keys_is_list(self):
        payload, _ = self._enriched(
            hostname="ws01",
            user=NormalizedUser(name="alice"),
        )
        assert isinstance(payload["related_entity_keys"], list)

    def test_related_entity_keys_contains_host_key(self):
        payload, _ = self._enriched(hostname="myhost")
        keys = payload["related_entity_keys"]
        assert any("myhost" in k for k in keys)

    def test_related_entity_keys_no_duplicates(self):
        payload, _ = self._enriched(
            hostname="ws01",
            user=NormalizedUser(name="alice"),
            network=NormalizedNetwork(src_ip="10.0.0.1"),
        )
        keys = payload["related_entity_keys"]
        assert len(keys) == len(set(keys))

    def test_parent_event_id_added(self):
        raw = sysmon_eid1(parent_guid="{parent-0000-guid}")
        payload, _ = self._enriched(raw=raw)
        assert "parent_event_id" in payload
        assert payload["parent_event_id"] == "{parent-0000-guid}"

    def test_parent_event_id_none_without_parent_guid(self):
        payload, _ = self._enriched()
        assert payload.get("parent_event_id") is None

    def test_entities_serializable_as_dict(self):
        payload, _ = self._enriched(raw=sysmon_eid1())
        # entities must be a plain dict (model_dump output), not a Pydantic model
        assert isinstance(payload["entities"], dict)
        assert isinstance(payload["entities"]["processes"], list)


# ─── collect_entity_keys ──────────────────────────────────────────────────────

class TestCollectEntityKeys:
    def test_returns_list(self):
        result = extract_entities(make_event())
        assert isinstance(collect_entity_keys(result), list)

    def test_empty_event_no_keys_except_host(self):
        event = make_event(hostname="ws01")
        result = extract_entities(event)
        keys = collect_entity_keys(result)
        assert any(k == "host:ws01" for k in keys)

    def test_key_count_matches_entity_count(self):
        event = make_event(
            hostname="ws01",
            user=NormalizedUser(name="alice"),
            network=NormalizedNetwork(src_ip="10.0.0.1", dst_ip="8.8.8.8"),
            process=NormalizedProcess(name="cmd.exe"),
        )
        result = extract_entities(event)
        keys = collect_entity_keys(result)
        total_entities = (
            len(result.entities.users)
            + len(result.entities.hosts)
            + len(result.entities.ips)
            + len(result.entities.domains)
            + len(result.entities.processes)
            + len(result.entities.hashes)
        )
        assert len(keys) == total_entities

    def test_no_duplicate_keys(self):
        event = make_event(
            hostname="ws01",
            user=NormalizedUser(name="alice"),
            network=NormalizedNetwork(src_ip="10.0.0.1"),
        )
        result = extract_entities(event)
        keys = collect_entity_keys(result)
        assert len(keys) == len(set(keys))


# ─── entity_counts ────────────────────────────────────────────────────────────

class TestEntityCounts:
    def test_returns_all_group_keys(self):
        result = extract_entities(make_event())
        counts = entity_counts(result)
        assert set(counts.keys()) == {"users", "hosts", "ips", "domains", "processes", "hashes"}

    def test_counts_are_non_negative(self):
        result = extract_entities(make_event())
        for v in entity_counts(result).values():
            assert v >= 0

    def test_counts_match_entity_list_lengths(self):
        event = make_event(
            hostname="ws01",
            user=NormalizedUser(name="alice"),
            network=NormalizedNetwork(src_ip="10.0.0.1", dst_ip="8.8.8.8"),
        )
        result = extract_entities(event)
        counts = entity_counts(result)
        assert counts["hosts"]  == len(result.entities.hosts)
        assert counts["users"]  == len(result.entities.users)
        assert counts["ips"]    == len(result.entities.ips)

    def test_usable_as_structlog_kwargs(self):
        result = extract_entities(make_event(hostname="ws01"))
        counts = entity_counts(result)
        # Must be a flat str→int dict — safe to splat into logger.debug(...)
        assert all(isinstance(k, str) and isinstance(v, int) for k, v in counts.items())

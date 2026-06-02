from __future__ import annotations

import pytest

from app.correlation.matcher import EventMatcher, GroupContext, MatchResult, match_event
from app.correlation.rules import (
    HIGH_FREQUENCY_SOURCE,
    SAME_EVENT_CHAIN,
    SAME_HOST_BURST,
    SAME_LOGON_SESSION,
    SAME_PROCESS_TREE,
    SAME_USER_MULTI_HOST,
    SHARED_DEST_IP,
    SHARED_DOMAIN,
    SHARED_FILE_HASH,
    SHARED_SOURCE_IP,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

_CID = "corr-aaaa"
_SID = "sess-bbbb"
_PTID = "ptid-cccc"
_ECID = "ecid-dddd"


def _ctx(**overrides: int) -> GroupContext:
    return GroupContext(window_counts=overrides)  # type: ignore[arg-type]


def _payload(
    *,
    cid: str | None = _CID,
    sid: str | None = _SID,
    ptid: str | None = _PTID,
    ecid: str | None = _ECID,
    entities: list[dict] | None = None,
) -> dict:
    p: dict = {}
    if cid:
        p["correlation_id"] = cid
    if sid:
        p["session_id"] = sid
    if ptid:
        p["process_tree_id"] = ptid
    if ecid:
        p["event_chain_id"] = ecid
    p["entities"] = entities or []
    return p


def _rule_names(result: MatchResult) -> list[str]:
    return [r.rule.name for r in result.matched_rules]


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestMatcherNoEntities:
    def test_no_rules_on_empty_context(self):
        result = match_event(_payload(), GroupContext())
        assert not result.any_matched

    def test_burst_fires_at_threshold(self):
        ctx = GroupContext(
            window_counts={(f"cid:{_CID}", SAME_HOST_BURST.window_seconds): 3}
        )
        result = match_event(_payload(), ctx)
        assert "same_host_burst" in _rule_names(result)

    def test_burst_does_not_fire_below_threshold(self):
        ctx = GroupContext(
            window_counts={(f"cid:{_CID}", SAME_HOST_BURST.window_seconds): 2}
        )
        result = match_event(_payload(), ctx)
        assert "same_host_burst" not in _rule_names(result)

    def test_session_fires_at_2(self):
        ctx = GroupContext(
            window_counts={(f"sid:{_SID}", SAME_LOGON_SESSION.window_seconds): 2}
        )
        result = match_event(_payload(), ctx)
        assert "same_logon_session" in _rule_names(result)

    def test_process_tree_fires_at_2(self):
        ctx = GroupContext(
            window_counts={(f"ptid:{_PTID}", SAME_PROCESS_TREE.window_seconds): 2}
        )
        result = match_event(_payload(), ctx)
        assert "same_process_tree" in _rule_names(result)

    def test_event_chain_fires_at_2(self):
        ctx = GroupContext(
            window_counts={(f"ecid:{_ECID}", SAME_EVENT_CHAIN.window_seconds): 2}
        )
        result = match_event(_payload(), ctx)
        assert "same_event_chain" in _rule_names(result)

    def test_high_frequency_fires_at_10(self):
        ctx = GroupContext(
            window_counts={(f"cid:{_CID}", HIGH_FREQUENCY_SOURCE.window_seconds): 10}
        )
        result = match_event(_payload(), ctx)
        assert "high_frequency_source" in _rule_names(result)

    def test_high_frequency_does_not_fire_at_9(self):
        ctx = GroupContext(
            window_counts={(f"cid:{_CID}", HIGH_FREQUENCY_SOURCE.window_seconds): 9}
        )
        result = match_event(_payload(), ctx)
        assert "high_frequency_source" not in _rule_names(result)


class TestMatcherWithEntities:
    def _ip_entity(self, address: str, direction: str = "") -> dict:
        return {"key": f"ip:{address}", "direction": direction}

    def _domain_entity(self, fqdn: str) -> dict:
        return {"key": f"domain:{fqdn}"}

    def _user_entity(self, name: str) -> dict:
        return {"key": f"user:{name}"}

    def _hash_entity(self, alg: str, val: str) -> dict:
        return {"key": f"hash:{alg}:{val}"}

    def test_shared_source_ip(self):
        ek = "ip:10.0.0.1"
        ctx = GroupContext(
            window_counts={(ek, SHARED_SOURCE_IP.window_seconds): 2}
        )
        p = _payload(entities=[self._ip_entity("10.0.0.1", "inbound")])
        result = match_event(p, ctx)
        assert "shared_source_ip" in _rule_names(result)

    def test_shared_dest_ip(self):
        ek = "ip:93.184.216.34"
        ctx = GroupContext(
            window_counts={(ek, SHARED_DEST_IP.window_seconds): 2}
        )
        p = _payload(entities=[self._ip_entity("93.184.216.34", "outbound")])
        result = match_event(p, ctx)
        assert "shared_dest_ip" in _rule_names(result)

    def test_shared_domain(self):
        ek = "domain:evil.example.com"
        ctx = GroupContext(window_counts={(ek, SHARED_DOMAIN.window_seconds): 2})
        p = _payload(entities=[self._domain_entity("evil.example.com")])
        result = match_event(p, ctx)
        assert "shared_domain" in _rule_names(result)

    def test_same_user_multi_host(self):
        ek = "user:corp\\alice"
        ctx = GroupContext(
            window_counts={(ek, SAME_USER_MULTI_HOST.window_seconds): 2}
        )
        p = _payload(entities=[self._user_entity("corp\\alice")])
        result = match_event(p, ctx)
        assert "same_user_multi_host" in _rule_names(result)

    def test_shared_file_hash(self):
        ek = "hash:md5:deadbeef"
        ctx = GroupContext(
            window_counts={(ek, SHARED_FILE_HASH.window_seconds): 2}
        )
        p = _payload(entities=[self._hash_entity("md5", "deadbeef")])
        result = match_event(p, ctx)
        assert "shared_file_hash" in _rule_names(result)

    def test_entity_below_threshold_does_not_fire(self):
        ek = "hash:md5:deadbeef"
        ctx = GroupContext(
            window_counts={(ek, SHARED_FILE_HASH.window_seconds): 1}
        )
        p = _payload(entities=[self._hash_entity("md5", "deadbeef")])
        result = match_event(p, ctx)
        assert "shared_file_hash" not in _rule_names(result)


class TestMatcherGroupKeys:
    def test_group_keys_deduplicated(self):
        # correlation_id generates cid: key via both burst and high_freq
        ctx = GroupContext()
        result = match_event(_payload(sid=None, ptid=None, ecid=None), ctx)
        cid_keys = [k for k in result.group_keys if k.startswith("cid:")]
        assert len(cid_keys) == 1

    def test_no_keys_when_no_ids(self):
        result = match_event(_payload(cid=None, sid=None, ptid=None, ecid=None), GroupContext())
        assert result.group_keys == []

    def test_multiple_entities_all_in_group_keys(self):
        p = _payload(
            cid=None, sid=None, ptid=None, ecid=None,
            entities=[
                {"key": "ip:1.2.3.4", "direction": "outbound"},
                {"key": "domain:test.com"},
            ],
        )
        result = match_event(p, GroupContext())
        assert "ip:1.2.3.4" in result.group_keys
        assert "domain:test.com" in result.group_keys


class TestMatcherMultipleRules:
    def test_multiple_rules_can_fire_simultaneously(self):
        ctx = GroupContext(
            window_counts={
                (f"cid:{_CID}", SAME_HOST_BURST.window_seconds): 5,
                (f"sid:{_SID}", SAME_LOGON_SESSION.window_seconds): 3,
                (f"ptid:{_PTID}", SAME_PROCESS_TREE.window_seconds): 2,
            }
        )
        result = match_event(_payload(ecid=None, entities=[]), ctx)
        names = _rule_names(result)
        assert "same_host_burst" in names
        assert "same_logon_session" in names
        assert "same_process_tree" in names

    def test_any_matched_true_when_at_least_one_rule_fires(self):
        ctx = GroupContext(
            window_counts={(f"cid:{_CID}", SAME_HOST_BURST.window_seconds): 3}
        )
        result = match_event(_payload(), ctx)
        assert result.any_matched

    def test_any_matched_false_when_nothing_fires(self):
        result = match_event(_payload(), GroupContext())
        assert not result.any_matched

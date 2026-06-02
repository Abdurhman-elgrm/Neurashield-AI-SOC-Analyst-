"""
Unit tests for app.correlation.utils
"""
from __future__ import annotations

import uuid

import pytest

from app.correlation.utils import (
    canonical_str,
    deterministic_uuid,
    extract_domain_from_url,
    is_valid_ip,
    make_correlation_id,
    make_event_chain_id,
    make_process_tree_id,
    make_session_id,
    parse_sysmon_hashes,
    safe_get,
    _NS_CORRELATION,
    _NS_SESSION,
)


# ─── safe_get ─────────────────────────────────────────────────────────────────

class TestSafeGet:
    def test_top_level_key(self):
        assert safe_get({"a": 1}, "a") == 1

    def test_nested_two_levels(self):
        assert safe_get({"a": {"b": 2}}, "a", "b") == 2

    def test_nested_three_levels(self):
        assert safe_get({"x": {"y": {"z": "found"}}}, "x", "y", "z") == "found"

    def test_missing_key_returns_default(self):
        assert safe_get({"a": 1}, "b") is None
        assert safe_get({"a": 1}, "b", default="missing") == "missing"

    def test_none_value_returns_default(self):
        assert safe_get({"a": None}, "a") is None

    def test_non_dict_intermediate_returns_default(self):
        assert safe_get({"a": "not-a-dict"}, "a", "b") is None

    def test_non_dict_root_returns_default(self):
        assert safe_get("string", "key") is None
        assert safe_get(None, "key") is None
        assert safe_get(42, "key") is None

    def test_empty_dict_returns_default(self):
        assert safe_get({}, "key") is None


# ─── canonical_str ────────────────────────────────────────────────────────────

class TestCanonicalStr:
    def test_lowercases(self):
        assert canonical_str("UPPERCASE") == "uppercase"

    def test_strips_whitespace(self):
        assert canonical_str("  hello  ") == "hello"

    def test_none_returns_none(self):
        assert canonical_str(None) is None

    def test_empty_string_returns_none(self):
        assert canonical_str("") is None

    def test_whitespace_only_returns_none(self):
        assert canonical_str("   ") is None

    def test_integer_input(self):
        assert canonical_str(42) == "42"

    def test_mixed_case_with_spaces(self):
        assert canonical_str("  FOO\\BAR  ") == "foo\\bar"


# ─── is_valid_ip ──────────────────────────────────────────────────────────────

class TestIsValidIp:
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("10.0.0.0") is True
        assert is_valid_ip("255.255.255.255") is True

    def test_valid_ipv6(self):
        assert is_valid_ip("2001:db8::1") is True
        assert is_valid_ip("::1") is True
        assert is_valid_ip("fe80::1") is True

    def test_invalid_hostname(self):
        assert is_valid_ip("example.com") is False
        assert is_valid_ip("not-an-ip") is False

    def test_empty_string(self):
        assert is_valid_ip("") is False

    def test_none(self):
        assert is_valid_ip(None) is False  # type: ignore[arg-type]

    def test_placeholder(self):
        assert is_valid_ip("-") is False
        assert is_valid_ip("0.0.0.0") is True  # structurally valid even if unspecified


# ─── deterministic_uuid ───────────────────────────────────────────────────────

class TestDeterministicUuid:
    def test_same_inputs_same_output(self):
        ns = uuid.UUID("aaaabbbb-0000-1111-2222-333344445555")
        a = deterministic_uuid(ns, "tenant-1", "host-a", "session-x")
        b = deterministic_uuid(ns, "tenant-1", "host-a", "session-x")
        assert a == b

    def test_different_inputs_different_output(self):
        ns = uuid.UUID("aaaabbbb-0000-1111-2222-333344445555")
        a = deterministic_uuid(ns, "tenant-1", "host-a")
        b = deterministic_uuid(ns, "tenant-1", "host-b")
        assert a != b

    def test_different_tenants_different_output(self):
        ns = uuid.UUID("aaaabbbb-0000-1111-2222-333344445555")
        a = deterministic_uuid(ns, "tenant-1", "host-a")
        b = deterministic_uuid(ns, "tenant-2", "host-a")
        assert a != b

    def test_output_is_valid_uuid_string(self):
        ns = uuid.UUID("aaaabbbb-0000-1111-2222-333344445555")
        result = deterministic_uuid(ns, "part1", "part2")
        parsed = uuid.UUID(result)
        assert str(parsed) == result

    def test_empty_parts_filtered(self):
        ns = uuid.UUID("aaaabbbb-0000-1111-2222-333344445555")
        a = deterministic_uuid(ns, "part1", "", "part2")
        b = deterministic_uuid(ns, "part1", "part2")
        assert a == b


# ─── ID factory functions ─────────────────────────────────────────────────────

class TestIdFactories:
    def test_correlation_id_with_logon(self):
        cid = make_correlation_id("t1", "host1", "0x3e9")
        assert uuid.UUID(cid)  # valid UUID

    def test_correlation_id_without_logon(self):
        cid_with    = make_correlation_id("t1", "host1", "0x3e9")
        cid_without = make_correlation_id("t1", "host1", None)
        assert cid_with != cid_without

    def test_correlation_id_tenant_isolated(self):
        a = make_correlation_id("tenant-A", "host1", None)
        b = make_correlation_id("tenant-B", "host1", None)
        assert a != b

    def test_session_id_deterministic(self):
        a = make_session_id("t1", "host1", "0x3e9")
        b = make_session_id("t1", "host1", "0x3e9")
        assert a == b

    def test_session_id_different_sessions(self):
        a = make_session_id("t1", "host1", "0x3e9")
        b = make_session_id("t1", "host1", "0x3f0")
        assert a != b

    def test_process_tree_id_with_guid(self):
        ptid = make_process_tree_id("t1", "host1", "{guid-abc}", None)
        assert ptid is not None
        assert uuid.UUID(ptid)

    def test_process_tree_id_with_ppid_fallback(self):
        ptid = make_process_tree_id("t1", "host1", None, 5678)
        assert ptid is not None

    def test_process_tree_id_no_anchor_returns_none(self):
        ptid = make_process_tree_id("t1", "host1", None, None)
        assert ptid is None

    def test_event_chain_id_with_guid(self):
        a = make_event_chain_id("t1", "host1", "{guid-abc}")
        b = make_event_chain_id("t1", "host1", "{guid-abc}")
        assert a == b

    def test_event_chain_id_without_guid_falls_back(self):
        eid = make_event_chain_id("t1", "host1", None)
        assert uuid.UUID(eid)  # still a valid UUID


# ─── parse_sysmon_hashes ──────────────────────────────────────────────────────

class TestParseSysmonHashes:
    def test_all_three_algos(self):
        result = parse_sysmon_hashes("MD5=abc,SHA256=def,SHA1=ghi")
        assert result == {"md5": "abc", "sha256": "def", "sha1": "ghi"}

    def test_single_algo(self):
        result = parse_sysmon_hashes("SHA256=deadbeef")
        assert result == {"sha256": "deadbeef"}

    def test_lowercases_values(self):
        result = parse_sysmon_hashes("MD5=ABCDEF")
        assert result["md5"] == "abcdef"

    def test_empty_string(self):
        assert parse_sysmon_hashes("") == {}

    def test_non_string_input(self):
        assert parse_sysmon_hashes(None) == {}  # type: ignore[arg-type]
        assert parse_sysmon_hashes(123) == {}   # type: ignore[arg-type]

    def test_malformed_segment_ignored(self):
        result = parse_sysmon_hashes("MD5=abc,NOEQUALS,SHA256=def")
        assert result == {"md5": "abc", "sha256": "def"}

    def test_unknown_algo_ignored(self):
        result = parse_sysmon_hashes("IMPHASH=xyz,MD5=abc")
        assert result == {"md5": "abc"}


# ─── extract_domain_from_url ──────────────────────────────────────────────────

class TestExtractDomainFromUrl:
    def test_http_url(self):
        assert extract_domain_from_url("http://evil.com/path") == "evil.com"

    def test_https_url(self):
        assert extract_domain_from_url("https://cdn.example.org/file.js") == "cdn.example.org"

    def test_url_with_port(self):
        assert extract_domain_from_url("http://host.example.com:8080/api") == "host.example.com"

    def test_url_with_credentials(self):
        assert extract_domain_from_url("ftp://user:pass@ftp.example.com/pub") == "ftp.example.com"

    def test_bare_hostname(self):
        assert extract_domain_from_url("example.com") == "example.com"

    def test_none_returns_none(self):
        assert extract_domain_from_url(None) is None  # type: ignore[arg-type]

    def test_empty_returns_none(self):
        assert extract_domain_from_url("") is None

    def test_lowercases_result(self):
        assert extract_domain_from_url("https://UPPERCASE.COM/path") == "uppercase.com"

    def test_url_with_query_and_fragment(self):
        assert extract_domain_from_url("https://track.io/pixel?id=1#anchor") == "track.io"

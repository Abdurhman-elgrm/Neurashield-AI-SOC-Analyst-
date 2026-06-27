"""
Pure utility functions for the correlation layer.

All functions are stateless and allocation-minimal.  Regex patterns are
pre-compiled at module load time so the hot path (per-event) pays no
compilation cost.  No recursion anywhere in this module.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

# ─── Namespace UUIDs for deterministic ID generation ─────────────────────────
# These are fixed constants — changing them invalidates all stored correlation
# IDs across the entire event history.

_NS_CORRELATION = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
_NS_SESSION = uuid.UUID("b2c3d4e5-f6a7-8901-bcde-f12345678901")
_NS_PROCESS_TREE = uuid.UUID("c3d4e5f6-a7b8-9012-cdef-123456789012")
_NS_EVENT_CHAIN = uuid.UUID("d4e5f6a7-b8c9-0123-def0-234567890123")

# Pre-compiled structural IP patterns — not RFC-complete but allocation-free.
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}$")


# ─── Core helpers ─────────────────────────────────────────────────────────────


def safe_get(data: Any, *keys: str, default: Any = None) -> Any:
    """
    Navigate nested dicts iteratively.  Returns `default` on any missing key,
    None value, or non-dict intermediate node.  Never raises.
    """
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def canonical_str(value: Any) -> str | None:
    """
    Normalize a value to a stripped, lowercase string.
    Returns None for None, empty, or whitespace-only inputs.
    """
    if value is None:
        return None
    s = str(value).strip().lower()
    return s or None


def is_valid_ip(value: str) -> bool:
    """
    Fast structural IPv4/v6 validation.  Not RFC-complete — intended to filter
    obviously non-IP strings without allocating a full socket.getaddrinfo call.
    """
    if not value or not isinstance(value, str):
        return False
    v = value.strip()
    return bool(_IPV4_RE.match(v) or _IPV6_RE.match(v))


def deterministic_uuid(namespace: uuid.UUID, *parts: str) -> str:
    """
    Produce a stable UUID5 string from a namespace and variable string parts.
    Empty parts are filtered so missing optional fields don't shift the key.
    """
    key = "|".join(p for p in parts if p)
    return str(uuid.uuid5(namespace, key))


# ─── Correlation ID factories ─────────────────────────────────────────────────


def make_correlation_id(
    tenant_id: str,
    hostname: str,
    logon_id: str | None,
) -> str:
    """
    Scope: tenant + host [+ optional logon session].
    Groups all events from the same machine in the same session.
    """
    parts = [tenant_id, hostname]
    if logon_id:
        parts.append(logon_id)
    return deterministic_uuid(_NS_CORRELATION, *parts)


def make_session_id(tenant_id: str, hostname: str, logon_id: str) -> str:
    """Scope: tenant + host + logon session. Only meaningful when logon_id is known."""
    return deterministic_uuid(_NS_SESSION, tenant_id, hostname, logon_id)


def make_process_tree_id(
    tenant_id: str,
    hostname: str,
    process_guid: str | None,
    ppid: int | None,
) -> str | None:
    """
    Scope: tenant + host + process lineage root.
    Returns None when no lineage anchor is available.
    ProcessGuid is preferred; ppid is the fallback.
    """
    if process_guid:
        return deterministic_uuid(_NS_PROCESS_TREE, tenant_id, hostname, process_guid)
    if ppid is not None:
        return deterministic_uuid(_NS_PROCESS_TREE, tenant_id, hostname, str(ppid))
    return None


def make_event_chain_id(
    tenant_id: str,
    hostname: str,
    process_guid: str | None,
) -> str:
    """
    Scope: per-process event chain.
    Falls back to tenant+host when no process anchor is available, which
    gives a coarser but still tenant-isolated identifier.
    """
    if process_guid:
        return deterministic_uuid(_NS_EVENT_CHAIN, tenant_id, hostname, process_guid)
    return deterministic_uuid(_NS_EVENT_CHAIN, tenant_id, hostname)


# ─── Parsing helpers ──────────────────────────────────────────────────────────


def parse_sysmon_hashes(raw_hashes: Any) -> dict[str, str]:
    """
    Parse Sysmon Hashes field format: 'MD5=abc,SHA256=def,SHA1=ghi'.
    Returns {'md5': 'abc', 'sha256': 'def', 'sha1': 'ghi'}.
    Ignores malformed or unknown-algorithm segments silently.
    """
    result: dict[str, str] = {}
    if not isinstance(raw_hashes, str) or not raw_hashes:
        return result
    for part in raw_hashes.split(","):
        if "=" in part:
            algo, _, val = part.partition("=")
            algo_c = algo.strip().lower()
            val_c = val.strip().lower()
            if algo_c in ("md5", "sha1", "sha256") and val_c:
                result[algo_c] = val_c
    return result


def extract_domain_from_url(url: Any) -> str | None:
    """
    Extract the hostname component from a URL string.
    Handles scheme, credentials, path, query, fragment, and port.
    Returns None for None, non-string, or unresolvable inputs.
    """
    if not isinstance(url, str) or not url.strip():
        return None
    s = url.strip()
    # Strip scheme
    if "://" in s:
        s = s.split("://", 1)[1]
    # Strip credentials (user:pass@host)
    if "@" in s:
        s = s.split("@", 1)[1]
    # Strip path, query, fragment
    s = s.split("/")[0].split("?")[0].split("#")[0]
    # Strip port — but guard against bare IPv6 addresses like [::1]:8080
    if not s.startswith("["):
        s = s.split(":")[0]
    return s.lower().strip() or None

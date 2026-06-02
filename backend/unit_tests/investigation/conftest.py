from __future__ import annotations

"""Shared fixtures and factories for the investigation test suite."""

from typing import Any

TENANT_ID = "tenant-inv-test-0000-1111-2222-33334444"
INV_ID    = "inv-aaaa-bbbb-cccc-dddd-eeeeffffgggg"

_TS_BASE = 1_700_000_000.0


def make_snapshot(
    *,
    event_id: str = "evt-001",
    timestamp: float = _TS_BASE,
    hostname: str = "WORKSTATION-01",
    category: str = "process",
    severity: int = 3,
    process: dict | None = None,
    network: dict | None = None,
    user: dict | None = None,
    raw: dict | None = None,
    related_entity_keys: list[str] | None = None,
    entities: list[dict] | None = None,
    correlation_id: str | None = "cid-aaa",
    session_id: str | None = "sid-bbb",
    process_tree_id: str | None = "ptid-ccc",
    event_chain_id: str | None = "ecid-ddd",
    matched_rules: list[str] | None = None,
    tenant_id: str = TENANT_ID,
) -> dict[str, Any]:
    return {
        "event_id":           event_id,
        "tenant_id":          tenant_id,
        "timestamp":          timestamp,
        "hostname":           hostname,
        "category":           category,
        "severity":           severity,
        "process":            process or {},
        "network":            network or {},
        "user":               user or {},
        "raw":                raw or {},
        "related_entity_keys": related_entity_keys or [f"host:{hostname.lower()}"],
        "entities":           entities or [],
        "correlation_id":     correlation_id,
        "session_id":         session_id,
        "process_tree_id":    process_tree_id,
        "event_chain_id":     event_chain_id,
        "matched_rules":      matched_rules or [],
    }


def make_process_snapshot(
    *,
    event_id: str = "proc-001",
    hostname: str = "WORKSTATION-01",
    process_name: str = "cmd.exe",
    cmd_line: str = "cmd.exe /c whoami",
    timestamp: float = _TS_BASE,
    severity: int = 3,
    parent_guid: str | None = None,
) -> dict[str, Any]:
    proc = {
        "name": process_name,
        "executable": f"C:\\Windows\\System32\\{process_name}",
        "command_line": cmd_line,
    }
    if parent_guid:
        proc["parent_guid"] = parent_guid
    return make_snapshot(
        event_id=event_id,
        hostname=hostname,
        category="process",
        severity=severity,
        timestamp=timestamp,
        process=proc,
        related_entity_keys=[
            f"host:{hostname.lower()}",
            f"proc:exe:c:\\windows\\system32\\{process_name.lower()}",
        ],
    )


def make_network_snapshot(
    *,
    event_id: str = "net-001",
    hostname: str = "WORKSTATION-01",
    src_ip: str = "10.0.0.1",
    dst_ip: str = "93.184.216.34",
    dst_port: int = 443,
    timestamp: float = _TS_BASE + 10,
) -> dict[str, Any]:
    return make_snapshot(
        event_id=event_id,
        hostname=hostname,
        category="network",
        severity=2,
        timestamp=timestamp,
        network={"source_ip": src_ip, "destination_ip": dst_ip, "destination_port": dst_port},
        related_entity_keys=[
            f"host:{hostname.lower()}",
            f"ip:{src_ip}",
            f"ip:{dst_ip}",
        ],
    )

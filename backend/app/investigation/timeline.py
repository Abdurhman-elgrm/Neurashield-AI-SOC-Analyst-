from __future__ import annotations

"""
Chronological attack timeline builder.

Consumes a list of event snapshots (dicts from the correlated_events stream)
and produces an AttackTimeline with full chronological ordering, group mappings,
and aggregate statistics.

No I/O — pure data transformation.
"""

from typing import Any

from app.investigation.schemas import AttackTimeline, TimelineEntry


def _process_name(snapshot: dict[str, Any]) -> str | None:
    proc = snapshot.get("process") or {}
    if isinstance(proc, dict):
        return proc.get("name") or proc.get("executable") or None
    return None


def _username(snapshot: dict[str, Any]) -> str | None:
    user = snapshot.get("user") or {}
    if isinstance(user, dict):
        name = user.get("name") or user.get("username")
        if name:
            return str(name)
    for ek in snapshot.get("related_entity_keys", []):
        if isinstance(ek, str) and ek.startswith("user:"):
            return ek[5:]
    return None


def _action_from_category(category: str) -> str:
    _MAP = {
        "process": "process_execution",
        "network": "network_connection",
        "file": "file_operation",
        "auth": "authentication",
        "registry": "registry_access",
        "dns": "dns_query",
        "other": "event",
    }
    return _MAP.get(str(category).lower(), "event")


def _outcome_from_severity(severity: int) -> str:
    if severity >= 8:
        return "critical"
    if severity >= 5:
        return "high"
    if severity >= 3:
        return "medium"
    return "low"


def _ip_keys(entity_keys: list[str]) -> list[str]:
    return [k[3:] for k in entity_keys if k.startswith("ip:")]


def _process_keys(entity_keys: list[str]) -> list[str]:
    return [k for k in entity_keys if k.startswith("proc:")]


def build_timeline(
    investigation_id: str,
    tenant_id: str,
    snapshots: list[dict[str, Any]],
) -> AttackTimeline:
    """
    Build an AttackTimeline from a list of event snapshots.
    Snapshots must each have at least: event_id, timestamp.
    """
    if not snapshots:
        return AttackTimeline(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
        )

    entries: list[TimelineEntry] = []
    session_groups: dict[str, list[str]] = {}
    process_tree_groups: dict[str, list[str]] = {}
    correlation_groups: dict[str, list[str]] = {}

    hosts: set[str] = set()
    users: set[str] = set()
    ips: set[str] = set()
    procs: set[str] = set()

    for snap in snapshots:
        event_id = str(snap.get("event_id") or snap.get("event_db_id") or "")
        if not event_id:
            continue

        ts_raw = snap.get("timestamp") or 0.0
        try:
            ts = float(ts_raw)
        except (TypeError, ValueError):
            ts = 0.0

        hostname = str(snap.get("hostname") or "")
        category = str(snap.get("category") or "other")
        severity = int(snap.get("severity") or 1)
        entity_keys: list[str] = snap.get("related_entity_keys") or snap.get("entity_keys") or []
        matched_rules: list[str] = snap.get("matched_rules") or []

        username = _username(snap)
        process = _process_name(snap)

        entry = TimelineEntry(
            event_id=event_id,
            timestamp=ts,
            hostname=hostname,
            username=username,
            process=process,
            action=_action_from_category(category),
            outcome=_outcome_from_severity(severity),
            rule_match=list(matched_rules),
            severity=severity,
            category=category,
            entity_keys=list(entity_keys),
        )
        entries.append(entry)

        if hostname:
            hosts.add(hostname)
        if username:
            users.add(username)
        ips.update(_ip_keys(entity_keys))
        if process:
            procs.add(process)

        # Group mappings
        sid = snap.get("session_id")
        if sid:
            session_groups.setdefault(sid, []).append(event_id)

        ptid = snap.get("process_tree_id")
        if ptid:
            process_tree_groups.setdefault(ptid, []).append(event_id)

        cid = snap.get("correlation_id")
        if cid:
            correlation_groups.setdefault(cid, []).append(event_id)

    # Sort chronologically
    entries.sort(key=lambda e: e.timestamp)

    timestamps = [e.timestamp for e in entries if e.timestamp > 0]
    first_seen = min(timestamps) if timestamps else 0.0
    last_seen = max(timestamps) if timestamps else 0.0
    duration = max(last_seen - first_seen, 0.0)

    return AttackTimeline(
        investigation_id=investigation_id,
        tenant_id=tenant_id,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
        total_events=len(entries),
        distinct_hosts=len(hosts),
        distinct_users=len(users),
        distinct_ips=len(ips),
        distinct_processes=len(procs),
        entries=entries,
        session_groups=session_groups,
        process_tree_groups=process_tree_groups,
        correlation_groups=correlation_groups,
    )

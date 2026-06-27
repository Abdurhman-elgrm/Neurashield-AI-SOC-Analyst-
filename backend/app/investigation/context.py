from __future__ import annotations

"""
Analyst-ready investigation context builder.

Aggregates entity data across all event snapshots, classifies suspicious
artifacts, and computes attack paths from the attack graph.
"""

from typing import Any

from app.investigation.schemas import (
    AttackGraph,
    AttackTimeline,
    BehaviorAnalysis,
    InvestigationContext,
)

# ─── Suspicious classification ────────────────────────────────────────────────

_SUSPICIOUS_PROC_NAMES: frozenset[str] = frozenset(
    {
        # credential access
        "mimikatz.exe",
        "mimikatz",
        "procdump.exe",
        "procdump",
        "wce.exe",
        "pwdump7.exe",
        "fgdump",
        # lolbas
        "mshta.exe",
        "regsvr32.exe",
        "rundll32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "installutil.exe",
        # lateral movement
        "psexec.exe",
        "psexesvc.exe",
        # C2 / RAT
        "nc.exe",
        "ncat.exe",
        # impact
        "xmrig.exe",
    }
)

_SUSPICIOUS_DOMAIN_PATTERNS: list[str] = [
    ".onion",
    ".xyz",
    ".top",
    ".club",
    ".icu",
    "pastebin.com",
    "ngrok.io",
    "serveo.net",
]

_SUSPICIOUS_CMD_PATTERNS: list[str] = [
    "-enc",
    "-encodedcommand",
    "invoke-expression",
    "iex(",
    "downloadstring",
    "frombase64string",
    "sekurlsa",
    "lsadump",
    "vssadmin delete",
    "wevtutil cl",
    "net user /add",
    "schtasks /create",
]


# ─── Context builder ──────────────────────────────────────────────────────────


def build_context(
    investigation_id: str,
    tenant_id: str,
    timeline: AttackTimeline,
    graph: AttackGraph,
    behaviors: BehaviorAnalysis,
    snapshots: list[dict[str, Any]],
    historical_group_ids: list[str] | None = None,
) -> InvestigationContext:
    import os as _os

    involved_users: list[str] = []
    involved_hosts: list[str] = []
    involved_ips: list[str] = []
    suspicious_processes: list[str] = []
    suspicious_commands: list[str] = []
    suspicious_domains: list[str] = []
    suspicious_hashes: list[str] = []
    related_events: list[str] = []
    entity_frequency: dict[str, int] = {}

    seen_users: set[str] = set()
    seen_hosts: set[str] = set()
    seen_ips: set[str] = set()
    seen_procs: set[str] = set()
    seen_cmds: set[str] = set()
    seen_domains: set[str] = set()
    seen_hashes: set[str] = set()

    for snap in snapshots:
        eid = str(snap.get("event_id") or snap.get("event_db_id") or "")
        if eid:
            related_events.append(eid)

        # entity keys
        for ek in snap.get("related_entity_keys") or []:
            entity_frequency[ek] = entity_frequency.get(ek, 0) + 1
            lower = ek.lower()
            if lower.startswith("user:") and ek[5:] not in seen_users:
                seen_users.add(ek[5:])
                involved_users.append(ek[5:])
            elif lower.startswith("host:") and ek[5:] not in seen_hosts:
                seen_hosts.add(ek[5:])
                involved_hosts.append(ek[5:])
            elif lower.startswith("ip:") and ek[3:] not in seen_ips:
                seen_ips.add(ek[3:])
                involved_ips.append(ek[3:])
            elif lower.startswith("hash:") and ek not in seen_hashes:
                seen_hashes.add(ek)
                suspicious_hashes.append(ek)
            elif lower.startswith("domain:") and ek[7:] not in seen_domains:
                seen_domains.add(ek[7:])
                d = ek[7:]
                if any(pat in d for pat in _SUSPICIOUS_DOMAIN_PATTERNS):
                    suspicious_domains.append(d)

        # hostname
        host = str(snap.get("hostname") or "")
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            involved_hosts.append(host)

        # process
        proc_dict = snap.get("process") or {}
        if isinstance(proc_dict, dict):
            img = proc_dict.get("executable") or proc_dict.get("name") or ""
            if img:
                basename = _os.path.basename(str(img)).lower()
                if basename not in seen_procs:
                    seen_procs.add(basename)
                    if basename in _SUSPICIOUS_PROC_NAMES:
                        suspicious_processes.append(str(img))
            cmd = str(proc_dict.get("command_line") or "")
            if cmd:
                cmd_lower = cmd.lower()
                for pat in _SUSPICIOUS_CMD_PATTERNS:
                    if pat in cmd_lower and cmd not in seen_cmds:
                        seen_cmds.add(cmd)
                        suspicious_commands.append(cmd[:512])
                        break

        # raw field fallback for commands
        raw = snap.get("raw") or {}
        if isinstance(raw, dict):
            cmd_raw = str(raw.get("CommandLine") or raw.get("command_line") or "")
            if cmd_raw:
                cmd_low = cmd_raw.lower()
                for pat in _SUSPICIOUS_CMD_PATTERNS:
                    if pat in cmd_low and cmd_raw not in seen_cmds:
                        seen_cmds.add(cmd_raw)
                        suspicious_commands.append(cmd_raw[:512])
                        break

    # Attack paths from graph (shortest paths between user→host→ip chains)
    attack_paths = _extract_attack_paths(graph)

    return InvestigationContext(
        investigation_id=investigation_id,
        tenant_id=tenant_id,
        involved_users=involved_users,
        involved_hosts=involved_hosts,
        involved_ips=involved_ips,
        suspicious_processes=suspicious_processes,
        suspicious_commands=suspicious_commands,
        suspicious_domains=suspicious_domains,
        suspicious_hashes=suspicious_hashes,
        related_alerts=[],  # filled by investigation engine if alert data available
        related_events=list(dict.fromkeys(related_events)),
        attack_paths=attack_paths,
        historical_group_ids=historical_group_ids or [],
        entity_frequency=entity_frequency,
    )


def _extract_attack_paths(graph: AttackGraph) -> list[list[str]]:
    """
    Extract meaningful attack paths from the graph.
    Looks for user→host, host→ip, process→ip chains.
    Returns up to 5 paths, each capped at 6 hops.
    """
    from app.investigation.graph import AttackGraphBuilder

    paths: list[list[str]] = []

    user_nodes = [n.node_id for n in graph.nodes if n.node_id.startswith("user:")]
    ip_nodes = [n.node_id for n in graph.nodes if n.node_id.startswith("ip:")]

    for u in user_nodes[:3]:
        for ip in ip_nodes[:3]:
            path = AttackGraphBuilder.shortest_path(graph, u, ip, max_hops=6)
            if path and len(path) >= 2:
                paths.append(path)
            if len(paths) >= 5:
                break
        if len(paths) >= 5:
            break

    return paths

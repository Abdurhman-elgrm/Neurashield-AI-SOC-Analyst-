from __future__ import annotations

"""
Generic behavior detection engine with MITRE ATT&CK tactic mapping.

Detection is entirely pattern-based — no ML, no hardcoded single-attack
scenarios. Patterns are keyed by behavior name; each pattern is an independent
checker that inspects the timeline and entity set.

Each checker returns a DetectedBehavior (or None) and is registered in
_BEHAVIOR_CHECKERS. The engine calls each checker in sequence.
"""

from typing import Any, Callable

from app.investigation.schemas import (
    AttackTimeline,
    BehaviorAnalysis,
    DetectedBehavior,
)

# ─── Pattern tables ───────────────────────────────────────────────────────────

# Lowercase process basenames that indicate specific categories.
_PROC_CREDENTIAL_ACCESS: frozenset[str] = frozenset({
    "mimikatz.exe", "mimikatz", "procdump.exe", "procdump", "wce.exe", "wce",
    "pwdump", "pwdump7.exe", "fgdump", "lsass.exe", "sekurlsa", "hashdump",
    "ntdsutil.exe", "ntdsutil",
})

_PROC_DISCOVERY: frozenset[str] = frozenset({
    "whoami.exe", "whoami", "net.exe", "net", "net1.exe", "net1",
    "ipconfig.exe", "ipconfig", "arp.exe", "arp", "nslookup.exe", "nslookup",
    "systeminfo.exe", "systeminfo", "tasklist.exe", "tasklist",
    "nltest.exe", "nltest", "quser.exe", "quser", "wmic.exe", "wmic",
    "netstat.exe", "netstat", "ping.exe", "ping", "tracert.exe", "tracert",
})

_PROC_LATERAL_MOVEMENT: frozenset[str] = frozenset({
    "psexec.exe", "psexec", "psexesvc.exe", "wmiexec.py", "smbexec.py",
    "dcomexec.py", "evil-winrm", "crackmapexec", "impacket",
})

_PROC_EXECUTION_LOLBAS: frozenset[str] = frozenset({
    "powershell.exe", "powershell", "wscript.exe", "wscript",
    "cscript.exe", "cscript", "mshta.exe", "mshta",
    "regsvr32.exe", "regsvr32", "rundll32.exe", "rundll32",
    "certutil.exe", "certutil", "bitsadmin.exe", "bitsadmin",
    "msiexec.exe", "msiexec", "installutil.exe", "installutil",
    "odbcconf.exe", "odbcconf", "regasm.exe", "regasm",
})

_PROC_PERSISTENCE: frozenset[str] = frozenset({
    "schtasks.exe", "schtasks", "at.exe", "at", "sc.exe", "sc",
    "reg.exe", "reg", "cron", "crontab",
})

_PROC_DEFENSE_EVASION: frozenset[str] = frozenset({
    "vssadmin.exe", "vssadmin", "wevtutil.exe", "wevtutil",
    "bcdedit.exe", "bcdedit", "netsh.exe", "netsh",
    "cipher.exe", "cipher",
})

_PROC_COLLECTION: frozenset[str] = frozenset({
    "rar.exe", "rar", "7z.exe", "7z", "zip.exe", "winzip.exe",
    "xcopy.exe", "xcopy", "robocopy.exe", "robocopy",
})

_PROC_EXFILTRATION: frozenset[str] = frozenset({
    "ftp.exe", "ftp", "curl.exe", "curl", "wget.exe", "wget",
    "nc.exe", "nc", "ncat.exe", "ncat",
})

_PROC_IMPACT: frozenset[str] = frozenset({
    "vssadmin.exe", "cipher.exe", "format.exe", "del.exe",
    "xmrig.exe", "xmrig", "cryptominer",
})

# Command-line substrings that indicate specific behaviors (lowercase).
_CMD_CREDENTIAL: list[str] = [
    "sekurlsa", "lsadump", "dumpcreds", "hashdump", "/sam",
    "invoke-mimikatz", "dcsync", "ntds.dit",
]
_CMD_DISCOVERY: list[str] = [
    "net user", "net group", "net localgroup", "net share",
    "whoami /priv", "whoami /groups", "tasklist /v",
    "get-aduser", "get-adgroup", "get-adcomputer",
]
_CMD_EXECUTION_ENCODED: list[str] = [
    "-enc", "-encodedcommand", "invoke-expression", "iex(",
    "downloadstring", "frombase64string", "-nop", "-windowstyle hidden",
]
_CMD_DEFENSE_EVASION: list[str] = [
    "clear-eventlog", "wevtutil cl", "wevtutil clear",
    "vssadmin delete", "bcdedit /set", "remove-item",
    "set-mppreference", "add-mppreference",
]
_CMD_LATERAL: list[str] = [
    "psexec \\\\", "wmic /node:", "invoke-command -computername",
    "new-pssession", "enter-pssession",
]
_CMD_PERSISTENCE: list[str] = [
    "schtasks /create", "reg add", "sc create", "sc config",
    "new-scheduledtask", "add-scheduledtask",
    "set-itemproperty.*run",
]
_CMD_COLLECTION: list[str] = [
    "compress-archive", "7z a", "rar a", "xcopy /s", "robocopy /s",
]
_CMD_EXFIL: list[str] = [
    "curl -t", "curl --upload", "ftp -s:", "certutil -encode",
    "invoke-webrequest -outfile",
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _proc_basenames(timeline: AttackTimeline) -> list[str]:
    names: list[str] = []
    for entry in timeline.entries:
        if entry.process:
            import os
            names.append(os.path.basename(entry.process).lower())
    return names


def _cmd_lines(snapshots: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for snap in snapshots:
        proc = snap.get("process") or {}
        if isinstance(proc, dict):
            cmd = proc.get("command_line") or proc.get("cmd") or ""
            if cmd:
                lines.append(str(cmd).lower())
        raw = snap.get("raw") or {}
        if isinstance(raw, dict):
            for field in ("CommandLine", "command_line", "cmd", "proctitle"):
                val = raw.get(field)
                if val:
                    lines.append(str(val).lower())
    return lines


def _distinct_hosts(timeline: AttackTimeline) -> set[str]:
    return {e.hostname for e in timeline.entries if e.hostname}


def _distinct_users(timeline: AttackTimeline) -> set[str]:
    return {e.username for e in timeline.entries if e.username}


def _event_ids_for_proc(timeline: AttackTimeline, proc_set: frozenset[str]) -> list[str]:
    import os
    ids = []
    for e in timeline.entries:
        if e.process and os.path.basename(e.process).lower() in proc_set:
            ids.append(e.event_id)
    return ids


def _event_ids_for_cmd(timeline: AttackTimeline, snapshots: list[dict[str, Any]], patterns: list[str]) -> list[str]:
    import os
    ids = []
    for snap in snapshots:
        proc = snap.get("process") or {}
        raw  = snap.get("raw") or {}
        cmd = ""
        if isinstance(proc, dict):
            cmd = str(proc.get("command_line") or "").lower()
        if not cmd and isinstance(raw, dict):
            cmd = str(raw.get("CommandLine") or raw.get("command_line") or "").lower()
        for pat in patterns:
            if pat in cmd:
                eid = str(snap.get("event_id") or snap.get("event_db_id") or "")
                if eid:
                    ids.append(eid)
                break
    return ids


def _min_max_ts(timeline: AttackTimeline, event_ids: list[str]) -> tuple[float, float]:
    ts = [e.timestamp for e in timeline.entries if e.event_id in set(event_ids) and e.timestamp > 0]
    if not ts:
        return timeline.first_seen, timeline.last_seen
    return min(ts), max(ts)


# ─── Behavior checkers ────────────────────────────────────────────────────────

BehaviorChecker = Callable[
    [AttackTimeline, list[dict[str, Any]]],
    DetectedBehavior | None,
]


def _check_credential_access(
    timeline: AttackTimeline,
    snapshots: list[dict[str, Any]],
) -> DetectedBehavior | None:
    import os
    proc_hits = [
        e.event_id for e in timeline.entries
        if e.process and os.path.basename(e.process).lower() in _PROC_CREDENTIAL_ACCESS
    ]
    cmd_hits = _event_ids_for_cmd(timeline, snapshots, _CMD_CREDENTIAL)
    all_hits = list(dict.fromkeys(proc_hits + cmd_hits))
    if not all_hits:
        return None
    evidence = [f"Detected credential access process/command ({len(all_hits)} events)"]
    confidence = min(0.5 + len(all_hits) * 0.1, 0.95)
    first, last = _min_max_ts(timeline, all_hits)
    return DetectedBehavior(
        behavior_name="credential_access",
        mitre_tactics=["TA0006"],
        confidence=round(confidence, 2),
        evidence=evidence,
        event_ids=all_hits,
        first_seen=first,
        last_seen=last,
    )


def _check_discovery(
    timeline: AttackTimeline,
    snapshots: list[dict[str, Any]],
) -> DetectedBehavior | None:
    import os
    proc_hits = [
        e.event_id for e in timeline.entries
        if e.process and os.path.basename(e.process).lower() in _PROC_DISCOVERY
    ]
    cmd_hits = _event_ids_for_cmd(timeline, snapshots, _CMD_DISCOVERY)
    all_hits = list(dict.fromkeys(proc_hits + cmd_hits))
    if len(all_hits) < 2:
        return None
    evidence = [f"Reconnaissance commands detected ({len(all_hits)} events)"]
    confidence = min(0.3 + len(all_hits) * 0.08, 0.90)
    first, last = _min_max_ts(timeline, all_hits)
    return DetectedBehavior(
        behavior_name="discovery",
        mitre_tactics=["TA0007"],
        confidence=round(confidence, 2),
        evidence=evidence,
        event_ids=all_hits,
        first_seen=first,
        last_seen=last,
    )


def _check_execution(
    timeline: AttackTimeline,
    snapshots: list[dict[str, Any]],
) -> DetectedBehavior | None:
    import os
    proc_hits = [
        e.event_id for e in timeline.entries
        if e.process and os.path.basename(e.process).lower() in _PROC_EXECUTION_LOLBAS
    ]
    cmd_hits = _event_ids_for_cmd(timeline, snapshots, _CMD_EXECUTION_ENCODED)
    all_hits = list(dict.fromkeys(proc_hits + cmd_hits))
    if not all_hits:
        return None
    evidence = []
    if proc_hits:
        evidence.append(f"Living-off-the-land binary (LOLBAS) detected ({len(proc_hits)} events)")
    if cmd_hits:
        evidence.append(f"Encoded/obfuscated command-line detected ({len(cmd_hits)} events)")
    confidence = min(0.4 + len(all_hits) * 0.1, 0.90)
    first, last = _min_max_ts(timeline, all_hits)
    return DetectedBehavior(
        behavior_name="execution",
        mitre_tactics=["TA0002"],
        confidence=round(confidence, 2),
        evidence=evidence,
        event_ids=all_hits,
        first_seen=first,
        last_seen=last,
    )


def _check_persistence(
    timeline: AttackTimeline,
    snapshots: list[dict[str, Any]],
) -> DetectedBehavior | None:
    import os
    proc_hits = [
        e.event_id for e in timeline.entries
        if e.process and os.path.basename(e.process).lower() in _PROC_PERSISTENCE
    ]
    cmd_hits = _event_ids_for_cmd(timeline, snapshots, _CMD_PERSISTENCE)
    all_hits = list(dict.fromkeys(proc_hits + cmd_hits))
    if not all_hits:
        return None
    evidence = [f"Persistence mechanism detected ({len(all_hits)} events)"]
    confidence = min(0.5 + len(all_hits) * 0.12, 0.92)
    first, last = _min_max_ts(timeline, all_hits)
    return DetectedBehavior(
        behavior_name="persistence",
        mitre_tactics=["TA0003"],
        confidence=round(confidence, 2),
        evidence=evidence,
        event_ids=all_hits,
        first_seen=first,
        last_seen=last,
    )


def _check_defense_evasion(
    timeline: AttackTimeline,
    snapshots: list[dict[str, Any]],
) -> DetectedBehavior | None:
    import os
    proc_hits = [
        e.event_id for e in timeline.entries
        if e.process and os.path.basename(e.process).lower() in _PROC_DEFENSE_EVASION
    ]
    cmd_hits = _event_ids_for_cmd(timeline, snapshots, _CMD_DEFENSE_EVASION)
    all_hits = list(dict.fromkeys(proc_hits + cmd_hits))
    if not all_hits:
        return None
    evidence = [f"Defense evasion indicators detected ({len(all_hits)} events)"]
    confidence = min(0.45 + len(all_hits) * 0.1, 0.90)
    first, last = _min_max_ts(timeline, all_hits)
    return DetectedBehavior(
        behavior_name="defense_evasion",
        mitre_tactics=["TA0005"],
        confidence=round(confidence, 2),
        evidence=evidence,
        event_ids=all_hits,
        first_seen=first,
        last_seen=last,
    )


def _check_lateral_movement(
    timeline: AttackTimeline,
    snapshots: list[dict[str, Any]],
) -> DetectedBehavior | None:
    import os
    proc_hits = [
        e.event_id for e in timeline.entries
        if e.process and os.path.basename(e.process).lower() in _PROC_LATERAL_MOVEMENT
    ]
    cmd_hits = _event_ids_for_cmd(timeline, snapshots, _CMD_LATERAL)
    # Cross-host same user is also a lateral movement indicator
    hosts = _distinct_hosts(timeline)
    users = _distinct_users(timeline)
    cross_host_hit = len(hosts) >= 2 and len(users) >= 1
    all_hits = list(dict.fromkeys(proc_hits + cmd_hits))
    if not all_hits and not cross_host_hit:
        return None
    evidence = []
    if all_hits:
        evidence.append(f"Lateral movement tool/command detected ({len(all_hits)} events)")
    if cross_host_hit:
        evidence.append(f"Same user active on {len(hosts)} distinct hosts")
        if not all_hits:
            all_hits = [e.event_id for e in timeline.entries][:3]
    confidence = min(0.4 + len(all_hits) * 0.1 + (0.2 if cross_host_hit else 0), 0.90)
    first, last = _min_max_ts(timeline, all_hits)
    return DetectedBehavior(
        behavior_name="lateral_movement",
        mitre_tactics=["TA0008"],
        confidence=round(confidence, 2),
        evidence=evidence,
        event_ids=all_hits,
        first_seen=first,
        last_seen=last,
    )


def _check_privilege_escalation(
    timeline: AttackTimeline,
    snapshots: list[dict[str, Any]],
) -> DetectedBehavior | None:
    privileged = any(
        e.username and (e.username.lower() in ("system", "nt authority\\system", "root"))
        for e in timeline.entries
    )
    high_sev_procs = [
        e.event_id for e in timeline.entries
        if e.severity >= 7 and e.category == "process"
    ]
    if not privileged and not high_sev_procs:
        return None
    evidence = []
    all_hits: list[str] = []
    if privileged:
        evidence.append("Privileged account (SYSTEM/root) observed in process chain")
        all_hits = [e.event_id for e in timeline.entries
                    if e.username and e.username.lower() in ("system", "nt authority\\system", "root")]
    if high_sev_procs:
        evidence.append(f"{len(high_sev_procs)} high-severity process events detected")
        all_hits.extend(high_sev_procs)
    all_hits = list(dict.fromkeys(all_hits))
    confidence = min(0.35 + len(all_hits) * 0.1, 0.85)
    first, last = _min_max_ts(timeline, all_hits)
    return DetectedBehavior(
        behavior_name="privilege_escalation",
        mitre_tactics=["TA0004"],
        confidence=round(confidence, 2),
        evidence=evidence,
        event_ids=all_hits,
        first_seen=first,
        last_seen=last,
    )


def _check_command_and_control(
    timeline: AttackTimeline,
    snapshots: list[dict[str, Any]],
) -> DetectedBehavior | None:
    # C2 indicators: unusual outbound ports, high connection frequency, beaconing
    network_events = [e for e in timeline.entries if e.category == "network"]
    if len(network_events) < 3:
        return None
    # Beaconing: many network events from same process in short window
    proc_counts: dict[str, int] = {}
    for e in network_events:
        if e.process:
            proc_counts[e.process] = proc_counts.get(e.process, 0) + 1
    beaconing = any(count >= 3 for count in proc_counts.values())
    # Check for unusual ports in snapshots
    unusual_ports: list[str] = []
    for snap in snapshots:
        net = snap.get("network") or {}
        if isinstance(net, dict):
            port = net.get("destination_port") or net.get("dst_port") or 0
            try:
                p = int(port)
                if p not in (80, 443, 53, 22, 25, 587, 3389) and p > 1024:
                    unusual_ports.append(str(p))
            except (TypeError, ValueError):
                pass
    if not beaconing and not unusual_ports:
        return None
    evidence = []
    if beaconing:
        evidence.append(f"Potential beaconing pattern detected ({len(network_events)} network events)")
    if unusual_ports:
        evidence.append(f"Unusual destination ports: {', '.join(set(unusual_ports[:5]))}")
    all_hits = [e.event_id for e in network_events]
    confidence = min(0.3 + (0.2 if beaconing else 0) + len(unusual_ports) * 0.05, 0.80)
    first, last = _min_max_ts(timeline, all_hits)
    return DetectedBehavior(
        behavior_name="command_and_control",
        mitre_tactics=["TA0011"],
        confidence=round(confidence, 2),
        evidence=evidence,
        event_ids=all_hits,
        first_seen=first,
        last_seen=last,
    )


def _check_collection(
    timeline: AttackTimeline,
    snapshots: list[dict[str, Any]],
) -> DetectedBehavior | None:
    import os
    proc_hits = [
        e.event_id for e in timeline.entries
        if e.process and os.path.basename(e.process).lower() in _PROC_COLLECTION
    ]
    cmd_hits = _event_ids_for_cmd(timeline, snapshots, _CMD_COLLECTION)
    all_hits = list(dict.fromkeys(proc_hits + cmd_hits))
    if not all_hits:
        return None
    evidence = [f"Data collection/staging tools detected ({len(all_hits)} events)"]
    confidence = min(0.4 + len(all_hits) * 0.1, 0.85)
    first, last = _min_max_ts(timeline, all_hits)
    return DetectedBehavior(
        behavior_name="collection",
        mitre_tactics=["TA0009"],
        confidence=round(confidence, 2),
        evidence=evidence,
        event_ids=all_hits,
        first_seen=first,
        last_seen=last,
    )


def _check_exfiltration(
    timeline: AttackTimeline,
    snapshots: list[dict[str, Any]],
) -> DetectedBehavior | None:
    import os
    proc_hits = [
        e.event_id for e in timeline.entries
        if e.process and os.path.basename(e.process).lower() in _PROC_EXFILTRATION
    ]
    cmd_hits = _event_ids_for_cmd(timeline, snapshots, _CMD_EXFIL)
    all_hits = list(dict.fromkeys(proc_hits + cmd_hits))
    if not all_hits:
        return None
    evidence = [f"Potential exfiltration tool/command detected ({len(all_hits)} events)"]
    confidence = min(0.45 + len(all_hits) * 0.1, 0.88)
    first, last = _min_max_ts(timeline, all_hits)
    return DetectedBehavior(
        behavior_name="exfiltration",
        mitre_tactics=["TA0010"],
        confidence=round(confidence, 2),
        evidence=evidence,
        event_ids=all_hits,
        first_seen=first,
        last_seen=last,
    )


def _check_impact(
    timeline: AttackTimeline,
    snapshots: list[dict[str, Any]],
) -> DetectedBehavior | None:
    import os
    proc_hits = [
        e.event_id for e in timeline.entries
        if e.process and os.path.basename(e.process).lower() in _PROC_IMPACT
    ]
    if not proc_hits:
        return None
    evidence = [f"Impact tools detected ({len(proc_hits)} events)"]
    confidence = min(0.55 + len(proc_hits) * 0.1, 0.92)
    first, last = _min_max_ts(timeline, proc_hits)
    return DetectedBehavior(
        behavior_name="impact",
        mitre_tactics=["TA0040"],
        confidence=round(confidence, 2),
        evidence=evidence,
        event_ids=proc_hits,
        first_seen=first,
        last_seen=last,
    )


# ─── Registry ─────────────────────────────────────────────────────────────────

_BEHAVIOR_CHECKERS: list[BehaviorChecker] = [
    _check_credential_access,
    _check_discovery,
    _check_execution,
    _check_persistence,
    _check_defense_evasion,
    _check_lateral_movement,
    _check_privilege_escalation,
    _check_command_and_control,
    _check_collection,
    _check_exfiltration,
    _check_impact,
]


# ─── Public API ───────────────────────────────────────────────────────────────

def analyze_behaviors(
    investigation_id: str,
    timeline: AttackTimeline,
    snapshots: list[dict[str, Any]],
) -> BehaviorAnalysis:
    """Run all behavior checkers and aggregate results."""
    detected: list[DetectedBehavior] = []
    for checker in _BEHAVIOR_CHECKERS:
        try:
            result = checker(timeline, snapshots)
        except Exception:
            continue
        if result is not None:
            detected.append(result)

    mitre_tactics: list[str] = list(
        dict.fromkeys(tactic for b in detected for tactic in b.mitre_tactics)
    )
    max_confidence = max((b.confidence for b in detected), default=0.0)

    return BehaviorAnalysis(
        investigation_id=investigation_id,
        detected_behaviors=detected,
        mitre_tactics=mitre_tactics,
        max_confidence=max_confidence,
        behavior_count=len(detected),
    )

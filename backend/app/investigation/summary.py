from __future__ import annotations

"""
Deterministic, template-driven investigation summary generator.
NO LLM calls. Pure rule/template-based logic.
"""

import datetime

from app.investigation.schemas import (
    MITRE_TACTIC_NAMES,
    AttackTimeline,
    BehaviorAnalysis,
    InvestigationContext,
    InvestigationScore,
    InvestigationSummary,
)

# ─── Containment recommendations by behavior ──────────────────────────────────

_CONTAINMENT_BY_BEHAVIOR: dict[str, list[str]] = {
    "credential_access": [
        "Immediately reset passwords for all involved accounts.",
        "Revoke and re-issue Kerberos tickets (klist purge) for affected hosts.",
        "Enable MFA on all privileged accounts if not already active.",
    ],
    "lateral_movement": [
        "Isolate affected hosts from the network at the switch/firewall level.",
        "Block SMB (445) and WMI (135) laterally between workstations.",
        "Disable or limit remote admin shares (C$, ADMIN$) on endpoints.",
    ],
    "persistence": [
        "Audit and remove all unauthorized scheduled tasks and startup entries.",
        "Review registry Run/RunOnce keys for unauthorized entries.",
        "Scan for newly installed services on affected hosts.",
    ],
    "defense_evasion": [
        "Re-enable Windows Event Logging if it was cleared or disabled.",
        "Restore Shadow Copies if VSS deletion was attempted.",
        "Enable tamper protection on endpoint security tools.",
    ],
    "command_and_control": [
        "Block all identified C2 IP addresses and domains at the perimeter.",
        "Capture and analyze network traffic from affected hosts.",
        "Enable DNS sinkholing for identified C2 domains.",
    ],
    "privilege_escalation": [
        "Audit SYSTEM-level process creations on affected hosts.",
        "Review and restrict local admin rights.",
        "Apply missing privilege escalation patches.",
    ],
    "exfiltration": [
        "Identify and block exfiltration destination endpoints.",
        "Classify and assess what data may have been exfiltrated.",
        "Enable DLP monitoring on affected endpoints.",
    ],
    "ransomware": [
        "IMMEDIATELY isolate all affected systems from the network.",
        "Do NOT restart affected systems — memory forensics may be possible.",
        "Initiate backup restoration from the last known-good snapshot.",
        "Engage incident response team and consider law enforcement notification.",
        "Preserve all available shadow copies before any recovery attempt.",
    ],
    "impact": [
        "Isolate affected systems immediately.",
        "Initiate backup restoration procedures.",
        "Engage incident response team for forensic analysis.",
    ],
}

# ─── Recommended actions by MITRE tactic ─────────────────────────────────────
# Each value is a LIST of action strings (not a single string).

_ACTIONS_BY_TACTIC: dict[str, list[str]] = {
    "TA0001": [
        "Investigate the initial access vector and patch exposed vulnerabilities.",
        "Review perimeter firewall and VPN access logs for the period.",
    ],
    "TA0002": [
        "Review script interpreter usage logs and restrict PowerShell execution policy.",
        "Enable script block logging (PowerShell) and AMSI if not already active.",
    ],
    "TA0003": [
        "Audit persistence mechanisms and remove unauthorized entries.",
        "Review scheduled tasks, services, and startup registry keys on affected hosts.",
    ],
    "TA0004": [
        "Review privilege assignments and apply least-privilege principle.",
        "Audit local administrator group membership on affected hosts.",
    ],
    "TA0005": [
        "Confirm event logging is intact; restore if tampered.",
        "Review defense evasion techniques and update detection rules.",
    ],
    "TA0006": [
        "Reset compromised credentials and enable privileged account MFA.",
        "Run a full credential audit and force rotation for all domain accounts.",
    ],
    "TA0007": [
        "Identify reconnaissance scope and assess what was enumerated.",
        "Review Active Directory query logs for unusual LDAP requests.",
    ],
    "TA0008": [
        "Contain lateral movement by isolating affected hosts.",
        "Review SMB, RDP, and WMI connection logs across the environment.",
    ],
    "TA0009": [
        "Identify staged data and assess impact.",
        "Locate and remove any data archives created on compromised systems.",
    ],
    "TA0010": [
        "Identify and block exfiltration channels.",
        "Review proxy and DNS logs for unusual outbound data transfers.",
    ],
    "TA0011": [
        "Block identified C2 infrastructure at the perimeter and DNS level.",
        "Perform full memory dump on beaconing hosts for IOC extraction.",
    ],
    "TA0040": [
        "Initiate disaster recovery procedures as appropriate.",
        "Assess scope of data destruction or encryption before recovery.",
    ],
}

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _human_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)} second(s)"
    if seconds < 3600:
        return f"{int(seconds / 60)} minute(s)"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hour(s)"
    return f"{seconds / 86400:.1f} day(s)"


def _format_ts(ts: float) -> str:
    if not ts:
        return "unknown"
    try:
        return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        return "unknown"


def _entity_summary(context: InvestigationContext) -> str:
    parts: list[str] = []
    if context.involved_users:
        parts.append(f"{len(context.involved_users)} user(s)")
    if context.involved_hosts:
        parts.append(f"{len(context.involved_hosts)} host(s)")
    if context.involved_ips:
        parts.append(f"{len(context.involved_ips)} external IP(s)")
    return ", ".join(parts) if parts else "multiple entities"


def _behavior_names(behaviors: BehaviorAnalysis) -> str:
    names = [b.behavior_name.replace("_", " ") for b in behaviors.detected_behaviors]
    if not names:
        return "no specific behaviors"
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + " and " + names[-1]


def _tactic_names(tactics: list[str]) -> str:
    names = [MITRE_TACTIC_NAMES.get(t, t) for t in tactics]
    return ", ".join(names) if names else "no specific MITRE tactics"


# ─── Summary sections ─────────────────────────────────────────────────────────


def _build_executive_summary(
    timeline: AttackTimeline,
    behaviors: BehaviorAnalysis,
    context: InvestigationContext,
    score: InvestigationScore,
) -> str:
    entity_sum = _entity_summary(context)
    duration = _human_duration(timeline.duration_seconds)
    first = _format_ts(timeline.first_seen)
    last = _format_ts(timeline.last_seen)

    # Check for ransomware — always escalate to critical language
    behavior_names = {b.behavior_name for b in behaviors.detected_behaviors}
    if "ransomware" in behavior_names:
        return (
            f"CRITICAL: Ransomware activity has been detected involving {entity_sum}. "
            f"Indicators include shadow deletion, backup removal, and/or high-volume "
            f"file operations. Immediate isolation and incident response engagement are required. "
            f"Activity first observed at {first}."
        )

    if score.confidence == "high":
        return (
            f"A high-confidence security incident has been detected involving {entity_sum}. "
            f"The investigation identified {behaviors.behavior_count} suspicious behavior(s) "
            f"mapped to {len(behaviors.mitre_tactics)} MITRE ATT&CK tactic(s) "
            f"({_tactic_names(behaviors.mitre_tactics)}). "
            f"Activity was first observed at {first} and remained active for {duration} "
            f"(last seen: {last}). Immediate containment is recommended."
        )
    if score.confidence == "medium":
        return (
            f"A medium-confidence security investigation is active involving {entity_sum}. "
            f"Detected behaviors include {_behavior_names(behaviors)}. "
            f"Activity spans {timeline.distinct_hosts} host(s) over {duration} "
            f"(first seen: {first}). Further analysis is recommended."
        )
    return (
        f"A low-confidence event cluster has been detected involving {entity_sum}. "
        f"Events showed patterns of {_behavior_names(behaviors)} "
        f"over a period of {duration}. Analyst review is advised."
    )


def _build_technical_summary(
    timeline: AttackTimeline,
    behaviors: BehaviorAnalysis,
    context: InvestigationContext,
    score: InvestigationScore,
) -> str:
    lines: list[str] = [
        f"Investigation timeline: {timeline.total_events} events across "
        f"{timeline.distinct_hosts} host(s), {timeline.distinct_users} user(s), "
        f"{timeline.distinct_ips} IP(s), {timeline.distinct_processes} distinct process(es).",
    ]
    if behaviors.detected_behaviors:
        behavior_detail = "; ".join(
            f"{b.behavior_name} (confidence={b.confidence:.0%}, "
            f"events={len(b.event_ids)}, "
            f"techniques={','.join(b.mitre_techniques[:3])})"
            for b in behaviors.detected_behaviors
        )
        lines.append(f"Behaviors detected ({behaviors.behavior_count}): {behavior_detail}.")
    if context.suspicious_processes:
        lines.append(f"Suspicious processes: {', '.join(context.suspicious_processes[:10])}.")
    if context.suspicious_commands:
        lines.append(
            f"Suspicious commands observed: {len(context.suspicious_commands)} unique command(s)."
        )
    if context.suspicious_domains:
        lines.append(f"Suspicious domains: {', '.join(context.suspicious_domains[:5])}.")
    lines.append(
        f"Threat score: {score.threat_score}/100 "
        f"(TP probability: {score.tp_probability:.0%}, "
        f"FP probability: {score.fp_probability:.0%})."
    )
    return " ".join(lines)


def _build_attack_progression(
    timeline: AttackTimeline,
    behaviors: BehaviorAnalysis,
) -> list[str]:
    if not timeline.entries:
        return ["No events recorded."]

    progression: list[str] = []
    entries = timeline.entries
    total = len(entries)

    # Phase 1: Initial activity
    first_entries = entries[: min(3, total)]
    hosts_in_first = list({e.hostname for e in first_entries if e.hostname})
    progression.append(
        f"[Initial Activity] First event at {_format_ts(entries[0].timestamp)} "
        f"on host(s): {', '.join(hosts_in_first) or 'unknown'}. "
        f"Categories: {', '.join({e.category for e in first_entries})}."
    )

    # Phase 2: Mid-stage behavior
    if behaviors.detected_behaviors:
        for b in behaviors.detected_behaviors[:5]:
            techniques_str = f" [{', '.join(b.mitre_techniques[:3])}]" if b.mitre_techniques else ""
            progression.append(
                f"[{b.behavior_name.replace('_', ' ').title()}] "
                f"Detected from {_format_ts(b.first_seen)} to {_format_ts(b.last_seen)} "
                f"({len(b.event_ids)} event(s), confidence={b.confidence:.0%}). "
                f"MITRE: {', '.join(b.mitre_tactics)}{techniques_str}."
            )

    # Phase 3: Spread / multi-host
    if timeline.distinct_hosts >= 2:
        progression.append(
            f"[Lateral Spread] Activity observed across {timeline.distinct_hosts} distinct host(s), "
            f"involving {timeline.distinct_users} user account(s)."
        )

    # Phase 4: Most recent activity
    if total > 3:
        last_entry = entries[-1]
        progression.append(
            f"[Recent Activity] Last event at {_format_ts(last_entry.timestamp)} "
            f"on host '{last_entry.hostname or 'unknown'}' "
            f"(category: {last_entry.category})."
        )

    return progression


def _build_root_cause(
    behaviors: BehaviorAnalysis,
    context: InvestigationContext,
    timeline: AttackTimeline,
) -> str:
    behavior_names = {b.behavior_name for b in behaviors.detected_behaviors}

    if "ransomware" in behavior_names:
        return (
            "Ransomware activity detected. The threat actor likely gained initial access "
            "via phishing or exposed credentials, then deployed ransomware to encrypt files "
            "and deleted backups/shadow copies to prevent recovery."
        )
    if "credential_access" in behavior_names and "lateral_movement" in behavior_names:
        return (
            "Suspected compromised credentials used to perform lateral movement. "
            "The threat actor likely obtained initial access via phishing or brute-force, "
            "escalated privileges, and moved laterally within the environment."
        )
    if "execution" in behavior_names and "persistence" in behavior_names:
        return (
            "Suspected malware execution followed by persistence installation. "
            "An attacker-controlled process established a foothold on the affected host."
        )
    if "command_and_control" in behavior_names:
        return (
            "Suspected command-and-control (C2) activity indicating a compromised host. "
            "The affected endpoint is likely communicating with attacker infrastructure."
        )
    if "discovery" in behavior_names:
        return (
            "Suspected reconnaissance activity. The observed commands suggest "
            "an actor was mapping the internal environment."
        )
    if context.involved_hosts and len(context.involved_hosts) > 1:
        return (
            f"Multi-host activity detected across {len(context.involved_hosts)} host(s). "
            "Root cause requires further forensic investigation."
        )
    return "Root cause could not be automatically determined. Manual investigation required."


def _build_recommended_actions(
    behaviors: BehaviorAnalysis,
    score: InvestigationScore,
) -> list[str]:
    actions: list[str] = []
    seen: set[str] = set()

    def _add(action: str) -> None:
        if action not in seen:
            seen.add(action)
            actions.append(action)

    # Always: document and preserve evidence
    _add("Document and preserve all relevant logs before any remediation steps.")
    _add("Assign this investigation to a Tier 2 analyst for immediate review.")

    for b in behaviors.detected_behaviors:
        # Look up tactic-specific actions (values are list[str] — iterate correctly)
        tactic = b.mitre_tactics[0] if b.mitre_tactics else ""
        for action in _ACTIONS_BY_TACTIC.get(tactic, []):
            _add(action)

    if score.threat_score >= 70:
        _add("Escalate to senior incident responders immediately.")
        _add("Consider triggering full incident response playbook.")
    elif score.threat_score >= 40:
        _add("Escalate to Tier 2 SOC analyst for review within 4 hours.")

    return actions


def _build_containment(behaviors: BehaviorAnalysis, score: InvestigationScore) -> list[str]:
    recommendations: list[str] = []
    seen: set[str] = set()

    for b in behaviors.detected_behaviors:
        for rec in _CONTAINMENT_BY_BEHAVIOR.get(b.behavior_name, []):
            if rec not in seen:
                seen.add(rec)
                recommendations.append(rec)

    if not recommendations:
        recommendations.append("Monitor affected hosts for further suspicious activity.")
    return recommendations


def _build_analyst_notes(
    timeline: AttackTimeline,
    behaviors: BehaviorAnalysis,
    score: InvestigationScore,
) -> list[str]:
    notes: list[str] = []
    if score.fp_probability >= 0.6:
        notes.append(
            f"FP probability is {score.fp_probability:.0%}. "
            "Consider reviewing alert tuning for involved detection rules."
        )
    if timeline.duration_seconds > 3600:
        notes.append(
            f"Activity spans {_human_duration(timeline.duration_seconds)}. "
            "Long-duration investigations may indicate a dwell-time breach."
        )
    if behaviors.behavior_count == 0:
        notes.append(
            "No specific behaviors were identified. This may indicate a novel technique "
            "or require manual behavioral analysis."
        )
    # Highlight MITRE technique coverage
    all_techniques: list[str] = list(
        dict.fromkeys(t for b in behaviors.detected_behaviors for t in b.mitre_techniques)
    )
    if all_techniques:
        notes.append(f"MITRE ATT&CK techniques mapped: {', '.join(all_techniques[:10])}.")
    return notes


# ─── Public API ───────────────────────────────────────────────────────────────


def generate_summary(
    investigation_id: str,
    timeline: AttackTimeline,
    behaviors: BehaviorAnalysis,
    context: InvestigationContext,
    score: InvestigationScore,
) -> InvestigationSummary:
    impacted = list(dict.fromkeys(context.involved_hosts[:10] + context.involved_users[:5]))

    return InvestigationSummary(
        investigation_id=investigation_id,
        executive_summary=_build_executive_summary(timeline, behaviors, context, score),
        technical_summary=_build_technical_summary(timeline, behaviors, context, score),
        attack_progression=_build_attack_progression(timeline, behaviors),
        suspected_root_cause=_build_root_cause(behaviors, context, timeline),
        impacted_assets=impacted,
        recommended_actions=_build_recommended_actions(behaviors, score),
        analyst_notes=_build_analyst_notes(timeline, behaviors, score),
        containment_recommendations=_build_containment(behaviors, score),
    )

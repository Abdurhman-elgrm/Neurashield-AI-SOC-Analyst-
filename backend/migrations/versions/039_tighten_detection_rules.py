"""039_tighten_detection_rules

Revision ID: 039
Revises: 038
Create Date: 2026-06-30

Tighten 11 high-false-positive detection rules for all existing tenants.

Only system-seeded rules (created_by_id IS NULL) are updated so that
tenant-customised rules are left untouched.

Changes per rule:
  1. "Linux sudo Privilege Escalation"
       → "Linux sudo - Shell or Interpreter Privilege Escalation"
       Adds command-pattern filter; no longer fires on every sudo call.

  2. "Account Lockout Detected (Event 4740)"
       → "Account Lockout Storm - Password Spray Indicator (Event 4740)"
       Changed from pattern (fires on 1 lockout) to threshold (3+ in 10 min).

  3. "Kerberoasting Indicator - Kerberos Pre-Auth Failure (Event 4771)"
       → "Kerberoasting / AS-REP Roast - Pre-Auth Failure Burst (Event 4771)"
       Changed from pattern (fires on 1 failure) to threshold (10+ in 5 min).
       Severity raised medium → high.

  4. "Scheduled Task Created (Event 4698)"
       → "Scheduled Task Created via Suspicious Binary or Location (Event 4698)"
       Now requires suspicious path / LOLBin / encoded command.
       Severity raised medium → high.

  5. "New Service Installed (Event 7045)"
       → "New Service Installed from Suspicious Path or Binary (Event 7045)"
       Now requires suspicious path or LOLBin binary.

  6. "Kernel Driver Loaded - Sysmon Event 6"
       → "Kernel Driver Loaded - Unsigned or Suspicious Driver (Sysmon Event 6)"
       Now requires unsigned driver or suspicious load path.

  7. "Remote Interactive Logon (RDP / Type 10) Detected"
       → "RDP Logon from External Network (Type 10)"
       Now excludes RFC-1918 source IPs; suppression extended 600 → 3600 s.
       Added Initial Access tactic.

  8. "Network Logon to Administrative Share (Type 3)"
       → "Lateral Movement - Rapid Network Logon Spread to Multiple Hosts (Type 3)"
       Changed from pattern (fires on every type-3 logon) to threshold
       (4+ distinct hosts per user in 5 min).  Severity raised medium → high.

  9. "Archive / Compression Tool Execution Before Exfiltration"
       → "Archive Tool - Password-Protected Staging of User Data"
       Now requires password flag + user data path, or execution from temp path.
       Severity raised low → medium.

 10. "Discovery - Active Directory Enumeration Tools"
       → "Discovery - Active Directory Attack Tool Detected"
       Removed standard RSAT cmdlets (Get-ADUser, Get-ADComputer, Get-ADGroup);
       added PowerView-specific attack cmdlets.

 11. "C2 - PowerShell Direct TCP Socket Connection"
       StreamReader condition tightened: now requires co-occurrence with IP address.

 12. "LSASS Access - Credential Dump Attempt"
       Removed the overly-broad regex `\\blsass\\.exe.*\\s+-` (matched any process
       referencing lsass.exe with any hyphenated flag — fired constantly on AV/EDR
       agents and monitoring scripts).  Condition 2 (comsvcs MiniDump) now requires
       rundll32.exe as the calling process.  Added exclusion list for known diagnostic
       binaries (WerFault, taskmgr, procexp, MsMpEng, lsaiso).  Added dedicated
       dump-tool names (nanodump, pypykatz).  Suppression extended 300 → 3600 s.
"""
from __future__ import annotations

import json

import sqlalchemy as sa
from alembic import op


revision = "039"
down_revision = "038"
branch_labels = None
depends_on = None


# ─── New rule definitions (keyed by OLD name for matching) ───────────────────

_RULE_UPDATES: list[dict] = [
    {
        "old_name": "Linux sudo Privilege Escalation",
        "new_name": "Linux sudo - Shell or Interpreter Privilege Escalation",
        "rule_type": "pattern",
        "severity": "medium",
        "suppression_window_secs": 300,
        "description": (
            "sudo executed a shell binary, scripting interpreter, or dual-use network "
            "tool as root.  Generic administrative commands (apt, systemctl, service, "
            "journalctl, etc.) are NOT matched — they account for nearly all false "
            "positives from this event class and carry no attack signal.  "
            "Fires only when the sudo COMMAND field targets a shell (/bash, /sh, /zsh), "
            "a scripting runtime (python, perl, ruby, node), a network utility (nc, "
            "curl, wget, socat), sensitive file editing (vi on passwd/shadow/sudoers), "
            "or kernel module manipulation (insmod, modprobe)."
        ),
        "conditions": [
            {"field": "category", "op": "eq", "value": "auth"},
            {"field": "raw.program", "op": "eq", "value": "sudo"},
            {"field": "raw.outcome", "op": "eq", "value": "success"},
            {
                "op": "any_of",
                "conditions": [
                    {"field": "raw.message", "op": "regex",
                     "value": r"COMMAND=\S*(/bash|/sh\b|/dash|/zsh|/ksh|/fish)\b"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"COMMAND=\S*(python[23]?|ruby|perl|node)\b"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"COMMAND=\S*(nc\b|ncat|netcat|curl|wget|socat)\b"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"COMMAND=\S*(vim|nano|vi|emacs)\b.*(passwd|shadow|sudoers|crontab)"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"COMMAND=\S*(insmod|rmmod|modprobe)\b"},
                ],
            },
        ],
    },
    {
        "old_name": "Account Lockout Detected (Event 4740)",
        "new_name": "Account Lockout Storm - Password Spray Indicator (Event 4740)",
        "rule_type": "threshold",
        "severity": "high",
        "suppression_window_secs": 600,
        "description": (
            "Three or more distinct account lockouts occur on the same host within "
            "10 minutes, indicating automated password spraying or a credential "
            "stuffing campaign.  Single lockout events — the most common false "
            "positive, triggered when a user simply forgets their password — are "
            "excluded entirely by the threshold requirement."
        ),
        "conditions": {
            "field": "user.name",
            "group_by": "hostname",
            "threshold": 3,
            "window_secs": 600,
            "filters": [
                {"field": "raw.windows_event_id", "op": "eq", "value": "4740"},
            ],
        },
    },
    {
        "old_name": "Kerberoasting Indicator - Kerberos Pre-Auth Failure (Event 4771)",
        "new_name": "Kerberoasting / AS-REP Roast - Pre-Auth Failure Burst (Event 4771)",
        "rule_type": "threshold",
        "severity": "high",
        "suppression_window_secs": 300,
        "description": (
            "Ten or more Kerberos pre-authentication failures on the same host within "
            "5 minutes indicate AS-REP roasting, Kerberoasting, or password spraying "
            "against Active Directory accounts.  Single failures (mistyped password, "
            "expired certificate, clock skew) are excluded — they are the dominant "
            "false-positive source for this event class."
        ),
        "conditions": {
            "field": "hostname",
            "group_by": "hostname",
            "threshold": 10,
            "window_secs": 300,
            "filters": [
                {"field": "raw.windows_event_id", "op": "eq", "value": "4771"},
            ],
        },
    },
    {
        "old_name": "Scheduled Task Created (Event 4698)",
        "new_name": "Scheduled Task Created via Suspicious Binary or Location (Event 4698)",
        "rule_type": "pattern",
        "severity": "high",
        "suppression_window_secs": 3600,
        "description": (
            "A new scheduled task was registered whose action runs from a user-writable "
            "or suspicious location (Temp, AppData, Public, Downloads), invokes a LOLBin "
            "(cmd.exe, powershell.exe, wscript.exe, mshta.exe) with execution flags, "
            "contains a base64-encoded command, or targets a UNC network path.  "
            "Broad 'any new task' rules are a major false-positive source — Windows "
            "Update, driver packages, and virtually every enterprise software installer "
            "creates scheduled tasks.  This rule requires at least one attacker-specific "
            "characteristic before firing."
        ),
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4698"},
            {
                "op": "any_of",
                "conditions": [
                    {"field": "raw.message", "op": "regex",
                     "value": r"\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\Downloads\\"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe)\s+(/c\s|/k\s|-enc\s|-Command\s)"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"-[Ee]nc[a-z]*\s+[A-Za-z0-9+/]{20,}"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"<Command>\s*\\\\[^\\]"},
                ],
            },
        ],
    },
    {
        "old_name": "New Service Installed (Event 7045)",
        "new_name": "New Service Installed from Suspicious Path or Binary (Event 7045)",
        "rule_type": "pattern",
        "severity": "high",
        "suppression_window_secs": 600,
        "description": (
            "A new Windows service was installed with a binary path in a user-writable "
            "or non-standard location, or the service binary is a shell / LOLBin.  "
            "Services from System32, Program Files, and vendor-signed paths are excluded."
        ),
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "7045"},
            {
                "op": "any_of",
                "conditions": [
                    {"field": "raw.message", "op": "regex",
                     "value": r"Service File Name:.*\\Temp\\|Service File Name:.*\\AppData\\"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"Service File Name:.*\\Users\\Public\\|Service File Name:.*\\Downloads\\"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"Service File Name:\s+\\\\[^\\]"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"Service File Name:.*(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe)"},
                ],
            },
        ],
    },
    {
        "old_name": "Kernel Driver Loaded - Sysmon Event 6",
        "new_name": "Kernel Driver Loaded - Unsigned or Suspicious Driver (Sysmon Event 6)",
        "rule_type": "pattern",
        "severity": "high",
        "suppression_window_secs": 3600,
        "description": (
            "A kernel driver was loaded that is unsigned, has an invalid/unavailable "
            "signature, or was loaded from outside the standard Windows driver "
            "directories.  Thousands of legitimate signed drivers loaded at boot "
            "are excluded via the signature filter."
        ),
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "6"},
            {
                "op": "any_of",
                "conditions": [
                    {"field": "raw.message", "op": "contains", "value": "Signed: false"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"SignatureStatus:\s+(Invalid|Unavailable|Error|Expired)"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"ImageLoaded:.*\\Temp\\|ImageLoaded:.*\\AppData\\|ImageLoaded:.*\\Users\\Public\\"},
                    {"field": "raw.message", "op": "regex",
                     "value": r"ImageLoaded:\s+\\\\[^\\]"},
                ],
            },
        ],
    },
    {
        "old_name": "Remote Interactive Logon (RDP / Type 10) Detected",
        "new_name": "RDP Logon from External Network (Type 10)",
        "rule_type": "pattern",
        "severity": "medium",
        "suppression_window_secs": 3600,
        "description": (
            "A successful RDP logon (type 10) originated from an IP outside RFC-1918 "
            "private ranges, indicating a publicly routed connection.  Internal admin "
            "RDP sessions are excluded by filtering out all private address space."
        ),
        "mitre_tactics": ["Lateral Movement", "Initial Access"],
        "mitre_techniques": ["T1021.001", "T1133"],
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4624"},
            {"field": "raw.LogonType", "op": "eq", "value": "10"},
            {"field": "network.src_ip", "op": "exists", "value": None},
            {
                "op": "none_of",
                "conditions": [
                    {"field": "network.src_ip", "op": "startswith", "value": "10."},
                    {"field": "network.src_ip", "op": "startswith", "value": "192.168."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.16."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.17."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.18."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.19."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.20."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.21."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.22."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.23."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.24."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.25."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.26."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.27."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.28."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.29."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.30."},
                    {"field": "network.src_ip", "op": "startswith", "value": "172.31."},
                    {"field": "network.src_ip", "op": "startswith", "value": "127."},
                    {"field": "network.src_ip", "op": "startswith", "value": "169.254."},
                ],
            },
        ],
    },
    {
        "old_name": "Network Logon to Administrative Share (Type 3)",
        "new_name": "Lateral Movement - Rapid Network Logon Spread to Multiple Hosts (Type 3)",
        "rule_type": "threshold",
        "severity": "high",
        "suppression_window_secs": 600,
        "description": (
            "A single user authenticates via network logon (type 3) to four or more "
            "distinct hosts within 5 minutes — the behavioral fingerprint of automated "
            "lateral movement.  Single type-3 logons (normal domain auth) are excluded."
        ),
        "conditions": {
            "field": "hostname",
            "group_by": "user.name",
            "threshold": 4,
            "window_secs": 300,
            "filters": [
                {"field": "raw.windows_event_id", "op": "eq", "value": "4624"},
                {"field": "raw.LogonType", "op": "eq", "value": "3"},
            ],
        },
    },
    {
        "old_name": "Archive / Compression Tool Execution Before Exfiltration",
        "new_name": "Archive Tool - Password-Protected Staging of User Data",
        "rule_type": "pattern",
        "severity": "medium",
        "suppression_window_secs": 3600,
        "description": (
            "An archiving tool created a password-protected archive from user data "
            "directories, or was invoked from a temporary/staging path.  Plain "
            "compression of user data is intentionally excluded."
        ),
        "conditions": [
            {
                "field": "process.name",
                "op": "in",
                "value": ["7z.exe", "winrar.exe", "rar.exe", "7za.exe"],
            },
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.command_line", "op": "regex",
                                 "value": r"-p[^\s]|\s-p\s"},
                                {"field": "process.command_line", "op": "regex",
                                 "value": r"\\Users\\|\\Documents\\|\\Desktop\\|\\Downloads\\"},
                            ],
                        ],
                    },
                    {"field": "process.executable", "op": "regex",
                     "value": r"\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\"},
                ],
            },
        ],
    },
    {
        "old_name": "Discovery - Active Directory Enumeration Tools",
        "new_name": "Discovery - Active Directory Attack Tool Detected",
        "rule_type": "pattern",
        "severity": "high",
        "suppression_window_secs": 600,
        "description": (
            "Known AD attack tool detected — BloodHound, SharpHound, ADFind, or "
            "PowerView offensive cmdlets.  Standard RSAT cmdlets (Get-ADUser, "
            "Get-ADComputer, Get-ADGroup) are excluded — they are built-in admin "
            "tools with no inherent attack signal."
        ),
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of",
                        "conditions": [
                            {"field": "process.executable", "op": "contains", "value": "BloodHound"},
                            {"field": "process.executable", "op": "contains", "value": "SharpHound"},
                            {"field": "process.executable", "op": "contains", "value": "adfind"},
                            {"field": "process.command_line", "op": "contains", "value": "BloodHound"},
                            {"field": "process.command_line", "op": "contains", "value": "SharpHound"},
                            {"field": "process.command_line", "op": "contains", "value": "Invoke-ACLScanner"},
                            {"field": "process.command_line", "op": "contains", "value": "Find-LocalAdminAccess"},
                            {"field": "process.command_line", "op": "contains", "value": "Invoke-UserHunter"},
                            {"field": "process.command_line", "op": "contains", "value": "Get-DomainTrust"},
                            {"field": "process.command_line", "op": "contains", "value": "Get-NetLocalGroupMember"},
                            {"field": "process.command_line", "op": "contains", "value": "Invoke-ShareFinder"},
                        ],
                    },
                    {
                        "op": "any_of",
                        "conditions": [
                            {"field": "raw.message", "op": "contains", "value": "BloodHound"},
                            {"field": "raw.message", "op": "contains", "value": "SharpHound"},
                            {"field": "raw.message", "op": "contains", "value": "adfind.exe"},
                        ],
                    },
                ],
            },
        ],
    },
    {
        "old_name": "LSASS Access - Credential Dump Attempt",
        "new_name": "LSASS Access - Credential Dump Attempt",
        "rule_type": "pattern",
        "severity": "critical",
        "suppression_window_secs": 3600,
        "description": (
            "Detects high-confidence LSASS credential dump techniques: procdump/procdump64 "
            "targeting lsass, rundll32 comsvcs MiniDump (fileless dump), dump-specific "
            "flags alongside lsass (-ma, -dump), and dedicated dump utilities (nanodump, "
            "pypykatz).  Known diagnostic binaries (WerFault, taskmgr, procexp, MsMpEng, "
            "lsaiso) are excluded.  Suppression is 1 hour — credential dumps are one-shot "
            "events; repeated alerts within an hour are always a monitoring false positive."
        ),
        "conditions": [
            {
                "op": "none_of",
                "conditions": [
                    {
                        "field": "process.name",
                        "op": "in",
                        "value": [
                            "WerFault.exe", "werfault.exe", "taskmgr.exe",
                            "procexp.exe", "procexp64.exe",
                            "MsMpEng.exe", "msmpeng.exe",
                            "svchost.exe", "lsaiso.exe",
                        ],
                    },
                ],
            },
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.name", "op": "eq", "value": "procdump.exe"},
                                {"field": "process.command_line", "op": "contains", "value": "lsass"},
                            ],
                            [
                                {"field": "process.name", "op": "eq", "value": "procdump64.exe"},
                                {"field": "process.command_line", "op": "contains", "value": "lsass"},
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.name", "op": "in", "value": ["rundll32.exe", "rundll32"]},
                                {"field": "process.command_line", "op": "contains", "value": "comsvcs"},
                                {"field": "process.command_line", "op": "contains", "value": "MiniDump"},
                            ],
                        ],
                    },
                    {
                        "field": "process.command_line",
                        "op": "regex",
                        "value": r"lsass.*-ma\b|lsass.*-dump\b|lsass.*\.dmp\b",
                    },
                    {
                        "field": "process.name",
                        "op": "in",
                        "value": ["nanodump.exe", "nanodump", "pypykatz.exe", "pypykatz"],
                    },
                ],
            },
        ],
    },
    {
        "old_name": "C2 - PowerShell Direct TCP Socket Connection",
        "new_name": "C2 - PowerShell Direct TCP Socket Connection",
        "rule_type": "pattern",
        "severity": "high",
        "suppression_window_secs": 300,
        "description": (
            "PowerShell using raw socket primitives (TCPClient, Net.Sockets, "
            "NetworkStream) to establish a direct TCP channel — standard technique "
            "for pure-PowerShell C2 implants.  StreamReader alone is excluded unless "
            "accompanied by a hard-coded IP address in the same command."
        ),
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of",
                        "conditions": [
                            {"field": "process.command_line", "op": "contains", "value": "TCPClient"},
                            {"field": "process.command_line", "op": "contains", "value": "Net.Sockets"},
                            {"field": "process.command_line", "op": "contains", "value": "NetworkStream"},
                            {"field": "process.command_line", "op": "regex",
                             "value": r"StreamReader.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"},
                        ],
                    },
                    {
                        "op": "any_of",
                        "conditions": [
                            {"field": "raw.message", "op": "contains", "value": "TCPClient"},
                            {"field": "raw.message", "op": "contains", "value": "Net.Sockets"},
                            {"field": "raw.message", "op": "contains", "value": "NetworkStream"},
                        ],
                    },
                ],
            },
        ],
    },
]


def upgrade() -> None:
    conn = op.get_bind()

    for rule in _RULE_UPDATES:
        old_name = rule["old_name"]
        new_name = rule["new_name"]
        rule_type = rule["rule_type"]
        severity = rule["severity"]
        suppression = rule["suppression_window_secs"]
        description = rule["description"]
        conditions_json = json.dumps(rule["conditions"])

        # Build optional MITRE overrides
        mitre_tactics = rule.get("mitre_tactics")
        mitre_techniques = rule.get("mitre_techniques")

        if mitre_tactics and mitre_techniques:
            conn.execute(
                sa.text(
                    """
                    UPDATE detection_rules
                    SET name                   = :new_name,
                        description            = :description,
                        rule_type              = :rule_type,
                        severity               = :severity,
                        conditions             = :conditions::jsonb,
                        suppression_window_secs = :suppression,
                        mitre_tactics          = :mitre_tactics::jsonb,
                        mitre_techniques       = :mitre_techniques::jsonb,
                        updated_at             = NOW()
                    WHERE name             = :old_name
                      AND created_by_id IS NULL
                      AND deleted_at IS NULL
                    """
                ),
                {
                    "old_name": old_name,
                    "new_name": new_name,
                    "description": description,
                    "rule_type": rule_type,
                    "severity": severity,
                    "conditions": conditions_json,
                    "suppression": suppression,
                    "mitre_tactics": json.dumps(mitre_tactics),
                    "mitre_techniques": json.dumps(mitre_techniques),
                },
            )
        else:
            conn.execute(
                sa.text(
                    """
                    UPDATE detection_rules
                    SET name                   = :new_name,
                        description            = :description,
                        rule_type              = :rule_type,
                        severity               = :severity,
                        conditions             = :conditions::jsonb,
                        suppression_window_secs = :suppression,
                        updated_at             = NOW()
                    WHERE name             = :old_name
                      AND created_by_id IS NULL
                      AND deleted_at IS NULL
                    """
                ),
                {
                    "old_name": old_name,
                    "new_name": new_name,
                    "description": description,
                    "rule_type": rule_type,
                    "severity": severity,
                    "conditions": conditions_json,
                    "suppression": suppression,
                },
            )


def downgrade() -> None:
    # Rules are data migrations — downgrade is intentionally a no-op.
    # Reverting to noisier rules would re-introduce known false-positive sources.
    pass

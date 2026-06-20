"""
Built-in detection rule library.

Seeded into every new tenant on creation via seed_default_rules().
Covers the 50 most impactful MITRE ATT&CK techniques seen in real-world
breaches, tuned for minimum day-1 false-positive noise.

Field paths follow the NormalizedEvent schema used by evaluate_conditions()
and ThresholdEvaluator.  Pattern rules use list[dict] conditions;
threshold rules use a dict with field / group_by / threshold / window_secs / filters.
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection_rule import DetectionRule, RuleType, RuleSeverity

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Rule catalogue
# ─────────────────────────────────────────────────────────────────────────────

_DEFAULT_RULES: list[dict[str, Any]] = [

    # ═══════════════════════════════════════════════════════════════════════
    #  CREDENTIAL ACCESS
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Mimikatz - Credential Dumping Tool Detected",
        "description": (
            "Detects Mimikatz or compatible credential-dumping tools by process name. "
            "Mimikatz is involved in the majority of large-scale breaches and should "
            "never appear on production systems."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {"field": "process.name", "op": "contains", "value": "mimikatz"},
        ],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1003.001"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Mimikatz - sekurlsa or lsadump Module in Command Line",
        "description": (
            "Detects Mimikatz module names (sekurlsa, lsadump, kerberos) in process "
            "command lines. Attackers rename the binary but still use the same commands."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {"field": "process.command_line", "op": "regex",
             "value": r"sekurlsa|lsadump|kerberos::ptt|kerberos::golden"},
        ],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1003.001", "T1558.001"],
        "suppression_window_secs": 300,
    },
    {
        "name": "LSASS Access - Credential Dump Attempt",
        "description": (
            "Detects processes interacting with lsass.exe — the Windows Local Security "
            "Authority process that holds plaintext credentials in memory."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {"field": "process.command_line", "op": "contains", "value": "lsass"},
        ],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1003.001"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Legacy Password Dumping Tool Detected",
        "description": (
            "Detects known password extraction utilities: pwdump, fgdump, WCE, "
            "cachedump. These have no legitimate use in production environments."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "process.name", "op": "in",
             "value": ["pwdump", "pwdump6", "fgdump.exe", "wce.exe", "cachedump.exe"]},
        ],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1003"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Brute Force - Windows Failed Logon Threshold (Per Host)",
        "description": (
            "Fires when 5 or more Windows failed logon events (4625) occur on a single "
            "host within 5 minutes, suggesting automated password guessing."
        ),
        "rule_type": "threshold",
        "severity": "high",
        "conditions": {
            "field": "hostname",
            "group_by": "hostname",
            "threshold": 5,
            "window_secs": 300,
            "filters": [
                {"field": "category", "op": "eq", "value": "auth"},
                {"field": "raw.windows_event_id", "op": "eq", "value": "4625"},
            ],
        },
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.001"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Credential Stuffing - Multiple Distinct Usernames From Same Source",
        "description": (
            "Fires when 5 or more different usernames are targeted from the same "
            "source IP in 5 minutes.  Classic credential stuffing pattern."
        ),
        "rule_type": "threshold",
        "severity": "high",
        "conditions": {
            "field": "user.name",
            "group_by": "network.src_ip",
            "threshold": 5,
            "window_secs": 300,
            "filters": [
                {"field": "category", "op": "eq", "value": "auth"},
                {"field": "raw.windows_event_id", "op": "eq", "value": "4625"},
            ],
        },
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.004"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Account Lockout Detected (Event 4740)",
        "description": (
            "A Windows user account was locked out after repeated authentication "
            "failures.  Frequent lockouts indicate a brute force campaign."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4740"},
        ],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110"],
        "suppression_window_secs": 600,
    },
    {
        "name": "Kerberoasting Indicator - Kerberos Pre-Auth Failure (Event 4771)",
        "description": (
            "Kerberos pre-authentication failure (4771) can indicate Kerberoasting, "
            "AS-REP roasting, or password spraying against Active Directory accounts."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4771"},
        ],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1558.003"],
        "suppression_window_secs": 300,
    },
    {
        "name": "SSH Brute Force - Failed Password Threshold (Per Source IP)",
        "description": (
            "Fires when 10 or more SSH failed password attempts arrive from the same "
            "source IP within 2 minutes, indicating automated credential spraying."
        ),
        "rule_type": "threshold",
        "severity": "high",
        "conditions": {
            "field": "hostname",
            "group_by": "network.src_ip",
            "threshold": 10,
            "window_secs": 120,
            "filters": [
                {"field": "category", "op": "eq", "value": "auth"},
                {"field": "raw.program", "op": "eq", "value": "sshd"},
                {"field": "raw.outcome", "op": "eq", "value": "failure"},
            ],
        },
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.001"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Linux sudo Privilege Escalation",
        "description": (
            "A user executed a command as root via sudo.  Expected for administrators; "
            "review when triggered by service accounts or at unusual times."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "category", "op": "eq", "value": "auth"},
            {"field": "raw.program", "op": "eq", "value": "sudo"},
            {"field": "raw.outcome", "op": "eq", "value": "success"},
        ],
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1548.003"],
        "suppression_window_secs": 600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  DEFENSE EVASION
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Security Audit Log Cleared (Event 1102)",
        "description": (
            "The Windows Security event log was cleared.  This is almost always "
            "malicious — attackers clear logs to hide post-exploitation activity."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "1102"},
        ],
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1070.001"],
        "suppression_window_secs": 86400,
    },
    {
        "name": "Event Logging Service Stopped (Event 1100)",
        "description": (
            "The Windows Event Logging service was stopped.  Stopping this service "
            "blinds the SIEM before the attacker executes the main payload."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "1100"},
        ],
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.002"],
        "suppression_window_secs": 86400,
    },
    {
        "name": "Audit Policy Changed (Event 4719)",
        "description": (
            "System audit policy was modified.  Attackers disable specific audit "
            "categories (logon, process creation) before executing malicious activity."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4719"},
        ],
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.002"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "Windows Defender - Malware Detected (Event 1116)",
        "description": (
            "Microsoft Defender detected malware on this endpoint.  Critical alert "
            "regardless of whether the threat was remediated."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "1116"},
        ],
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1204"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Windows Defender Real-Time Protection Disabled (Event 5001)",
        "description": (
            "Real-time malware protection was disabled.  Attackers do this "
            "immediately before deploying their payload to avoid detection."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "5001"},
        ],
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.001"],
        "suppression_window_secs": 3600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  EXECUTION
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Encoded PowerShell Execution (-EncodedCommand / -enc)",
        "description": (
            "PowerShell launched with -EncodedCommand or -enc.  Base64 encoding "
            "hides malicious payloads from AV and human review."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "process.name", "op": "eq", "value": "powershell.exe"},
            {"field": "process.command_line", "op": "regex", "value": r"-enc\b|-EncodedCommand"},
        ],
        "mitre_tactics": ["Execution", "Defense Evasion"],
        "mitre_techniques": ["T1059.001", "T1027"],
        "suppression_window_secs": 300,
    },
    {
        "name": "PowerShell Download Cradle Detected",
        "description": (
            "PowerShell using Net.WebClient.DownloadString, Invoke-WebRequest, or "
            "Start-BitsTransfer to pull and execute remote code."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "process.name", "op": "eq", "value": "powershell.exe"},
            {"field": "process.command_line", "op": "regex",
             "value": r"DownloadString|DownloadFile|Invoke-WebRequest|iwr\s|curl\s.*http|Start-BitsTransfer"},
        ],
        "mitre_tactics": ["Execution", "Command and Control"],
        "mitre_techniques": ["T1059.001", "T1105"],
        "suppression_window_secs": 300,
    },
    {
        "name": "MSHTA - HTML Application Execution",
        "description": (
            "mshta.exe runs HTA files and is abused to execute malicious VBScript / "
            "JScript while bypassing application allow-lists."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "process.name", "op": "eq", "value": "mshta.exe"},
        ],
        "mitre_tactics": ["Execution", "Defense Evasion"],
        "mitre_techniques": ["T1218.005"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Regsvr32 - COM Scriptlet AppLocker Bypass (Squiblydoo)",
        "description": (
            "regsvr32 loading a remote .sct scriptlet is a well-known AppLocker "
            "bypass that executes arbitrary code without touching disk."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "process.name", "op": "eq", "value": "regsvr32.exe"},
            {"field": "process.command_line", "op": "regex", "value": r"scrobj|\.sct|/s.*http"},
        ],
        "mitre_tactics": ["Defense Evasion", "Execution"],
        "mitre_techniques": ["T1218.010"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Certutil - Living-off-the-Land File Decode / Download",
        "description": (
            "certutil.exe used to decode, encode, or download files.  Frequently "
            "abused to fetch and decode second-stage malware payloads."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "process.name", "op": "eq", "value": "certutil.exe"},
            {"field": "process.command_line", "op": "regex", "value": r"-decode|-encode|-urlcache"},
        ],
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1140", "T1105"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Windows Script Host (wscript / cscript) Execution",
        "description": (
            "wscript.exe or cscript.exe launched.  These interpreters run VBScript "
            "and JScript and are a common phishing / macro payload delivery mechanism."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "process.name", "op": "in", "value": ["wscript.exe", "cscript.exe"]},
        ],
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1059.005"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Volume Shadow Copy Deletion - Ransomware Indicator",
        "description": (
            "vssadmin or wmic used with 'shadowcopy' or 'delete shadows'. "
            "Destroying VSS snapshots is a pre-encryption step in virtually all ransomware."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {"field": "process.command_line", "op": "regex",
             "value": r"shadowcopy|shadow\s+delete|delete\s+shadows|vssadmin.*delete"},
        ],
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1490"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "System Enumeration - whoami / systeminfo",
        "description": (
            "whoami or systeminfo executed.  Attackers run these immediately after "
            "gaining access to understand their privilege level and environment."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "process.name", "op": "in",
             "value": ["whoami.exe", "systeminfo.exe", "hostname.exe"]},
        ],
        "mitre_tactics": ["Discovery"],
        "mitre_techniques": ["T1033", "T1082"],
        "suppression_window_secs": 600,
    },
    {
        "name": "User / Group Enumeration via net.exe",
        "description": (
            "net.exe called with 'user', 'group', or 'localgroup' arguments. "
            "Standard discovery technique to find high-value accounts for targeting."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "process.name", "op": "eq", "value": "net.exe"},
            {"field": "process.command_line", "op": "regex",
             "value": r"\buser\b|\bgroup\b|\blocalgroup\b"},
        ],
        "mitre_tactics": ["Discovery"],
        "mitre_techniques": ["T1087.001", "T1087.002"],
        "suppression_window_secs": 600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  PERSISTENCE
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Scheduled Task Created (Event 4698)",
        "description": (
            "A new scheduled task was registered.  Scheduled tasks are the most "
            "common Windows persistence mechanism used by attackers."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4698"},
        ],
        "mitre_tactics": ["Persistence", "Execution"],
        "mitre_techniques": ["T1053.005"],
        "suppression_window_secs": 600,
    },
    {
        "name": "New Service Installed (Event 7045)",
        "description": (
            "A new Windows service was installed.  Services start automatically and "
            "run with elevated privileges, making them ideal for persistence."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "7045"},
        ],
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1543.003"],
        "suppression_window_secs": 600,
    },
    {
        "name": "WMI Permanent Event Consumer Created (Event 5861)",
        "description": (
            "A WMI permanent event subscription was registered.  This is one of "
            "the stealthiest Windows persistence mechanisms, surviving reboots."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "5861"},
        ],
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1546.003"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "WMI Temporary Event Consumer Created (Event 5860)",
        "description": (
            "A WMI temporary event subscription was created.  While it does not "
            "survive reboots, it is used for in-session lateral movement."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "5860"},
        ],
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1546.003"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "Linux Cron Job Execution Detected",
        "description": (
            "A cron job ran on a Linux host.  Review for unexpected commands, "
            "especially network calls or file downloads from crontabs."
        ),
        "rule_type": "pattern",
        "severity": "low",
        "conditions": [
            {"field": "category", "op": "eq", "value": "process"},
            {"field": "raw.program", "op": "in", "value": ["cron", "crond"]},
        ],
        "mitre_tactics": ["Persistence", "Execution"],
        "mitre_techniques": ["T1053.003"],
        "suppression_window_secs": 3600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  PRIVILEGE ESCALATION
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "New Local User Account Created (Event 4720)",
        "description": (
            "A new Windows local user account was created.  Attackers create backdoor "
            "accounts to maintain persistent access without domain credentials."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4720"},
        ],
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "mitre_techniques": ["T1136.001"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "User Added to Privileged Security Group (Events 4728 / 4732 / 4756)",
        "description": (
            "A member was added to a security group (local, domain, or universal). "
            "Review especially when the target group is Administrators or Domain Admins."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "in",
             "value": ["4728", "4732", "4756"]},
        ],
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1098"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "Special Privileges Assigned at Interactive Logon (Event 4672)",
        "description": (
            "Sensitive privileges (SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege) "
            "were assigned at logon.  Flag when triggered by non-service accounts."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4672"},
            {"field": "user.is_privileged", "op": "eq", "value": True},
        ],
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1134"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "Linux Kernel Module Loaded - Rootkit Detection",
        "description": (
            "insmod or modprobe loaded a kernel module.  Rootkits use this to hook "
            "syscalls and hide files, processes, and network connections."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "process.name", "op": "in", "value": ["insmod", "modprobe"]},
        ],
        "mitre_tactics": ["Persistence", "Defense Evasion"],
        "mitre_techniques": ["T1547.006"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "Kernel Driver Loaded - Sysmon Event 6",
        "description": (
            "A device driver was loaded (Sysmon Event 6).  Unsigned or unusual "
            "drivers may indicate a rootkit, BYOVD exploit, or vulnerable driver abuse."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "6"},
        ],
        "mitre_tactics": ["Persistence", "Defense Evasion"],
        "mitre_techniques": ["T1014", "T1068"],
        "suppression_window_secs": 3600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  LATERAL MOVEMENT
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Remote Interactive Logon (RDP / Type 10) Detected",
        "description": (
            "A remote interactive desktop logon (type 10) succeeded.  Review source "
            "IP to determine if the connection originated from an unexpected location."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4624"},
            {"field": "raw.LogonType", "op": "eq", "value": "10"},
            {"field": "network.src_ip", "op": "exists", "value": None},
        ],
        "mitre_tactics": ["Lateral Movement"],
        "mitre_techniques": ["T1021.001"],
        "suppression_window_secs": 600,
    },
    {
        "name": "Explicit Credential Use - Pass-the-Hash Indicator (Event 4648)",
        "description": (
            "Logon with explicit credentials other than the logged-on user (Event 4648). "
            "Classic indicator of pass-the-hash, pass-the-ticket, or runas abuse."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4648"},
        ],
        "mitre_tactics": ["Lateral Movement", "Credential Access"],
        "mitre_techniques": ["T1550.002"],
        "suppression_window_secs": 600,
    },
    {
        "name": "Network Logon to Administrative Share (Type 3)",
        "description": (
            "Network logon (type 3) with a source IP present.  PsExec, WMI, and "
            "manual SMB lateral movement all produce network type-3 logons."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4624"},
            {"field": "raw.LogonType", "op": "eq", "value": "3"},
            {"field": "network.src_ip", "op": "exists", "value": None},
        ],
        "mitre_tactics": ["Lateral Movement"],
        "mitre_techniques": ["T1021.002"],
        "suppression_window_secs": 600,
    },
    {
        "name": "Remote Thread Injection Detected - Sysmon Event 8",
        "description": (
            "A remote thread was created in another process (Sysmon Event 8). "
            "Core technique for DLL injection, process hollowing, and shellcode injection."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "8"},
        ],
        "mitre_tactics": ["Defense Evasion", "Privilege Escalation"],
        "mitre_techniques": ["T1055.001"],
        "suppression_window_secs": 600,
    },
    {
        "name": "Lateral Movement - Same User Authenticating to Multiple Hosts",
        "description": (
            "A single account authenticates to 5 or more distinct hosts within "
            "10 minutes — consistent with automated lateral movement or credential reuse."
        ),
        "rule_type": "threshold",
        "severity": "high",
        "conditions": {
            "field": "hostname",
            "group_by": "user.name",
            "threshold": 5,
            "window_secs": 600,
            "filters": [
                {"field": "category", "op": "eq", "value": "auth"},
                {"field": "raw.windows_event_id", "op": "eq", "value": "4624"},
            ],
        },
        "mitre_tactics": ["Lateral Movement"],
        "mitre_techniques": ["T1021"],
        "suppression_window_secs": 600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  DISCOVERY
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Network Port Scanning - Rapid Distinct Destination Ports",
        "description": (
            "A single host sends traffic to 15 or more different destination ports "
            "in 60 seconds, indicating active port scanning or enumeration."
        ),
        "rule_type": "threshold",
        "severity": "medium",
        "conditions": {
            "field": "network.dst_port",
            "group_by": "hostname",
            "threshold": 15,
            "window_secs": 60,
            "filters": [
                {"field": "category", "op": "eq", "value": "network"},
            ],
        },
        "mitre_tactics": ["Discovery"],
        "mitre_techniques": ["T1046"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Process Discovery - tasklist / qprocess",
        "description": (
            "tasklist.exe or qprocess.exe used to enumerate running processes. "
            "Attackers use this to find AV, EDR, and backup software to disable."
        ),
        "rule_type": "pattern",
        "severity": "low",
        "conditions": [
            {"field": "process.name", "op": "in",
             "value": ["tasklist.exe", "qprocess.exe"]},
        ],
        "mitre_tactics": ["Discovery"],
        "mitre_techniques": ["T1057"],
        "suppression_window_secs": 3600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  IMPACT
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Windows Backup / Recovery Disabled - Ransomware Indicator",
        "description": (
            "wbadmin or bcdedit with 'delete' argument detected.  Disabling Windows "
            "backup and recovery is a standard ransomware pre-encryption step."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {"field": "process.name", "op": "in",
             "value": ["wbadmin.exe", "bcdedit.exe"]},
            {"field": "process.command_line", "op": "contains", "value": "delete"},
        ],
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1490"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "Windows Defender Exclusion Path Added (Event 5007)",
        "description": (
            "A Defender configuration change (Event 5007) occurred, potentially "
            "adding an exclusion path attackers use to hide malware from scanning."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "5007"},
        ],
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.001"],
        "suppression_window_secs": 3600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  COMMAND AND CONTROL
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Suspicious Outbound Connection to Known C2 Framework Ports",
        "description": (
            "Outbound connection to a well-known C2 default port: 4444 (Metasploit), "
            "1337 (common RAT), 8888, 9999, 31337 (elite/Back Orifice), 4445."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "category", "op": "eq", "value": "network"},
            {"field": "network.dst_port", "op": "regex",
             "value": r"^(4444|1337|8888|9999|31337|4445|8443)$"},
        ],
        "mitre_tactics": ["Command and Control"],
        "mitre_techniques": ["T1071"],
        "suppression_window_secs": 300,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  COLLECTION / EXFILTRATION
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "High-Volume Outbound Network Events - Possible Data Exfiltration",
        "description": (
            "A single host generates 100 or more outbound network events in 5 minutes. "
            "May indicate staged data being transferred to an external C2 or cloud host."
        ),
        "rule_type": "threshold",
        "severity": "medium",
        "conditions": {
            "field": "network.dst_ip",
            "group_by": "hostname",
            "threshold": 100,
            "window_secs": 300,
            "filters": [
                {"field": "category", "op": "eq", "value": "network"},
            ],
        },
        "mitre_tactics": ["Exfiltration"],
        "mitre_techniques": ["T1041"],
        "suppression_window_secs": 600,
    },
    {
        "name": "Archive / Compression Tool Execution Before Exfiltration",
        "description": (
            "7-Zip, WinRAR, or native archive tools executed.  Attackers compress and "
            "encrypt data before exfiltration to reduce transfer time and bypass DLP."
        ),
        "rule_type": "pattern",
        "severity": "low",
        "conditions": [
            {"field": "process.name", "op": "in",
             "value": ["7z.exe", "winrar.exe", "rar.exe", "tar", "zip", "7za.exe"]},
        ],
        "mitre_tactics": ["Collection"],
        "mitre_techniques": ["T1560.001"],
        "suppression_window_secs": 3600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  ACCOUNT MANAGEMENT / IDENTITY
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "User Password Reset by Non-Owner (Event 4724)",
        "description": (
            "An administrator reset another user's password (Event 4724). "
            "Review when performed outside normal IT workflows or on admin accounts."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4724"},
        ],
        "mitre_tactics": ["Credential Access", "Persistence"],
        "mitre_techniques": ["T1098"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "Windows Firewall Rule Added or Modified (Events 4946 / 4947 / 4948)",
        "description": (
            "A firewall rule was added (4946) or modified (4947/4948). "
            "Attackers add inbound rules to allow persistent remote access."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "in",
             "value": ["4946", "4947", "4948"]},
        ],
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.004"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "Disabled User Account Re-Enabled (Event 4722)",
        "description": (
            "A previously disabled account was re-enabled (Event 4722). "
            "Could indicate reactivation of a dormant backdoor or compromised account."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4722"},
        ],
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1098"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "PowerShell Script Block Logging - Execution Captured (Event 4104)",
        "description": (
            "PowerShell script block logging (Event 4104) captured an execution. "
            "Investigate command content for encoded blobs, network calls, or credential access."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4104"},
        ],
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1059.001"],
        "suppression_window_secs": 600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  HASH IOC — MALWAREBAZAAR CONFIRMED MALWARE
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Malware Hash Confirmed - MalwareBazaar IOC Match",
        "description": (
            "A file hash on this host matched a known malware sample in MalwareBazaar. "
            "This is a confirmed indicator of compromise — the file is a known malicious binary."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {"field": "threat_intel_flags", "op": "list_contains", "value": "hash_ioc_match"},
        ],
        "mitre_tactics": ["Execution", "Defense Evasion"],
        "mitre_techniques": ["T1204.002", "T1027"],
        "suppression_window_secs": 86400,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  RANSOMWARE & IMPACT
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Ransomware - Shadow Copy Deletion via VSSAdmin or WMI",
        "description": (
            "Command line indicates deletion of Volume Shadow Copies — the first step "
            "in most ransomware attacks to prevent recovery."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.command_line", "op": "contains", "value": "vssadmin"},
                                {"field": "process.command_line", "op": "contains", "value": "delete"},
                                {"field": "process.command_line", "op": "contains", "value": "shadow"},
                            ],
                            [
                                {"field": "process.command_line", "op": "contains", "value": "wmic"},
                                {"field": "process.command_line", "op": "contains", "value": "shadowcopy"},
                                {"field": "process.command_line", "op": "contains", "value": "delete"},
                            ],
                            [
                                {"field": "process.command_line", "op": "contains", "value": "wmic"},
                                {"field": "process.command_line", "op": "contains", "value": "shadow"},
                                {"field": "process.command_line", "op": "contains", "value": "call"},
                                {"field": "process.command_line", "op": "contains", "value": "delete"},
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "vssadmin"},
                                {"field": "raw.message", "op": "contains", "value": "delete"},
                                {"field": "raw.message", "op": "contains", "value": "shadow"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1490"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Ransomware - Boot Recovery Disabled via BCDEdit",
        "description": (
            "BCDEdit used to disable boot recovery and error handling — "
            "classic ransomware persistence-of-damage technique to prevent OS recovery."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.command_line", "op": "contains", "value": "bcdedit"},
                                {"field": "process.command_line", "op": "contains", "value": "recoveryenabled"},
                                {"field": "process.command_line", "op": "contains", "value": "no"},
                            ],
                            [
                                {"field": "process.command_line", "op": "contains", "value": "bcdedit"},
                                {"field": "process.command_line", "op": "contains", "value": "bootstatuspolicy"},
                                {"field": "process.command_line", "op": "contains", "value": "ignoreallfailures"},
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "bcdedit"},
                                {"field": "raw.message", "op": "contains", "value": "recoveryenabled"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1490"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Ransomware - Backup Catalog Deletion via wbadmin",
        "description": (
            "wbadmin used to delete Windows backup catalog — "
            "eliminates the last restore point before ransomware encryption begins."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.command_line", "op": "contains", "value": "wbadmin"},
                                {"field": "process.command_line", "op": "contains", "value": "delete"},
                                {"field": "process.command_line", "op": "contains", "value": "catalog"},
                            ],
                            [
                                {"field": "process.command_line", "op": "contains", "value": "wbadmin"},
                                {"field": "process.command_line", "op": "contains", "value": "delete"},
                                {"field": "process.command_line", "op": "contains", "value": "backup"},
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "wbadmin"},
                                {"field": "raw.message", "op": "contains", "value": "delete"},
                                {"field": "raw.message", "op": "contains", "value": "catalog"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1490"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Impact - Disk Wipe via Cipher Overwrite",
        "description": (
            "cipher.exe /w flag triggered — overwrites free disk space, "
            "destroying evidence of deleted files. Rare in legitimate use."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.executable", "op": "endswith", "value": "\\cipher.exe"},
                                {"field": "process.command_line", "op": "contains", "value": "/w:"},
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "cipher.exe"},
                                {"field": "raw.message", "op": "contains", "value": "/w:"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1561.001"],
        "suppression_window_secs": 300,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  DEFENSE EVASION
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Defense Evasion - Windows Firewall Disabled via netsh",
        "description": (
            "netsh command used to turn off Windows Firewall — "
            "commonly done by malware or attackers to allow inbound C2 connections."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.command_line", "op": "contains", "value": "netsh"},
                                {"field": "process.command_line", "op": "contains", "value": "firewall"},
                                {"field": "process.command_line", "op": "contains", "value": "state off"},
                            ],
                            [
                                {"field": "process.command_line", "op": "contains", "value": "netsh"},
                                {"field": "process.command_line", "op": "contains", "value": "advfirewall"},
                                {"field": "process.command_line", "op": "contains", "value": "off"},
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "netsh"},
                                {"field": "raw.message", "op": "contains", "value": "firewall"},
                                {"field": "raw.message", "op": "contains", "value": "off"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.004"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Defense Evasion - AMSI Bypass Attempt",
        "description": (
            "PowerShell command contains known AMSI bypass strings — "
            "attackers disable the Antimalware Scan Interface to execute malicious scripts undetected."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of",
                        "conditions": [
                            {"field": "process.command_line", "op": "contains", "value": "amsiInitFailed"},
                            {"field": "process.command_line", "op": "contains", "value": "AmsiScanBuffer"},
                            {"field": "process.command_line", "op": "contains", "value": "amsiContext"},
                            {"field": "process.command_line", "op": "contains", "value": "AmsiUtils"},
                            {"field": "process.command_line", "op": "contains", "value": "DisableScriptBlockLogging"},
                            {"field": "process.command_line", "op": "contains", "value": "EnableScriptBlockLogging"},
                        ],
                    },
                    {
                        "op": "any_of",
                        "conditions": [
                            {"field": "raw.message", "op": "contains", "value": "amsiInitFailed"},
                            {"field": "raw.message", "op": "contains", "value": "AmsiScanBuffer"},
                            {"field": "raw.message", "op": "contains", "value": "amsiContext"},
                            {"field": "raw.message", "op": "contains", "value": "DisableScriptBlockLogging"},
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.001"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Defense Evasion - ETW Trace Session Disabled",
        "description": (
            "Event Tracing for Windows (ETW) provider disabled — "
            "used to blind security tools that rely on ETW for behavioral telemetry."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.command_line", "op": "contains", "value": "logman"},
                                {"field": "process.command_line", "op": "contains", "value": "stop"},
                            ],
                            [
                                {"field": "process.command_line", "op": "contains", "value": "tracerpt"},
                                {"field": "process.command_line", "op": "contains", "value": "-stop"},
                            ],
                        ],
                    },
                    {"field": "raw.windows_event_id", "op": "eq", "value": "4657"},
                ],
            },
        ],
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562.006"],
        "suppression_window_secs": 600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  CREDENTIAL ACCESS
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Credential Access - SAM / NTDS Hive Copy Attempt",
        "description": (
            "Attempt to copy SAM, SYSTEM, SECURITY, or NTDS.dit hive — "
            "these files contain password hashes for all local and domain accounts."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of",
                        "conditions": [
                            {"field": "process.command_line", "op": "contains", "value": "\\System32\\config\\SAM"},
                            {"field": "process.command_line", "op": "contains", "value": "\\System32\\config\\SYSTEM"},
                            {"field": "process.command_line", "op": "contains", "value": "\\System32\\config\\SECURITY"},
                            {"field": "process.command_line", "op": "contains", "value": "\\Windows\\NTDS\\NTDS.dit"},
                            {"field": "process.command_line", "op": "contains", "value": "HKLM\\SAM"},
                            {"field": "process.command_line", "op": "contains", "value": "HKLM\\SYSTEM"},
                        ],
                    },
                    {
                        "op": "any_of",
                        "conditions": [
                            {"field": "raw.message", "op": "contains", "value": "\\config\\SAM"},
                            {"field": "raw.message", "op": "contains", "value": "NTDS.dit"},
                            {"field": "raw.message", "op": "contains", "value": "HarddiskVolumeShadowCopy"},
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1003.002", "T1003.003"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Credential Access - Token Impersonation Logon (Type 9)",
        "description": (
            "Logon Type 9 (NewCredentials) detected — "
            "used by pass-the-hash and token manipulation attacks to impersonate another user "
            "without knowing their plaintext password."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4624"},
            {"field": "raw.LogonType", "op": "eq", "value": "9"},
        ],
        "mitre_tactics": ["Credential Access", "Lateral Movement"],
        "mitre_techniques": ["T1134.001"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Credential Access - Windows Vault Credential Dump via cmdkey",
        "description": (
            "cmdkey /list executed — enumerates credentials stored in Windows Credential Manager. "
            "Attackers use this to discover stored RDP, network share, and application passwords."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.executable", "op": "endswith", "value": "\\cmdkey.exe"},
                                {"field": "process.command_line", "op": "contains", "value": "/list"},
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "cmdkey"},
                                {"field": "raw.message", "op": "contains", "value": "/list"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1555.004"],
        "suppression_window_secs": 600,
    },
    {
        "name": "Credential Access - DCSync via Mimikatz lsadump::dcsync",
        "description": (
            "DCSync command detected in process arguments — "
            "replicates domain controller password database without direct DC access."
        ),
        "rule_type": "pattern",
        "severity": "critical",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of",
                        "conditions": [
                            {"field": "process.command_line", "op": "contains", "value": "lsadump::dcsync"},
                            {"field": "process.command_line", "op": "contains", "value": "dcsync"},
                        ],
                    },
                    {
                        "op": "any_of",
                        "conditions": [
                            {"field": "raw.message", "op": "contains", "value": "lsadump::dcsync"},
                            {"field": "raw.message", "op": "contains", "value": "dcsync"},
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1003.006"],
        "suppression_window_secs": 300,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  EXECUTION - LOLBins & LIVING-OFF-THE-LAND
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Execution - BITS Transfer Abuse via BITSAdmin",
        "description": (
            "bitsadmin.exe used to create a transfer job — attackers abuse BITS to download "
            "payloads while blending into normal Windows background traffic."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.executable", "op": "endswith", "value": "\\bitsadmin.exe"},
                                {
                                    "op": "any_of",
                                    "conditions": [
                                        {"field": "process.command_line", "op": "contains", "value": "/transfer"},
                                        {"field": "process.command_line", "op": "contains", "value": "/create"},
                                        {"field": "process.command_line", "op": "contains", "value": "/addfile"},
                                    ],
                                },
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "bitsadmin"},
                                {"field": "raw.message", "op": "contains", "value": "/transfer"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Defense Evasion", "Command and Control"],
        "mitre_techniques": ["T1197"],
        "suppression_window_secs": 600,
    },
    {
        "name": "Execution - .NET Compiler Used in Suspicious Location",
        "description": (
            "csc.exe or vbc.exe (C# / VB.NET compiler) invoked from Temp or AppData — "
            "used to compile malicious code on-the-fly, evading static analysis."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {
                                    "op": "any_of",
                                    "conditions": [
                                        {"field": "process.executable", "op": "endswith", "value": "\\csc.exe"},
                                        {"field": "process.executable", "op": "endswith", "value": "\\vbc.exe"},
                                    ],
                                },
                                {
                                    "op": "any_of",
                                    "conditions": [
                                        {"field": "process.command_line", "op": "contains", "value": "\\AppData\\"},
                                        {"field": "process.command_line", "op": "contains", "value": "\\Temp\\"},
                                        {"field": "process.command_line", "op": "contains", "value": "\\tmp\\"},
                                        {"field": "process.command_line", "op": "contains", "value": "\\Users\\Public\\"},
                                    ],
                                },
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {
                                    "op": "any_of",
                                    "conditions": [
                                        {"field": "raw.message", "op": "contains", "value": "csc.exe"},
                                        {"field": "raw.message", "op": "contains", "value": "vbc.exe"},
                                    ],
                                },
                                {"field": "raw.message", "op": "contains", "value": "\\Temp\\"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Defense Evasion", "Execution"],
        "mitre_techniques": ["T1027.004"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Execution - InstallUtil LOLBin Abuse",
        "description": (
            "InstallUtil.exe executing code from unusual paths — "
            "a signed Microsoft binary commonly abused to bypass AppLocker and execute arbitrary code."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.executable", "op": "endswith", "value": "\\InstallUtil.exe"},
                                {
                                    "op": "any_of",
                                    "conditions": [
                                        {"field": "process.command_line", "op": "contains", "value": "\\Temp\\"},
                                        {"field": "process.command_line", "op": "contains", "value": "\\AppData\\"},
                                        {"field": "process.command_line", "op": "contains", "value": "/logfile="},
                                        {"field": "process.command_line", "op": "contains", "value": "/LogToConsole="},
                                    ],
                                },
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "InstallUtil"},
                                {"field": "raw.message", "op": "contains", "value": "\\Temp\\"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Defense Evasion", "Execution"],
        "mitre_techniques": ["T1218.004"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Execution - CMSTP UAC Bypass",
        "description": (
            "cmstp.exe used with suspicious flags — exploits auto-elevation to bypass UAC "
            "and execute arbitrary code with administrator privileges."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.executable", "op": "endswith", "value": "\\cmstp.exe"},
                                {
                                    "op": "any_of",
                                    "conditions": [
                                        {"field": "process.command_line", "op": "contains", "value": "/s"},
                                        {"field": "process.command_line", "op": "contains", "value": "/au"},
                                        {"field": "process.command_line", "op": "contains", "value": ".inf"},
                                    ],
                                },
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "cmstp.exe"},
                                {"field": "raw.message", "op": "contains", "value": "/s"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Privilege Escalation", "Defense Evasion"],
        "mitre_techniques": ["T1218.003"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Execution - Odbcconf Used as Script Proxy",
        "description": (
            "odbcconf.exe with /a REGSVR flag — abused to register and execute "
            "malicious DLLs while impersonating a legitimate Windows ODBC configuration tool."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.executable", "op": "endswith", "value": "\\odbcconf.exe"},
                                {"field": "process.command_line", "op": "contains", "value": "regsvr"},
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "odbcconf"},
                                {"field": "raw.message", "op": "contains", "value": "regsvr"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Defense Evasion", "Execution"],
        "mitre_techniques": ["T1218.008"],
        "suppression_window_secs": 300,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  PRIVILEGE ESCALATION
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Privilege Escalation - AlwaysInstallElevated MSI Policy",
        "description": (
            "AlwaysInstallElevated registry policy detected via Event 4657 — "
            "allows any user to install MSI packages as SYSTEM, a critical privilege escalation path."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.windows_event_id", "op": "eq", "value": "4657"},
                                {"field": "raw.message", "op": "contains", "value": "AlwaysInstallElevated"},
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.command_line", "op": "contains", "value": "AlwaysInstallElevated"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1548.002"],
        "suppression_window_secs": 3600,
    },
    {
        "name": "Privilege Escalation - SeTcbPrivilege or SeDebugPrivilege Granted",
        "description": (
            "High-privilege token rights (SeTcbPrivilege or SeDebugPrivilege) assigned at logon — "
            "these allow process injection and SYSTEM-level impersonation."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4672"},
            {
                "op": "any_of",
                "conditions": [
                    {"field": "raw.message", "op": "contains", "value": "SeTcbPrivilege"},
                    {"field": "raw.message", "op": "contains", "value": "SeDebugPrivilege"},
                ],
            },
        ],
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1134"],
        "suppression_window_secs": 600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  DISCOVERY & RECONNAISSANCE
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Discovery - Active Directory Enumeration Tools",
        "description": (
            "Known Active Directory reconnaissance tool detected — "
            "BloodHound, ADFind, PowerView, or similar tools map AD attack paths for lateral movement."
        ),
        "rule_type": "pattern",
        "severity": "high",
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
                            {"field": "process.command_line", "op": "contains", "value": "Get-ADUser"},
                            {"field": "process.command_line", "op": "contains", "value": "Get-ADComputer"},
                            {"field": "process.command_line", "op": "contains", "value": "Get-ADGroup"},
                            {"field": "process.command_line", "op": "contains", "value": "Invoke-ACLScanner"},
                            {"field": "process.command_line", "op": "contains", "value": "Find-LocalAdminAccess"},
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
        "mitre_tactics": ["Discovery"],
        "mitre_techniques": ["T1069.002", "T1087.002"],
        "suppression_window_secs": 600,
    },
    {
        "name": "Discovery - Security Tool Enumeration",
        "description": (
            "Process querying installed antivirus or security software — "
            "attackers enumerate defenses to identify blind spots before deploying payloads."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.command_line", "op": "contains", "value": "wmic"},
                                {"field": "process.command_line", "op": "contains", "value": "AntiVirusProduct"},
                            ],
                            [
                                {"field": "process.command_line", "op": "contains", "value": "wmic"},
                                {"field": "process.command_line", "op": "contains", "value": "FirewallProduct"},
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "AntiVirusProduct"},
                                {"field": "raw.message", "op": "contains", "value": "wmic"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Discovery"],
        "mitre_techniques": ["T1518.001"],
        "suppression_window_secs": 600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  EXFILTRATION
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Exfiltration - Archive Tool Compressing User Data",
        "description": (
            "Archiving tool (7-zip, WinRAR, WinZip) compressing files from user directories — "
            "staging personal or corporate data for exfiltration."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {
                                    "op": "any_of",
                                    "conditions": [
                                        {"field": "process.executable", "op": "endswith", "value": "\\7z.exe"},
                                        {"field": "process.executable", "op": "endswith", "value": "\\7za.exe"},
                                        {"field": "process.executable", "op": "endswith", "value": "\\rar.exe"},
                                        {"field": "process.executable", "op": "endswith", "value": "\\winzip32.exe"},
                                        {"field": "process.executable", "op": "endswith", "value": "\\winrar.exe"},
                                    ],
                                },
                                {
                                    "op": "any_of",
                                    "conditions": [
                                        {"field": "process.command_line", "op": "contains", "value": "\\Users\\"},
                                        {"field": "process.command_line", "op": "contains", "value": "\\Documents\\"},
                                        {"field": "process.command_line", "op": "contains", "value": "\\Desktop\\"},
                                        {"field": "process.command_line", "op": "contains", "value": "\\Downloads\\"},
                                    ],
                                },
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Exfiltration", "Collection"],
        "mitre_techniques": ["T1560.001"],
        "suppression_window_secs": 600,
    },
    {
        "name": "Exfiltration - FTP Scripted Upload",
        "description": (
            "ftp.exe with -s or /s flag (script file) — automates upload of files via FTP, "
            "used to quietly transfer stolen data without interactive prompts."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "process.executable", "op": "endswith", "value": "\\ftp.exe"},
                                {
                                    "op": "any_of",
                                    "conditions": [
                                        {"field": "process.command_line", "op": "contains", "value": "-s:"},
                                        {"field": "process.command_line", "op": "contains", "value": "/s:"},
                                    ],
                                },
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "ftp.exe"},
                                {"field": "raw.message", "op": "contains", "value": "-s:"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Exfiltration"],
        "mitre_techniques": ["T1048.003"],
        "suppression_window_secs": 300,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  PERSISTENCE
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Persistence - Startup Folder File Drop",
        "description": (
            "A file was written to the Windows Startup folder — "
            "will execute automatically on the next user login as a persistence mechanism."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of",
                        "conditions": [
                            {"field": "file.path", "op": "contains", "value": "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"},
                            {"field": "file.path", "op": "contains", "value": "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\"},
                        ],
                    },
                    {
                        "op": "any_of",
                        "conditions": [
                            {"field": "raw.message", "op": "contains", "value": "\\Programs\\Startup\\"},
                            {"field": "raw.message", "op": "contains", "value": "\\Programs\\StartUp\\"},
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1547.001"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Persistence - COM Object Hijacking via HKCU Registry",
        "description": (
            "COM server registered under HKCU\\Software\\Classes\\CLSID — "
            "overrides system-wide COM registration without admin rights to achieve persistent execution."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.windows_event_id", "op": "eq", "value": "4657"},
                                {"field": "raw.message", "op": "contains", "value": "HKCU"},
                                {"field": "raw.message", "op": "contains", "value": "CLSID"},
                            ],
                        ],
                    },
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {"field": "raw.message", "op": "contains", "value": "HKCU\\Software\\Classes\\CLSID"},
                                {"field": "raw.message", "op": "contains", "value": "InprocServer32"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "mitre_techniques": ["T1546.015"],
        "suppression_window_secs": 600,
    },
    {
        "name": "Persistence - Suspicious Service DLL Registration (Event 7045)",
        "description": (
            "New service installed with a DLL path or from an unusual location — "
            "malware registers services with .dll or script paths to survive reboots."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "7045"},
            {
                "op": "any_of",
                "conditions": [
                    {"field": "raw.message", "op": "contains", "value": ".dll"},
                    {"field": "raw.message", "op": "contains", "value": "\\Temp\\"},
                    {"field": "raw.message", "op": "contains", "value": "\\AppData\\"},
                    {"field": "raw.message", "op": "contains", "value": "\\Users\\Public\\"},
                    {"field": "raw.message", "op": "contains", "value": "svchost.exe -k"},
                ],
            },
        ],
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1543.003"],
        "suppression_window_secs": 300,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  LATERAL MOVEMENT
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "Lateral Movement - Pass-the-Ticket Kerberos Anomaly (Event 4769)",
        "description": (
            "Kerberos service ticket requested with encryption type 0x17 (RC4) — "
            "modern environments use AES; RC4 tickets indicate Kerberoasting or Pass-the-Ticket attacks."
        ),
        "rule_type": "pattern",
        "severity": "high",
        "conditions": [
            {"field": "raw.windows_event_id", "op": "eq", "value": "4769"},
            {
                "op": "any_of",
                "conditions": [
                    {"field": "raw.message", "op": "contains", "value": "0x17"},
                    {"field": "raw.message", "op": "contains", "value": "0x18"},
                    {"field": "raw.message", "op": "contains", "value": "RC4"},
                ],
            },
        ],
        "mitre_tactics": ["Credential Access", "Lateral Movement"],
        "mitre_techniques": ["T1558.003", "T1550.003"],
        "suppression_window_secs": 300,
    },
    {
        "name": "Lateral Movement - Suspicious DCOM / MMC Execution",
        "description": (
            "mmc.exe or dcomcnfg used with unusual arguments or remote targets — "
            "DCOM can be abused to execute code on remote systems without SMB."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {
                        "op": "any_of_groups",
                        "groups": [
                            [
                                {
                                    "op": "any_of",
                                    "conditions": [
                                        {"field": "process.command_line", "op": "contains", "value": "mmc.exe"},
                                        {"field": "process.command_line", "op": "contains", "value": "dcomcnfg"},
                                    ],
                                },
                                {"field": "process.command_line", "op": "regex", "value": r"\\\\.+\\"},
                            ],
                        ],
                    },
                ],
            },
        ],
        "mitre_tactics": ["Lateral Movement", "Execution"],
        "mitre_techniques": ["T1021.003"],
        "suppression_window_secs": 600,
    },

    # ═══════════════════════════════════════════════════════════════════════
    #  COMMAND AND CONTROL
    # ═══════════════════════════════════════════════════════════════════════

    {
        "name": "C2 - Outbound Connection to Uncommon High Port",
        "description": (
            "Network connection established to a high ephemeral port (>49152) on an external host — "
            "malware often listens on non-standard high ports to avoid detection."
        ),
        "rule_type": "pattern",
        "severity": "medium",
        "conditions": [
            {"field": "category", "op": "eq", "value": "network"},
            {"field": "network.dst_port", "op": "gt", "value": 49152},
            {
                "op": "none_of",
                "conditions": [
                    {"field": "network.dst_ip", "op": "startswith", "value": "10."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "192.168."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.16."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.17."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.18."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.19."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.20."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.21."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.22."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.23."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.24."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.25."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.26."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.27."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.28."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.29."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.30."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "172.31."},
                    {"field": "network.dst_ip", "op": "startswith", "value": "127."},
                ],
            },
        ],
        "mitre_tactics": ["Command and Control"],
        "mitre_techniques": ["T1571"],
        "suppression_window_secs": 600,
    },
    {
        "name": "C2 - PowerShell Direct TCP Socket Connection",
        "description": (
            "PowerShell using System.Net.Sockets.TCPClient or Net.Sockets — "
            "pure-PowerShell C2 channels connect directly via raw sockets to bypass proxy settings."
        ),
        "rule_type": "pattern",
        "severity": "high",
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
                            {"field": "process.command_line", "op": "contains", "value": "StreamReader"},
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
        "mitre_tactics": ["Command and Control"],
        "mitre_techniques": ["T1095"],
        "suppression_window_secs": 300,
    },
]

# Validate count at import time to catch accidental additions/removals.
_RULE_COUNT = len(_DEFAULT_RULES)
assert _RULE_COUNT == 80, (  # noqa: S101
    f"default_rules.py: expected 80 built-in rules, found {_RULE_COUNT}. "
    "Update this assertion if the catalogue size changes intentionally."
)


# ─────────────────────────────────────────────────────────────────────────────
# Seeding function
# ─────────────────────────────────────────────────────────────────────────────

async def seed_default_rules(db: AsyncSession, tenant_id: UUID) -> int:
    """
    Bulk-inserts all default detection rules for a newly created tenant.

    Called once inside TenantService.create() within the same DB transaction
    so the rules are created atomically with the tenant itself.
    Returns the number of rules written.
    """
    rules: list[DetectionRule] = []
    for spec in _DEFAULT_RULES:
        rule = DetectionRule(
            tenant_id=tenant_id,
            name=spec["name"],
            description=spec.get("description"),
            rule_type=RuleType(spec["rule_type"]),
            severity=RuleSeverity(spec["severity"]),
            enabled=True,
            conditions=spec["conditions"],
            mitre_tactics=spec.get("mitre_tactics", []),
            mitre_techniques=spec.get("mitre_techniques", []),
            suppression_window_secs=spec.get("suppression_window_secs", 300),
            created_by_id=None,   # system-seeded; no human actor
            updated_by_id=None,
        )
        db.add(rule)
        rules.append(rule)

    await db.flush(rules)
    logger.info(
        "default_rules_seeded",
        tenant_id=str(tenant_id),
        count=len(rules),
    )
    return len(rules)

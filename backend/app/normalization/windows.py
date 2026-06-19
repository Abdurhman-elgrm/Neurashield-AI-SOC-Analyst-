from __future__ import annotations

import re
from typing import Any

from app.normalization.models import (
    NormalizedEvent,
    NormalizedFile,
    NormalizedNetwork,
    NormalizedProcess,
    NormalizedUser,
)


def _win_basename(path: str | None) -> str | None:
    """Extract the filename from a Windows or POSIX path, handling both separators."""
    if not path:
        return None
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    return name or None


# Human-readable titles for Windows Event IDs.
# Injected into event.tags so the UI displays meaningful names instead of "EventID XXXX".
# NOTE: EventID 10029 is shared between WindowsUpdateClient and DistributedCOM sources —
#       the handler below corrects the tag at runtime based on source_name.
_WIN_EVENT_TITLES: dict[str, str] = {
    # Authentication & Logon
    "4624":  "Successful User Logon",
    "4625":  "Failed User Logon Attempt",
    "4634":  "User Logoff",
    "4647":  "User-Initiated Logoff",
    "4648":  "Logon with Explicit Credentials",
    "4672":  "Special Privileges Assigned to New Logon",
    "4768":  "Kerberos TGT Requested",
    "4769":  "Kerberos Service Ticket Requested",
    "4771":  "Kerberos Pre-authentication Failed",
    "4776":  "NTLM Credential Validation",
    # Account Management
    "4720":  "User Account Created",
    "4722":  "User Account Enabled",
    "4723":  "User Password Change Attempt",
    "4724":  "User Password Reset",
    "4725":  "User Account Disabled",
    "4726":  "User Account Deleted",
    "4728":  "Member Added to Global Security Group",
    "4732":  "Member Added to Local Security Group",
    "4733":  "Member Removed from Local Security Group",
    "4740":  "User Account Locked Out",
    "4756":  "Member Added to Universal Security Group",
    # Policy Change & Audit
    "4657":  "Registry Value Modified",
    "4663":  "Object Access Attempt",
    "4670":  "Object Permissions Changed",
    "4719":  "System Audit Policy Changed",
    # Process & Service
    "4688":  "New Process Created",
    "4689":  "Process Terminated",
    "4698":  "Scheduled Task Created",
    "4699":  "Scheduled Task Deleted",
    "4702":  "Scheduled Task Updated",
    "7040":  "Service Start Type Changed",
    "7045":  "New Service Installed",
    # Audit Tampering
    "1100":  "Event Logging Service Stopped",
    "1102":  "Security Audit Log Cleared",
    # Credential Access
    "5058":  "Cryptographic Key File Operation",
    "5382":  "Vault Credentials Accessed",
    # PowerShell (Microsoft-Windows-PowerShell/Operational)
    "40961": "PowerShell Console Starting",
    "40962": "PowerShell Console Ready",
    "4100":  "PowerShell Error",
    "4103":  "PowerShell Pipeline Execution",
    "4104":  "PowerShell Script Block Logged",
    "53504": "PowerShell Console Initializing",
    # WMI Activity
    "5857":  "WMI Provider Host Started",
    "5858":  "WMI Provider Query Failed",
    "5860":  "WMI Temporary Event Consumer Created",
    "5861":  "WMI Permanent Event Consumer Created",
    # Network & Firewall
    "5156":  "Network Connection Allowed by Firewall",
    "5157":  "Network Connection Blocked by Firewall",
    "5158":  "Network Bind Allowed by Firewall",
    "5159":  "Network Bind Blocked by Firewall",
    # Windows Defender
    "1006":  "Defender: Malware Scan Completed",
    "1116":  "Defender: Malware Detected",
    "1117":  "Defender: Action Taken on Threat",
    "1150":  "Defender: Service Started",
    "1151":  "Defender: Scheduled Scan",
    # Task Scheduler
    "106":   "Scheduled Task Registered",
    "140":   "Scheduled Task Updated",
    "141":   "Scheduled Task Deleted",
    "200":   "Scheduled Task Execution Started",
    "201":   "Scheduled Task Execution Completed",
    # Windows Update (WindowsUpdateClient source only — see DCOM note above)
    "10029": "Windows Update: Download Started",
    "16384": "Windows Update: Auto-Restart Scheduled",
    "16394": "Windows Update: Reboot Required",
    # Sysmon (Event IDs 1–26)
    "1":  "Sysmon: Process Created",
    "2":  "Sysmon: File Creation Time Changed",
    "3":  "Sysmon: Network Connection",
    "4":  "Sysmon: Service State Changed",
    "5":  "Sysmon: Process Terminated",
    "6":  "Sysmon: Driver Loaded",
    "7":  "Sysmon: Image Loaded",
    "8":  "Sysmon: Remote Thread Created",
    "9":  "Sysmon: Raw Disk Read",
    "10": "Sysmon: Process Access",
    "11": "Sysmon: File Created",
    "12": "Sysmon: Registry Key Created/Deleted",
    "13": "Sysmon: Registry Value Set",
    "14": "Sysmon: Registry Key/Value Renamed",
    "15": "Sysmon: Alternate Data Stream Created",
    "16": "Sysmon: Configuration Changed",
    "17": "Sysmon: Named Pipe Created",
    "18": "Sysmon: Named Pipe Connected",
    "19": "Sysmon: WMI Event Filter Activity",
    "20": "Sysmon: WMI Event Consumer Activity",
    "21": "Sysmon: WMI Consumer Bound to Filter",
    "22": "Sysmon: DNS Query",
    "23": "Sysmon: File Deleted",
    "24": "Sysmon: Clipboard Content Captured",
    "25": "Sysmon: Process Tampered",
    "26": "Sysmon: File Delete Logged",
    # Miscellaneous System
    "258":   "Kernel: Time Change",
    "8224":  "Volume Shadow Copy Service Started",
    "17890": "IIS: Worker Process Failure",
}

# Maps Windows log source names → normalized category.
# Applied when source_name is present (promoted from the raw sub-dict by mapper.py).
_SOURCE_CATEGORY: dict[str, str] = {
    "Microsoft-Windows-Security-Auditing":               "auth",
    "Microsoft-Windows-PowerShell":                      "process",
    "Microsoft-Windows-PowerShell/Operational":          "process",
    "Microsoft-Windows-Sysmon/Operational":              "process",
    "Microsoft-Windows-WMI-Activity/Operational":        "other",
    "Microsoft-Windows-Windows Defender/Operational":    "other",
    "Microsoft-Windows-TaskScheduler/Operational":       "process",
    "Microsoft-Windows-WindowsUpdateClient/Operational": "other",
    "Microsoft-Windows-Bits-Client/Operational":         "network",
    "Microsoft-Windows-DNS-Client/Operational":          "network",
    "Microsoft-Windows-Kernel-General":                  "other",
    "Service Control Manager":                           "process",
}

_SYSTEM_ACCOUNTS = {"-", "", "system", "local service", "network service", "anonymous logon"}

# Service process names whose 4672 events are routine infrastructure noise.
_SERVICE_PROCESS_NAMES = frozenset({
    "services.exe", "lsass.exe", "svchost.exe", "wininit.exe", "winlogon.exe",
    "csrss.exe", "smss.exe", "taskhostw.exe", "ntoskrnl.exe",
})

# Windows protocol number → name (used by firewall audit events 5156/5157).
_PROTO_MAP = {"1": "ICMP", "6": "TCP", "17": "UDP", "58": "ICMPv6"}

# ── Logon type classification (EventID 4624 / 4625 / 4648) ───────────────────
# Maps the numeric LogonType field to a short label injected as a tag,
# e.g. "logon:rdp", "logon:network", "logon:interactive".
_LOGON_TYPE_NAMES: dict[str, str] = {
    "2":  "interactive",        # Local console keyboard/mouse session
    "3":  "network",            # Network share, SMB, WMI, scheduled task over network
    "4":  "batch",              # Batch job / scheduled task
    "5":  "service",            # Service start
    "7":  "unlock",             # Workstation unlock
    "8":  "network-cleartext",  # Credentials sent in cleartext (e.g. IIS Basic Auth)
    "9":  "new-credentials",    # RunAs /netonly — uses cached creds locally, new for net
    "10": "rdp",                # Remote Desktop / Terminal Services interactive session
    "11": "cached-interactive", # Domain logon with cached credentials (offline)
    "12": "cached-rdp",         # RDP logon with cached credentials
    "13": "cached-unlock",      # Workstation unlock with cached credentials
}

# Logon types that establish a remote session — worth tagging and escalating
# when a non-local source IP is present.
_REMOTE_LOGON_TYPES  = frozenset({"10", "12"})       # RDP / cached-RDP
_NETWORK_LOGON_TYPES = frozenset({"3", "8", "9"})    # Network / cleartext / new-credentials

# ── Privilege risk classification (EventID 4672) ──────────────────────────────
# Presence of these privileges for a non-system user account is a meaningful
# detection signal that warrants elevated severity and explicit tagging.
_HIGH_RISK_PRIVILEGES = frozenset({
    "SeDebugPrivilege",              # Read/write any process memory — enables LSASS dump
    "SeImpersonatePrivilege",        # Impersonate any logged-on user token
    "SeTcbPrivilege",                # Act as part of the operating system
    "SeLoadDriverPrivilege",         # Load/unload kernel-mode drivers (rootkit potential)
    "SeTakeOwnershipPrivilege",      # Take ownership of any securable object
    "SeCreateTokenPrivilege",        # Create arbitrary access tokens
    "SeAssignPrimaryTokenPrivilege", # Assign a primary token to a process
})

_MEDIUM_RISK_PRIVILEGES = frozenset({
    "SeBackupPrivilege",     # Bypass file ACLs for backup — enables sensitive file reads
    "SeRestorePrivilege",    # Bypass file ACLs for restore — allows overwriting system files
    "SeSecurityPrivilege",   # Manage audit/security log — can clear event logs
    "SeSystemtimePrivilege", # Modify system clock — disrupts timestamp-based detections
})

# IPs that are never interesting as "external" source IPs.
_LOCAL_IP_ADDRESSES = frozenset({
    "-", "", "::1", "127.0.0.1", "0.0.0.0", "::ffff:127.0.0.1",
})


def get_win_event_title(event_id: Any) -> str | None:
    """Return a human-readable title for a Windows Event ID, or None if unknown."""
    return _WIN_EVENT_TITLES.get(str(event_id))


def normalize_windows_event(raw: dict[str, Any], base: NormalizedEvent) -> NormalizedEvent:
    """
    Maps Windows-specific event fields to the normalized schema.
    Handles Security Event Log, Sysmon, PowerShell, WMI, Defender, and other channels.
    """
    event_id = raw.get("event_id_windows") or raw.get("EventID")

    # Store EventID in raw for frontend reference and add a human-readable title tag.
    if event_id:
        base.raw["windows_event_id"] = str(event_id)
        title = get_win_event_title(event_id)
        if title and title not in base.tags:
            base.tags.insert(0, title)

    # Apply source_name → category mapping before per-event handlers so that
    # specific handlers can override it if needed.
    source = raw.get("source_name") or raw.get("SourceName")
    if source:
        cat = _SOURCE_CATEGORY.get(source)
        if cat and base.category == "other":
            base.category = cat

    # Populate sub-objects from any pre-structured fields the agent included.
    if base.process is None and (proc := raw.get("process") or raw.get("Image")):
        base.process = _extract_process_windows(raw, proc if isinstance(proc, dict) else {})

    if base.network is None and raw.get("network"):
        base.network = _extract_network_windows(raw.get("network", {}))

    if base.file is None and raw.get("file"):
        base.file = _extract_file_windows(raw.get("file", {}))

    if base.user is None:
        base.user = _extract_user_windows(raw)

    eid = str(event_id) if event_id is not None else ""

    # ── Sysmon ────────────────────────────────────────────────────────────────
    if eid == "1":  # Process Create
        base.category = "process"
        base.process = _extract_process_from_sysmon_create(raw)

    elif eid == "3":  # Network Connect
        base.category = "network"
        base.network = _extract_network_from_sysmon(raw)

    elif eid == "5":  # Process Terminated
        base.category = "process"
        base.severity = 1

    elif eid in ("6", "7"):  # Driver/Image Loaded — can indicate DLL injection
        base.category = "process"
        base.severity = 2

    elif eid in ("8", "10"):  # Remote Thread / Process Access — high suspicion
        base.category = "process"
        base.severity = 3

    elif eid == "11":  # File Create
        base.category = "file"
        base.file = _extract_file_from_sysmon(raw)

    elif eid in ("12", "13", "14"):  # Registry events
        base.category = "registry"
        base.registry = _extract_registry_windows(raw)

    elif eid == "22":  # DNS Query
        base.category = "network"
        base.severity = 1

    elif eid == "23":  # File Deleted
        base.category = "file"
        base.severity = 2

    # ── WMI Activity ──────────────────────────────────────────────────────────
    elif eid == "5857":  # WMI Provider Host Started — routine infrastructure
        base.category = "other"
        base.severity = 1
        provider = raw.get("ProviderName") or raw.get("NamespaceName")
        pid = _to_int(raw.get("ProcessID") or raw.get("HostingProcessId"))
        if provider:
            base.process = NormalizedProcess(name=provider, pid=pid)

    elif eid == "5858":  # WMI Provider Error
        base.category = "other"
        base.severity = 2

    elif eid in ("5860", "5861"):  # WMI Event Consumer — persistence indicator
        base.category = "other"
        base.severity = 3
        _add_tag(base, "wmi_persistence")

    # ── PowerShell ────────────────────────────────────────────────────────────
    elif eid in ("40961", "40962", "53504"):  # Console startup — noisy, not suspicious
        base.category = "process"
        base.severity = 1

    elif eid == "4100":  # PowerShell Error
        base.category = "process"
        base.severity = 2

    elif eid == "4103":  # Pipeline Execution
        base.category = "process"
        base.severity = 2

    elif eid == "4104":  # Script Block Logged — can catch obfuscated scripts
        base.category = "process"
        base.severity = 3

    # ── Security log: Process events ──────────────────────────────────────────
    elif eid == "4688":  # New Process Created
        base.category = "process"
        image = raw.get("Image") or raw.get("NewProcessName")
        if image:
            base.process = NormalizedProcess(
                name=_win_basename(image),
                executable=image or None,
                command_line=raw.get("CommandLine"),
                pid=_to_int(raw.get("NewProcessId")),
                ppid=_to_int(raw.get("ProcessId")),
            )
        if not base.user:
            name = raw.get("SubjectUserName") or raw.get("TargetUserName")
            if name and name.lower() not in _SYSTEM_ACCOUNTS:
                base.user = NormalizedUser(name=name, domain=raw.get("SubjectDomainName"))

    elif eid == "4689":  # Process Terminated
        base.category = "process"
        base.severity = 1

    elif eid in ("4698", "4702"):  # Scheduled Task Created/Updated
        base.category = "process"
        base.severity = 3

    elif eid == "4699":  # Scheduled Task Deleted
        base.category = "process"
        base.severity = 2

    elif eid == "7045":  # Service Installed
        base.category = "process"
        base.severity = 3

    # ── Security log: Authentication ──────────────────────────────────────────
    elif eid == "4624":  # Successful Logon
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 1
        _try_extract_src_ip(raw, base)
        _apply_logon_type(raw, base)
        # Machine accounts (e.g. WORKSTATION01$) performing network logons are normal
        # domain traffic — cap severity at INFO and mark explicitly.
        if _is_machine_account(base.user.name if base.user else None):
            _add_tag(base, "machine-account")
            base.severity = min(base.severity, 1)

    elif eid == "4625":  # Failed Logon
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 2
        _try_extract_src_ip(raw, base)
        _apply_logon_type(raw, base)

    elif eid == "4648":  # Logon with Explicit Credentials
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 2
        _try_extract_src_ip(raw, base)
        _apply_logon_type(raw, base)

    elif eid in ("4634", "4647"):  # Logoff
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 1

    elif eid == "4672":  # Special Privileges Assigned
        base.category = "auth"
        user = _extract_user_from_logon(raw)
        # Read the raw account name rather than user.name: _extract_user_from_logon
        # now suppresses system accounts to None, so user.name would be empty for
        # SYSTEM/LOCAL SERVICE/NETWORK SERVICE and the service-account check would miss them.
        raw_acct = (raw.get("TargetUserName") or raw.get("SubjectUserName") or "").upper()
        proc = (raw.get("Image") or raw.get("ProcessName") or "").lower()
        is_service_acct = raw_acct in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
        is_service_proc  = bool(proc and any(proc.endswith(s) for s in _SERVICE_PROCESS_NAMES))
        is_machine_acct  = _is_machine_account(raw_acct)

        if is_service_acct or is_service_proc or is_machine_acct:
            # Built-in OS accounts and computer accounts are always privileged by design.
            # Clear is_privileged so UEBA does not raise a false positive signal.
            user.is_privileged = False
            base.severity = 1
        else:
            user.is_privileged = True
            privs     = _extract_privileges_4672(raw)
            high_risk = [p for p in privs if p in _HIGH_RISK_PRIVILEGES]
            med_risk  = [p for p in privs if p in _MEDIUM_RISK_PRIVILEGES]

            if high_risk:
                # A real user holding these privileges is worth active investigation.
                base.severity = 3
                for priv in high_risk:
                    _add_tag(base, f"priv:{priv}")
                _add_tag(base, "dangerous-privileges")
            elif med_risk:
                base.severity = 2
            else:
                base.severity = 2

        base.user = user

    elif eid in ("4768", "4769", "4776"):  # Kerberos / NTLM auth
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)

    elif eid == "4771":  # Kerberos Pre-auth Failed
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 2

    # ── Security log: Account Management ─────────────────────────────────────
    elif eid == "4720":  # User Account Created
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 2

    elif eid in ("4722", "4723", "4724", "4725", "4726"):  # Account state changes
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 2

    elif eid == "4740":  # Account Locked Out
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 3

    elif eid in ("4728", "4732", "4733", "4756"):  # Group membership changes
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 2

    # ── Security log: Policy Change ───────────────────────────────────────────
    elif eid == "4719":  # Audit Policy Changed
        base.category = "auth"
        base.severity = 3

    elif eid == "1102":  # Audit Log Cleared
        base.category = "auth"
        base.severity = 4

    elif eid == "1100":  # Event Logging Service Stopped
        base.category = "other"
        base.severity = 3

    # ── Credential Access ─────────────────────────────────────────────────────
    elif eid in ("5058", "5382"):  # Key File Op / Vault Credential Read
        base.category = "auth"
        base.severity = 2

    # ── Network / Firewall ────────────────────────────────────────────────────
    elif eid in ("5156", "5158"):  # Connection/bind allowed
        base.category = "network"
        base.severity = 1
        _try_extract_firewall_network(raw, base)

    elif eid in ("5157", "5159"):  # Connection/bind blocked
        base.category = "network"
        base.severity = 2
        _try_extract_firewall_network(raw, base)

    # ── Windows Defender ──────────────────────────────────────────────────────
    elif eid in ("1150", "1151", "1006"):  # Defender service/scan events
        base.category = "other"
        base.severity = 1

    elif eid == "1116":  # Malware Detected
        base.category = "other"
        base.severity = 4

    elif eid == "1117":  # Defender Action on Malware
        base.category = "other"
        base.severity = 3

    # ── Windows Update / DCOM ─────────────────────────────────────────────────
    elif eid == "10029":
        # EventID 10029 is shared between two distinct sources:
        #   WindowsUpdateClient → "A download has been started"      (routine)
        #   DistributedCOM      → "Server did not register with DCOM" (system noise)
        # Both are severity 1, but the tag must accurately reflect the actual source.
        base.category = "other"
        base.severity = 1
        source_name = raw.get("source_name") or ""
        if "DCOM" in source_name or "DistributedCOM" in source_name:
            _replace_tag(base, "Windows Update: Download Started", "DCOM: Server Registration Timeout")

    elif eid in ("16384", "16394"):
        base.category = "other"
        base.severity = 1

    # ── Miscellaneous System ──────────────────────────────────────────────────
    elif eid in ("258", "8224", "17890"):
        base.category = "other"
        base.severity = 1

    return base


# ─── Field extraction helpers ─────────────────────────────────────────────────

def _extract_process_windows(raw: dict[str, Any], proc: dict[str, Any]) -> NormalizedProcess:
    hashes = raw.get("Hashes") if isinstance(raw.get("Hashes"), dict) else {}
    image = raw.get("Image", "")
    return NormalizedProcess(
        pid=_to_int(proc.get("pid") or raw.get("ProcessId")),
        ppid=_to_int(proc.get("ppid") or raw.get("ParentProcessId")),
        name=proc.get("name") or _win_basename(image),
        executable=proc.get("executable") or image or None,
        command_line=proc.get("command_line") or raw.get("CommandLine"),
        user=proc.get("user") or raw.get("User"),
        hash_md5=proc.get("hash_md5") or hashes.get("MD5"),
        hash_sha256=proc.get("hash_sha256") or hashes.get("SHA256"),
    )


def _extract_process_from_sysmon_create(raw: dict[str, Any]) -> NormalizedProcess:
    hashes = _parse_sysmon_hashes(raw.get("Hashes", ""))
    image = raw.get("Image", "")
    return NormalizedProcess(
        pid=_to_int(raw.get("ProcessId")),
        ppid=_to_int(raw.get("ParentProcessId")),
        name=_win_basename(image),
        executable=image or None,
        command_line=raw.get("CommandLine"),
        user=raw.get("User"),
        hash_md5=hashes.get("MD5"),
        hash_sha256=hashes.get("SHA256"),
    )


def _extract_network_from_sysmon(raw: dict[str, Any]) -> NormalizedNetwork:
    return NormalizedNetwork(
        src_ip=raw.get("SourceIp"),
        src_port=_to_int(raw.get("SourcePort")),
        dst_ip=raw.get("DestinationIp"),
        dst_port=_to_int(raw.get("DestinationPort")),
        protocol=raw.get("Protocol"),
        direction="outbound" if raw.get("Initiated") == "true" else None,
    )


def _extract_file_from_sysmon(raw: dict[str, Any]) -> NormalizedFile:
    path = raw.get("TargetFilename", "")
    name = _win_basename(path)
    ext = name.rsplit(".", 1)[-1] if name and "." in name else None
    return NormalizedFile(path=path or None, name=name, extension=ext)


def _extract_network_windows(net: dict[str, Any]) -> NormalizedNetwork:
    return NormalizedNetwork(
        src_ip=net.get("src_ip") or net.get("SourceIp"),
        src_port=_to_int(net.get("src_port") or net.get("SourcePort")),
        dst_ip=net.get("dst_ip") or net.get("DestinationIp"),
        dst_port=_to_int(net.get("dst_port") or net.get("DestinationPort")),
        protocol=net.get("protocol") or net.get("Protocol"),
    )


def _extract_file_windows(f: dict[str, Any]) -> NormalizedFile:
    path = f.get("path") or f.get("TargetFilename", "")
    name = f.get("name") or _win_basename(path)
    ext = f.get("extension") or (name.rsplit(".", 1)[-1] if name and "." in name else None)
    return NormalizedFile(
        path=path or None,
        name=name,
        extension=ext,
        size=_to_int(f.get("size")),
        hash_md5=f.get("hash_md5"),
        hash_sha256=f.get("hash_sha256"),
        action=f.get("action"),
    )


def _extract_user_windows(raw: dict[str, Any]) -> NormalizedUser:
    user_raw = raw.get("user") or {}
    if not isinstance(user_raw, dict):
        user_raw = {}
    name = (
        user_raw.get("name")
        or raw.get("TargetUserName")
        or raw.get("SubjectUserName")
        or raw.get("User")
    )
    domain = (
        user_raw.get("domain")
        or raw.get("TargetDomainName")
        or raw.get("SubjectDomainName")
    )
    if name and name.lower() in _SYSTEM_ACCOUNTS:
        name = None
    if name and "\\" in name:
        parts = name.split("\\", 1)
        domain = domain or parts[0]
        name = parts[1]
    return NormalizedUser(name=name, domain=domain, id=user_raw.get("id"))


def _extract_user_from_logon(raw: dict[str, Any]) -> NormalizedUser:
    name   = raw.get("TargetUserName") or raw.get("SubjectUserName")
    domain = raw.get("TargetDomainName") or raw.get("SubjectDomainName")
    sid    = raw.get("TargetUserSid")

    # Suppress built-in OS / anonymous accounts so they don't produce UEBA noise.
    # _SYSTEM_ACCOUNTS covers: SYSTEM, LOCAL SERVICE, NETWORK SERVICE, ANONYMOUS LOGON, etc.
    # Machine accounts (ending '$') are left intact for the caller to handle via
    # _is_machine_account(); they carry separate semantics from system accounts.
    if name and name.lower() in _SYSTEM_ACCOUNTS:
        name = None

    # Only real human "administrator" accounts get the privileged flag here.
    # The 4672 handler applies finer-grained privilege analysis and overrides this.
    is_machine    = _is_machine_account(name)
    is_privileged = bool(name) and not is_machine and name.upper() == "ADMINISTRATOR"

    return NormalizedUser(name=name, domain=domain, id=sid, is_privileged=is_privileged)


def _extract_privileges_4672(raw: dict[str, Any]) -> list[str]:
    """
    Return the privilege list from a 4672 event.
    Tries the structured ``Privileges`` field first (populated by some log shippers
    and the mapper's key-value parser), then falls back to scanning the original
    raw message text with a regex.  Result is ordered and deduplicated.
    """
    privs_raw = raw.get("Privileges") or raw.get("privileges")
    if privs_raw and isinstance(privs_raw, str):
        found = re.findall(r"Se\w+(?:Privilege|Right)", privs_raw)
        if found:
            return list(dict.fromkeys(found))

    # Fall back to the original message embedded in the raw sub-dict.
    raw_sub = raw.get("raw") if isinstance(raw.get("raw"), dict) else {}
    msg = raw_sub.get("message", "")
    return list(dict.fromkeys(re.findall(r"Se\w+(?:Privilege|Right)", msg)))


def _extract_registry_windows(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "key":    raw.get("TargetObject") or raw.get("registry", {}).get("key"),
        "value":  raw.get("Details")      or raw.get("registry", {}).get("value"),
        "action": raw.get("EventType")    or raw.get("registry", {}).get("action"),
    }


def _parse_sysmon_hashes(hashes_str: str) -> dict[str, str]:
    result: dict[str, str] = {}
    if not hashes_str:
        return result
    for part in hashes_str.split(","):
        if "=" in part:
            k, _, v = part.partition("=")
            result[k.strip()] = v.strip()
    return result


def _to_int(val: object) -> int | None:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _is_machine_account(name: str | None) -> bool:
    """Windows computer/machine accounts end with '$' — they are not human users."""
    return bool(name and name.endswith("$"))


def _add_tag(base: NormalizedEvent, tag: str) -> None:
    """Append *tag* to base.tags only if not already present."""
    if tag not in base.tags:
        base.tags.append(tag)


def _replace_tag(base: NormalizedEvent, old: str, new: str) -> None:
    """Replace *old* tag with *new* in-place, preserving list position.
    Falls back to appending *new* if *old* is not found."""
    try:
        idx = base.tags.index(old)
        base.tags[idx] = new
    except ValueError:
        _add_tag(base, new)


def _apply_logon_type(raw: dict[str, Any], base: NormalizedEvent) -> None:
    """
    Extract the Windows LogonType numeric code, inject a descriptive
    ``logon:<type>`` tag, and escalate severity for high-risk session types
    when a non-local source IP is present.

    Called for EventIDs 4624 (success), 4625 (failure), and 4648 (explicit creds).

    Escalation rules
    ----------------
    - Type 8  (network-cleartext) → HIGH (3) always: credentials sent in plaintext.
    - Type 10 / 12 (RDP / cached-RDP) from external IP → MEDIUM (2) minimum.
    - Type 3 / 9  (network / new-credentials) from external IP → MEDIUM (2) minimum.
    """
    lt = str(raw.get("LogonType") or raw.get("Logon Type") or "").strip()
    name = _LOGON_TYPE_NAMES.get(lt)
    if not name:
        return

    _add_tag(base, f"logon:{name}")

    src_ip      = raw.get("IpAddress") or raw.get("source_ip") or ""
    is_external = bool(src_ip) and src_ip not in _LOCAL_IP_ADDRESSES

    if lt == "8" and base.severity < 3:
        # Cleartext credentials are always a concern regardless of source.
        base.severity = 3
    elif lt in _REMOTE_LOGON_TYPES and is_external and base.severity < 2:
        base.severity = 2
    elif lt in _NETWORK_LOGON_TYPES and lt != "8" and is_external and base.severity < 2:
        base.severity = 2


def _try_extract_src_ip(raw: dict[str, Any], base: NormalizedEvent) -> None:
    ip = raw.get("IpAddress") or raw.get("source_ip")
    if not ip or ip in _LOCAL_IP_ADDRESSES:
        return
    if base.network is None:
        base.network = NormalizedNetwork(src_ip=ip)
    elif base.network.src_ip is None:
        base.network.src_ip = ip


def _try_extract_firewall_network(raw: dict[str, Any], base: NormalizedEvent) -> None:
    """Populate network sub-object from Windows Firewall audit fields (5156/5157/5158/5159)."""
    src_ip = raw.get("SourceAddress") or raw.get("source_ip")
    dst_ip = raw.get("DestAddress")   or raw.get("dest_ip")
    if not src_ip and not dst_ip:
        return
    src_port = _to_int(raw.get("SourcePort"))
    dst_port = _to_int(raw.get("DestPort"))
    protocol = _PROTO_MAP.get(str(raw.get("Protocol", ""))) or raw.get("Protocol")
    if base.network is None:
        base.network = NormalizedNetwork(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
        )

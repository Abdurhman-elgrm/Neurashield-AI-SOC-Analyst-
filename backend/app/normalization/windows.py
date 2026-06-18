from __future__ import annotations

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


def normalize_windows_event(raw: dict[str, Any], base: NormalizedEvent) -> NormalizedEvent:
    """
    Maps Windows-specific event fields to the normalized schema.
    Handles Sysmon (EventID-based) and generic Windows Security Event Log formats.
    """
    event_id = raw.get("event_id_windows") or raw.get("EventID")

    # Persist Windows EventID into raw so the frontend can display human-readable descriptions
    if event_id:
        base.raw["windows_event_id"] = str(event_id)

    if base.process is None and (proc := raw.get("process") or raw.get("Image")):
        base.process = _extract_process_windows(raw, proc if isinstance(proc, dict) else {})

    if base.network is None and raw.get("network"):
        base.network = _extract_network_windows(raw.get("network", {}))

    if base.file is None and raw.get("file"):
        base.file = _extract_file_windows(raw.get("file", {}))

    if base.user is None:
        base.user = _extract_user_windows(raw)

    # Windows Sysmon process events
    if event_id in ("1", 1):  # Process Create
        base.category = "process"
        base.process = _extract_process_from_sysmon_create(raw)

    elif event_id in ("3", 3):  # Network Connect
        base.category = "network"
        base.network = _extract_network_from_sysmon(raw)

    elif event_id in ("11", 11):  # File Create
        base.category = "file"
        base.file = _extract_file_from_sysmon(raw)

    elif event_id in ("13", 13, "14", 14):  # Registry value set / renamed
        base.category = "registry"
        base.registry = _extract_registry_windows(raw)

    # WMI Activity — provider host started/failed
    elif event_id in ("5857", 5857):
        base.category = "process"
        provider = raw.get("ProviderName") or raw.get("NamespaceName")
        pid = _to_int(raw.get("ProcessID") or raw.get("HostingProcessId"))
        if provider:
            base.process = NormalizedProcess(name=provider, pid=pid)
        elif pid:
            base.process = NormalizedProcess(pid=pid)

    # Windows Security log — process creation
    elif event_id in ("4688", 4688):  # Process Create (Security log)
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

    # Windows Security log — auth events
    elif event_id in ("4624", 4624):  # Successful logon
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 1
        _try_extract_src_ip(raw, base)

    elif event_id in ("4625", 4625):  # Failed logon
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 2
        _try_extract_src_ip(raw, base)

    elif event_id in ("4648", 4648):  # Logon with explicit credentials
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 2
        _try_extract_src_ip(raw, base)

    elif event_id in ("4634", 4634):  # Logoff
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)

    elif event_id in ("4672", 4672):  # Special privileges assigned to new logon
        base.category = "auth"
        user = _extract_user_from_logon(raw)
        user.is_privileged = True  # 4672 IS the privileged logon event — always flag
        base.user = user
        base.severity = 2

    elif event_id in ("4698", 4698, "4702", 4702):  # Scheduled task created/updated
        base.category = "process"
        base.severity = 3

    elif event_id in ("4719", 4719):  # Audit policy changed
        base.category = "auth"
        base.severity = 3

    elif event_id in ("4720", 4720):  # User account created
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 2

    elif event_id in ("4728", 4728, "4732", 4732):  # User added to security group
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 2

    elif event_id in ("4768", 4768, "4769", 4769, "4776", 4776):  # Kerberos auth events
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)

    elif event_id in ("7045", 7045):  # Service installed
        base.category = "process"
        base.severity = 3

    elif event_id in ("1102", 1102):  # Audit log cleared
        base.category = "auth"
        base.severity = 4

    elif event_id in ("4104", 4104):  # PowerShell script block logged
        base.category = "process"
        base.severity = 3

    return base


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


_SYSTEM_ACCOUNTS = {"-", "", "system", "local service", "network service", "anonymous logon"}


def _extract_user_windows(raw: dict[str, Any]) -> NormalizedUser:
    user_raw = raw.get("user") or {}
    if not isinstance(user_raw, dict):
        user_raw = {}
    # TargetUserName is the acting account in security events (more useful than SubjectUserName)
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
    # Filter out noise: system/service accounts that don't represent real users
    if name and name.lower() in _SYSTEM_ACCOUNTS:
        name = None
    if name and "\\" in name:
        parts = name.split("\\", 1)
        domain = domain or parts[0]
        name = parts[1]
    return NormalizedUser(name=name, domain=domain, id=user_raw.get("id"))


def _extract_user_from_logon(raw: dict[str, Any]) -> NormalizedUser:
    return NormalizedUser(
        name=raw.get("TargetUserName") or raw.get("SubjectUserName"),
        domain=raw.get("TargetDomainName") or raw.get("SubjectDomainName"),
        id=raw.get("TargetUserSid"),
        is_privileged=raw.get("TargetUserName", "").upper() in ("ADMINISTRATOR", "SYSTEM"),
    )


def _extract_registry_windows(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "key": raw.get("TargetObject") or raw.get("registry", {}).get("key"),
        "value": raw.get("Details") or raw.get("registry", {}).get("value"),
        "action": raw.get("EventType") or raw.get("registry", {}).get("action"),
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


def _try_extract_src_ip(raw: dict[str, Any], base: NormalizedEvent) -> None:
    ip = raw.get("IpAddress") or raw.get("source_ip")
    if not ip or ip in ("-", "::1", "127.0.0.1", "0.0.0.0", ""):
        return
    if base.network is None:
        base.network = NormalizedNetwork(src_ip=ip)
    elif base.network.src_ip is None:
        base.network.src_ip = ip

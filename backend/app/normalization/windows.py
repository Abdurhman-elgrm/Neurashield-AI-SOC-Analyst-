from __future__ import annotations

from typing import Any

from app.normalization.models import (
    NormalizedEvent,
    NormalizedFile,
    NormalizedNetwork,
    NormalizedProcess,
    NormalizedUser,
)


def normalize_windows_event(raw: dict[str, Any], base: NormalizedEvent) -> NormalizedEvent:
    """
    Maps Windows-specific event fields to the normalized schema.
    Handles Sysmon (EventID-based) and generic Windows Security Event Log formats.
    """
    event_id = raw.get("event_id_windows") or raw.get("EventID")

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

    elif event_id in ("13", 13, "14", 14):  # Registry
        base.category = "registry"
        base.registry = _extract_registry_windows(raw)

    # Windows Security log
    elif event_id in ("4624", 4624, "4625", 4625):  # Logon success/failure
        base.category = "auth"
        base.user = _extract_user_from_logon(raw)
        base.severity = 1 if event_id in ("4624", 4624) else 2

    return base


def _extract_process_windows(raw: dict[str, Any], proc: dict[str, Any]) -> NormalizedProcess:
    return NormalizedProcess(
        pid=_to_int(proc.get("pid") or raw.get("ProcessId")),
        ppid=_to_int(proc.get("ppid") or raw.get("ParentProcessId")),
        name=proc.get("name") or raw.get("Image", "").split("\\")[-1],
        executable=proc.get("executable") or raw.get("Image"),
        command_line=proc.get("command_line") or raw.get("CommandLine"),
        user=proc.get("user") or raw.get("User"),
        hash_md5=proc.get("hash_md5") or raw.get("Hashes", {}).get("MD5") if isinstance(raw.get("Hashes"), dict) else None,
        hash_sha256=proc.get("hash_sha256") or raw.get("Hashes", {}).get("SHA256") if isinstance(raw.get("Hashes"), dict) else None,
    )


def _extract_process_from_sysmon_create(raw: dict[str, Any]) -> NormalizedProcess:
    hashes = _parse_sysmon_hashes(raw.get("Hashes", ""))
    image = raw.get("Image", "")
    return NormalizedProcess(
        pid=_to_int(raw.get("ProcessId")),
        ppid=_to_int(raw.get("ParentProcessId")),
        name=image.split("\\")[-1] if image else None,
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
    name = path.split("\\")[-1] if path else None
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
    name = f.get("name") or (path.split("\\")[-1] if path else None)
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
    name = user_raw.get("name") or raw.get("SubjectUserName") or raw.get("User")
    domain = user_raw.get("domain") or raw.get("SubjectDomainName")
    if name and domain and "\\" in name:
        parts = name.split("\\", 1)
        domain = parts[0]
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

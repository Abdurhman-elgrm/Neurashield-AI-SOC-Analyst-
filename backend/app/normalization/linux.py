from __future__ import annotations

from typing import Any

from app.normalization.models import (
    NormalizedEvent,
    NormalizedFile,
    NormalizedNetwork,
    NormalizedProcess,
    NormalizedUser,
)


def normalize_linux_event(raw: dict[str, Any], base: NormalizedEvent) -> NormalizedEvent:
    """
    Maps Linux-specific event fields to the normalized schema.
    Handles auditd, syslog, and generic Linux agent formats.
    """
    syscall = raw.get("syscall") or raw.get("type")

    if base.process is None:
        base.process = _extract_process_linux(raw)

    if base.network is None and raw.get("network"):
        base.network = _extract_network_linux(raw.get("network", {}))

    if base.file is None and raw.get("file"):
        base.file = _extract_file_linux(raw.get("file", {}))

    if base.user is None:
        base.user = _extract_user_linux(raw)

    # Auditd-specific mapping
    if syscall == "execve":
        base.category = "process"
        base.process = _extract_process_from_execve(raw)

    elif syscall in ("connect", "accept", "bind"):
        base.category = "network"
        if not base.network:
            base.network = _extract_network_from_auditd(raw)

    elif syscall in ("open", "openat", "creat", "unlink", "rename"):
        base.category = "file"
        if not base.file:
            base.file = _extract_file_from_auditd(raw)

    elif syscall in ("setuid", "setgid") or raw.get("category") == "auth":
        base.category = "auth"
        if raw.get("res") == "failed":
            base.severity = 2

    return base


def _extract_process_linux(raw: dict[str, Any]) -> NormalizedProcess:
    proc = raw.get("process") or {}
    if not isinstance(proc, dict):
        proc = {}
    exe = proc.get("executable") or raw.get("exe") or raw.get("comm")
    return NormalizedProcess(
        pid=_to_int(proc.get("pid") or raw.get("pid")),
        ppid=_to_int(proc.get("ppid") or raw.get("ppid")),
        name=proc.get("name") or (exe.split("/")[-1] if exe else None),
        executable=proc.get("executable") or raw.get("exe"),
        command_line=proc.get("command_line") or raw.get("cmdline") or raw.get("proctitle"),
        user=proc.get("user") or raw.get("auid"),
        hash_md5=proc.get("hash_md5"),
        hash_sha256=proc.get("hash_sha256"),
    )


def _extract_process_from_execve(raw: dict[str, Any]) -> NormalizedProcess:
    exe = raw.get("exe") or raw.get("a0", "")
    args = [raw.get(f"a{i}") for i in range(4) if raw.get(f"a{i}")]
    return NormalizedProcess(
        pid=_to_int(raw.get("pid")),
        ppid=_to_int(raw.get("ppid")),
        name=exe.split("/")[-1] if exe else None,
        executable=exe or None,
        command_line=" ".join(str(a) for a in args) if args else None,
        user=raw.get("auid") or raw.get("uid"),
    )


def _extract_network_linux(net: dict[str, Any]) -> NormalizedNetwork:
    return NormalizedNetwork(
        src_ip=net.get("src_ip") or net.get("laddr"),
        src_port=_to_int(net.get("src_port") or net.get("lport")),
        dst_ip=net.get("dst_ip") or net.get("faddr"),
        dst_port=_to_int(net.get("dst_port") or net.get("fport")),
        protocol=net.get("protocol"),
    )


def _extract_network_from_auditd(raw: dict[str, Any]) -> NormalizedNetwork:
    return NormalizedNetwork(
        src_ip=raw.get("laddr"),
        src_port=_to_int(raw.get("lport")),
        dst_ip=raw.get("faddr"),
        dst_port=_to_int(raw.get("fport")),
        protocol=raw.get("ipver"),
    )


def _extract_file_linux(f: dict[str, Any]) -> NormalizedFile:
    path = f.get("path") or f.get("name", "")
    name = f.get("name") or (path.split("/")[-1] if path else None)
    ext = name.rsplit(".", 1)[-1] if name and "." in name else None
    return NormalizedFile(
        path=path or None,
        name=name,
        extension=ext,
        size=_to_int(f.get("size")),
        hash_md5=f.get("hash_md5"),
        hash_sha256=f.get("hash_sha256"),
        action=f.get("action"),
    )


def _extract_file_from_auditd(raw: dict[str, Any]) -> NormalizedFile:
    path = raw.get("name") or raw.get("path", "")
    name = path.split("/")[-1] if path else None
    ext = name.rsplit(".", 1)[-1] if name and "." in name else None
    return NormalizedFile(path=path or None, name=name, extension=ext)


def _extract_user_linux(raw: dict[str, Any]) -> NormalizedUser:
    user_raw = raw.get("user") or {}
    if not isinstance(user_raw, dict):
        user_raw = {}
    name = user_raw.get("name") or raw.get("uid") or raw.get("auid")
    uid_val = user_raw.get("id") or raw.get("uid")
    is_priv = uid_val in ("0", 0) or name in ("root",)
    return NormalizedUser(name=str(name) if name else None, id=str(uid_val) if uid_val else None, is_privileged=bool(is_priv))


def _to_int(val: object) -> int | None:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None

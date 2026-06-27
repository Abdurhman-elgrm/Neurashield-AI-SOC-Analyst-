"""
Linux / Unix event normalizer.

Dispatches on two orthogonal axes:
  1. syslog program name (sshd, sudo, su, cron, kernel, systemd, …)
  2. auditd syscall type   (execve, connect, open, setuid, …)

For each program / syscall a dedicated handler enriches the base
NormalizedEvent and returns it.  Callers never see partial objects.

Supported sources
-----------------
  Syslog (rsyslog / journald):
    - sshd    — password/publickey auth, session open/close, invalid-user
    - sudo    — privileged command execution and failures
    - su      — session open/close and auth failures
    - cron / crond — job execution
    - useradd / userdel / usermod — account lifecycle
    - passwd  — password change events
    - systemd-logind — session management
    - kernel  — module loading, OOM, panic messages

  auditd (structured key=value or pre-parsed dicts):
    - execve  — process execution
    - connect / accept / bind — network activity
    - open / openat / creat / unlink / rename — file activity
    - setuid / setgid — privilege change
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from app.normalization.models import (
    NormalizedEvent,
    NormalizedFile,
    NormalizedNetwork,
    NormalizedProcess,
    NormalizedUser,
)

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Program → default category / severity floor
# ─────────────────────────────────────────────────────────────────────────────

_PROGRAM_CATEGORY: dict[str, str] = {
    "sshd": "auth",
    "sudo": "auth",
    "su": "auth",
    "login": "auth",
    "passwd": "auth",
    "useradd": "auth",
    "userdel": "auth",
    "usermod": "auth",
    "chpasswd": "auth",
    "newusers": "auth",
    "cron": "process",
    "crond": "process",
    "at": "process",
    "atd": "process",
    "kernel": "other",
    "systemd": "other",
    "systemd-logind": "auth",
    "systemd-modules-load": "other",
    "insmod": "process",
    "modprobe": "process",
    "rmmod": "process",
    "auditd": "other",
    "rsyslogd": "other",
    "sshguard": "auth",
    "fail2ban": "auth",
    "pam_unix": "auth",
    "pam_tally2": "auth",
    "pam_faillock": "auth",
    "gdm": "auth",
    "gdm-password": "auth",
    "lightdm": "auth",
    "xdm": "auth",
    "httpd": "network",
    "nginx": "network",
    "apache2": "network",
}

# Minimum severity a program always emits (1 = low, 4 = critical)
_PROGRAM_SEVERITY_FLOOR: dict[str, int] = {
    "sudo": 2,
    "su": 2,
    "useradd": 2,
    "userdel": 2,
    "usermod": 2,
    "chpasswd": 2,
    "newusers": 2,
    "insmod": 3,
    "modprobe": 3,
    "rmmod": 3,
    "systemd-modules-load": 3,
}

# syslog severity names → internal severity (1–4)
_SYSLOG_SEVERITY: dict[str, int] = {
    "emerg": 4,
    "alert": 4,
    "crit": 4,
    "err": 3,
    "error": 3,
    "warning": 3,
    "warn": 3,
    "notice": 2,
    "info": 1,
    "debug": 1,
    "0": 4,
    "1": 4,
    "2": 4,
    "3": 3,
    "4": 3,
    "5": 2,
    "6": 1,
    "7": 1,
}


# ─────────────────────────────────────────────────────────────────────────────
# Compiled regex patterns
# ─────────────────────────────────────────────────────────────────────────────

# sshd
_RE_SSH_ACCEPTED = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)",
    re.IGNORECASE,
)
_RE_SSH_FAILED = re.compile(
    r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)",
    re.IGNORECASE,
)
_RE_SSH_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE,
)
_RE_SSH_DISCONNECT = re.compile(
    r"Disconnected from (?:authenticating |invalid )?user (?P<user>\S+) (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)",
    re.IGNORECASE,
)
_RE_SSH_SESSION_OPEN = re.compile(
    r"session opened for user (?P<user>\S+)",
    re.IGNORECASE,
)
_RE_SSH_SESSION_CLOSE = re.compile(
    r"session closed for user (?P<user>\S+)",
    re.IGNORECASE,
)
_RE_SSH_TOO_MANY_AUTH = re.compile(
    r"Disconnecting.*too many authentication failures",
    re.IGNORECASE,
)

# sudo
_RE_SUDO_CMD = re.compile(
    r"(?P<user>\S+)\s*:\s*(?:TTY=\S+\s*;\s*)?PWD=\S+\s*;\s*USER=(?P<run_as>\S+)\s*;\s*COMMAND=(?P<cmd>.+)",
)
_RE_SUDO_FAIL = re.compile(
    r"(?P<user>\S+)\s*:\s*(?:command not allowed|authentication failure|3 incorrect password)",
    re.IGNORECASE,
)
_RE_SUDO_SESSION_OPEN = re.compile(
    r"pam_unix\(sudo:session\).*session opened for user (?P<user>\S+)",
    re.IGNORECASE,
)

# su
_RE_SU_SUCCESS = re.compile(
    r"Successful su for (?P<user>\S+) by (?P<by>\S+)",
    re.IGNORECASE,
)
_RE_SU_FAIL = re.compile(
    r"FAILED SU .* for (?P<user>\S+) by (?P<by>\S+)",
    re.IGNORECASE,
)
_RE_SU_SESSION = re.compile(
    r"pam_unix\(su.*\).*session (?P<action>opened|closed) for user (?P<user>\S+)",
    re.IGNORECASE,
)

# cron
_RE_CRON_CMD = re.compile(
    r"\((?P<user>[^)]+)\)\s+CMD\s+\((?P<cmd>.+)\)",
)
_RE_CRON_SESSION = re.compile(
    r"pam_unix\(cron:session\).*session (?P<action>opened|closed) for user (?P<user>\S+)",
    re.IGNORECASE,
)

# kernel module
_RE_KERNEL_MODULE = re.compile(
    r"(?:Loading module|insmod|modprobe)\s+(?P<module>\S+)",
    re.IGNORECASE,
)

# systemd-logind
_RE_LOGIND_NEW_SESSION = re.compile(
    r"New session (?P<sid>\S+) of user (?P<user>\S+)",
    re.IGNORECASE,
)
_RE_LOGIND_REMOVED_SESSION = re.compile(
    r"Removed session (?P<sid>\S+)",
    re.IGNORECASE,
)

# PAM generic
_RE_PAM_AUTH_FAIL = re.compile(
    r"pam_unix\((?P<service>[^:]+):auth\).*authentication failure.*user=(?P<user>\S+)",
    re.IGNORECASE,
)
_RE_PAM_SESSION_OPEN = re.compile(
    r"pam_unix\((?P<service>[^:]+):session\).*session opened for user (?P<user>\S+)",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────


def normalize_linux_event(raw: dict[str, Any], base: NormalizedEvent) -> NormalizedEvent:
    """
    Maps Linux-specific event fields onto the NormalizedEvent schema.
    Handles: syslog (via program field), auditd (via syscall/type field),
    and structured agent-forwarded events.
    """
    program = _get_program(raw)
    message = raw.get("message") or raw.get("msg") or ""
    syscall = raw.get("syscall") or raw.get("type")
    syslog_sev = raw.get("syslog_severity") or raw.get("priority") or ""

    # ── Apply program-level defaults ──────────────────────────────────────
    if program in _PROGRAM_CATEGORY:
        base.category = _PROGRAM_CATEGORY[program]

    sev_floor = _PROGRAM_SEVERITY_FLOOR.get(program, 0)
    if sev_floor:
        base.severity = max(base.severity, sev_floor)

    if syslog_sev:
        mapped = _SYSLOG_SEVERITY.get(str(syslog_sev).lower())
        if mapped:
            base.severity = max(base.severity, mapped)

    # ── Extract common fields from structured sub-dicts ───────────────────
    if base.user is None:
        base.user = _extract_user_linux(raw)

    if base.process is None:
        base.process = _extract_process_linux(raw, program)

    if base.network is None and raw.get("network"):
        base.network = _extract_network_linux(raw["network"])

    if base.file is None and raw.get("file"):
        base.file = _extract_file_linux(raw["file"])

    # ── Program-specific message parsing ─────────────────────────────────
    if program == "sshd":
        _handle_sshd(message, base, raw)

    elif program == "sudo":
        _handle_sudo(message, base, raw)

    elif program == "su":
        _handle_su(message, base, raw)

    elif program in ("cron", "crond", "at", "atd"):
        _handle_cron(message, base, raw)

    elif program in ("useradd", "userdel", "usermod", "chpasswd", "newusers"):
        _handle_account_management(program, message, base, raw)

    elif program in ("insmod", "modprobe", "rmmod", "systemd-modules-load"):
        _handle_kernel_module(message, base, raw)

    elif program in ("systemd", "systemd-logind"):
        _handle_systemd_logind(message, base, raw)

    elif message and ("pam_unix" in message or "pam_tally" in message):
        _handle_pam_message(message, base, raw)

    # ── auditd syscall dispatch ───────────────────────────────────────────
    elif syscall:
        _handle_auditd_syscall(str(syscall), raw, base)

    # ── Generic message keyword scan ─────────────────────────────────────
    elif message:
        _handle_generic_keywords(message, base)

    # Store the program name for rule matching (raw.program in patterns)
    if program:
        base.raw.setdefault("program", program)

    return base


# ─────────────────────────────────────────────────────────────────────────────
# Program-specific handlers
# ─────────────────────────────────────────────────────────────────────────────


def _handle_sshd(message: str, base: NormalizedEvent, raw: dict[str, Any]) -> None:
    base.category = "auth"

    m = _RE_SSH_ACCEPTED.search(message)
    if m:
        base.user = _merge_user(base.user, NormalizedUser(name=m.group("user")))
        base.network = NormalizedNetwork(
            src_ip=m.group("ip"),
            src_port=_to_int(m.group("port")),
            protocol="tcp",
        )
        base.raw["outcome"] = "success"
        base.raw["auth_method"] = m.group("method")
        base.severity = max(base.severity, 1)
        return

    m = _RE_SSH_INVALID_USER.search(message)
    if m:
        base.user = _merge_user(base.user, NormalizedUser(name=m.group("user")))
        base.network = NormalizedNetwork(
            src_ip=m.group("ip"),
            src_port=_to_int(m.group("port")) if m.group("port") else None,
            protocol="tcp",
        )
        base.raw["outcome"] = "failure"
        base.raw["invalid_user"] = True
        base.severity = max(base.severity, 2)
        return

    m = _RE_SSH_FAILED.search(message)
    if m:
        base.user = _merge_user(base.user, NormalizedUser(name=m.group("user")))
        base.network = NormalizedNetwork(
            src_ip=m.group("ip"),
            src_port=_to_int(m.group("port")),
            protocol="tcp",
        )
        base.raw["outcome"] = "failure"
        base.raw["auth_method"] = m.group("method")
        base.severity = max(base.severity, 2)
        return

    m = _RE_SSH_TOO_MANY_AUTH.search(message)
    if m:
        base.raw["outcome"] = "failure"
        base.severity = max(base.severity, 2)
        return

    m = _RE_SSH_SESSION_OPEN.search(message)
    if m:
        base.user = _merge_user(base.user, NormalizedUser(name=m.group("user")))
        base.raw["outcome"] = "success"
        base.raw["action"] = "session_open"
        return

    m = _RE_SSH_SESSION_CLOSE.search(message)
    if m:
        base.user = _merge_user(base.user, NormalizedUser(name=m.group("user")))
        base.raw["action"] = "session_close"
        return

    m = _RE_SSH_DISCONNECT.search(message)
    if m:
        base.user = _merge_user(base.user, NormalizedUser(name=m.group("user")))
        base.network = NormalizedNetwork(
            src_ip=m.group("ip"),
            src_port=_to_int(m.group("port")),
        )
        base.raw["action"] = "disconnect"


def _handle_sudo(message: str, base: NormalizedEvent, raw: dict[str, Any]) -> None:
    base.category = "auth"
    base.severity = max(base.severity, 2)

    m = _RE_SUDO_CMD.search(message)
    if m:
        user = m.group("user")
        run_as = m.group("run_as")
        cmd = m.group("cmd").strip()
        base.user = NormalizedUser(
            name=user,
            is_privileged=(run_as.lower() == "root"),
        )
        base.process = NormalizedProcess(
            command_line=cmd,
            name=cmd.split()[0].split("/")[-1] if cmd else None,
            user=run_as,
        )
        base.raw["outcome"] = "success"
        base.raw["sudo_run_as"] = run_as
        # Shell escalation is more severe than running a single command
        if cmd.split()[0].split("/")[-1] in ("bash", "sh", "zsh", "fish", "dash"):
            base.severity = max(base.severity, 3)
        return

    m = _RE_SUDO_FAIL.search(message)
    if m:
        base.user = NormalizedUser(name=m.group("user"))
        base.raw["outcome"] = "failure"
        base.severity = max(base.severity, 2)


def _handle_su(message: str, base: NormalizedEvent, raw: dict[str, Any]) -> None:
    base.category = "auth"
    base.severity = max(base.severity, 2)

    m = _RE_SU_SUCCESS.search(message)
    if m:
        base.user = NormalizedUser(
            name=m.group("by"),
            is_privileged=(m.group("user").lower() == "root"),
        )
        base.raw["outcome"] = "success"
        base.raw["su_target_user"] = m.group("user")
        return

    m = _RE_SU_FAIL.search(message)
    if m:
        base.user = NormalizedUser(name=m.group("by"))
        base.raw["outcome"] = "failure"
        base.raw["su_target_user"] = m.group("user")
        return

    m = _RE_SU_SESSION.search(message)
    if m:
        base.user = NormalizedUser(
            name=m.group("user"),
            is_privileged=(m.group("user").lower() == "root"),
        )
        base.raw["action"] = f"session_{m.group('action')}"


def _handle_cron(message: str, base: NormalizedEvent, raw: dict[str, Any]) -> None:
    base.category = "process"

    m = _RE_CRON_CMD.search(message)
    if m:
        user = m.group("user")
        cmd = m.group("cmd").strip()
        base.user = NormalizedUser(name=user, is_privileged=(user.lower() == "root"))
        base.process = NormalizedProcess(
            command_line=cmd,
            name=cmd.split()[0].split("/")[-1] if cmd else None,
            user=user,
        )
        base.raw["action"] = "cron_cmd"
        # Cron jobs that reach out to the network are suspicious
        if re.search(r"\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|\bbash\s+-i\b", cmd):
            base.severity = max(base.severity, 3)
        return

    m = _RE_CRON_SESSION.search(message)
    if m:
        base.user = NormalizedUser(name=m.group("user"))
        base.raw["action"] = f"session_{m.group('action')}"


def _handle_account_management(
    program: str, message: str, base: NormalizedEvent, raw: dict[str, Any]
) -> None:
    base.category = "auth"
    base.severity = max(base.severity, 2)

    # Extract the subject from common patterns: "new user: name=alice, …"
    m = re.search(r"(?:new user|user).*name=(?P<user>\S+)", message, re.IGNORECASE)
    if m:
        base.user = NormalizedUser(name=m.group("user").rstrip(","))

    action_map = {
        "useradd": "account_created",
        "userdel": "account_deleted",
        "usermod": "account_modified",
        "chpasswd": "password_changed",
        "newusers": "accounts_created_bulk",
    }
    base.raw["action"] = action_map.get(program, program)


def _handle_kernel_module(message: str, base: NormalizedEvent, raw: dict[str, Any]) -> None:
    base.category = "process"
    base.severity = max(base.severity, 3)

    m = _RE_KERNEL_MODULE.search(message)
    module_name = m.group("module") if m else (message.strip() or None)
    base.process = NormalizedProcess(
        name=module_name,
        executable=f"/lib/modules/{module_name}" if module_name else None,
        command_line=message.strip() or None,
    )
    base.raw["action"] = "kernel_module_load"
    base.raw["module_name"] = module_name

    # Modules with no obvious legitimate name or loaded outside maintenance windows
    # are potentially rootkits — escalate to critical.
    if module_name and re.search(r"^\w{1,6}$", module_name):
        # Very short/opaque module name — suspicious
        base.severity = max(base.severity, 4)


def _handle_systemd_logind(message: str, base: NormalizedEvent, raw: dict[str, Any]) -> None:
    base.category = "auth"

    m = _RE_LOGIND_NEW_SESSION.search(message)
    if m:
        base.user = NormalizedUser(name=m.group("user"))
        base.raw["action"] = "session_open"
        base.raw["session_id"] = m.group("sid")
        return

    m = _RE_LOGIND_REMOVED_SESSION.search(message)
    if m:
        base.raw["action"] = "session_close"
        base.raw["session_id"] = m.group("sid")


def _handle_pam_message(message: str, base: NormalizedEvent, raw: dict[str, Any]) -> None:
    m = _RE_PAM_AUTH_FAIL.search(message)
    if m:
        base.category = "auth"
        base.user = NormalizedUser(name=m.group("user"))
        base.raw["outcome"] = "failure"
        base.raw["pam_service"] = m.group("service")
        base.severity = max(base.severity, 2)
        return

    m = _RE_PAM_SESSION_OPEN.search(message)
    if m:
        base.category = "auth"
        base.user = NormalizedUser(name=m.group("user"))
        base.raw["outcome"] = "success"
        base.raw["pam_service"] = m.group("service")


def _handle_generic_keywords(message: str, base: NormalizedEvent) -> None:
    lower = message.lower()
    if any(w in lower for w in ("error", "failed", "failure", "denied", "refused")):
        base.severity = max(base.severity, 2)
    if any(w in lower for w in ("critical", "emergency", "panic", "exploit")):
        base.severity = max(base.severity, 4)
    if any(w in lower for w in ("warning", "warn")):
        base.severity = max(base.severity, 2)


# ─────────────────────────────────────────────────────────────────────────────
# auditd syscall handler
# ─────────────────────────────────────────────────────────────────────────────


def _handle_auditd_syscall(syscall: str, raw: dict[str, Any], base: NormalizedEvent) -> None:
    if syscall == "execve":
        base.category = "process"
        base.process = _extract_process_from_execve(raw)

    elif syscall in ("connect", "accept", "bind"):
        base.category = "network"
        if base.network is None:
            base.network = _extract_network_from_auditd(raw)

    elif syscall in ("open", "openat", "creat", "unlink", "rename", "unlinkat"):
        base.category = "file"
        if base.file is None:
            base.file = _extract_file_from_auditd(raw)

    elif syscall in ("setuid", "setgid", "setreuid", "setresuid"):
        base.category = "auth"
        if raw.get("res") in ("failed", "0xffffffff"):
            base.severity = max(base.severity, 2)

    elif syscall in ("init_module", "finit_module"):
        base.category = "process"
        base.severity = max(base.severity, 3)
        base.raw["action"] = "kernel_module_load"

    elif syscall == "ptrace":
        # ptrace is used by debuggers but also by credential dumpers
        base.category = "process"
        base.severity = max(base.severity, 2)

    if raw.get("res") in ("failed", "0xffffffff", "-1"):
        base.raw["outcome"] = "failure"
    elif raw.get("res") == "success":
        base.raw["outcome"] = "success"


# ─────────────────────────────────────────────────────────────────────────────
# Field extractors
# ─────────────────────────────────────────────────────────────────────────────


def _get_program(raw: dict[str, Any]) -> str:
    """Returns the normalized program name (lowercase, path stripped)."""
    prog = (
        raw.get("program") or raw.get("process_name") or raw.get("ident") or raw.get("comm") or ""
    )
    return prog.split("/")[-1].lower()


def _extract_user_linux(raw: dict[str, Any]) -> NormalizedUser:
    user_sub = raw.get("user") or {}
    if not isinstance(user_sub, dict):
        user_sub = {}

    # Prefer human-readable name over numeric uid
    name = (
        user_sub.get("name")
        or raw.get("username")
        or raw.get("user_name")
        or raw.get("acct")  # auditd USER_LOGIN record
    )
    uid_val = user_sub.get("id") or raw.get("uid")

    # auid == 4294967295 (0xFFFFFFFF) means "not associated with any user" in auditd
    auid = raw.get("auid")
    if name is None and auid and str(auid) != "4294967295":
        name = str(auid)

    is_priv = uid_val in ("0", 0) or str(name or "").lower() == "root"

    return NormalizedUser(
        name=str(name) if name else None,
        id=str(uid_val) if uid_val is not None else None,
        is_privileged=bool(is_priv),
    )


def _extract_process_linux(raw: dict[str, Any], program: str = "") -> NormalizedProcess:
    proc = raw.get("process") or {}
    if not isinstance(proc, dict):
        proc = {}
    exe = proc.get("executable") or raw.get("exe") or raw.get("comm")
    name = proc.get("name") or (exe.split("/")[-1] if exe else program or None)
    return NormalizedProcess(
        pid=_to_int(proc.get("pid") or raw.get("pid")),
        ppid=_to_int(proc.get("ppid") or raw.get("ppid")),
        name=name,
        executable=exe or None,
        command_line=proc.get("command_line") or raw.get("cmdline") or raw.get("proctitle"),
        user=str(raw.get("auid") or raw.get("uid") or ""),
    )


def _extract_process_from_execve(raw: dict[str, Any]) -> NormalizedProcess:
    exe = raw.get("exe") or raw.get("a0", "")
    args = [raw.get(f"a{i}") for i in range(8) if raw.get(f"a{i}")]
    return NormalizedProcess(
        pid=_to_int(raw.get("pid")),
        ppid=_to_int(raw.get("ppid")),
        name=exe.split("/")[-1] if exe else None,
        executable=exe or None,
        command_line=" ".join(str(a) for a in args) if args else None,
        user=str(raw.get("auid") or raw.get("uid") or ""),
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
        protocol=raw.get("ipver") or "tcp",
    )


def _extract_file_linux(f: dict[str, Any]) -> NormalizedFile:
    path = f.get("path") or f.get("name") or ""
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
    path = raw.get("name") or raw.get("path") or ""
    name = path.split("/")[-1] if path else None
    ext = name.rsplit(".", 1)[-1] if name and "." in name else None
    return NormalizedFile(path=path or None, name=name, extension=ext)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _merge_user(existing: NormalizedUser | None, override: NormalizedUser) -> NormalizedUser:
    """
    Merges structured user data (id, domain) from a pre-extracted user into
    the override produced by message parsing.  Message-parsed fields (name,
    is_privileged) win; structured fields (id) fill in any gaps.
    """
    if existing is None:
        return override
    return NormalizedUser(
        name=override.name or existing.name,
        domain=override.domain or existing.domain,
        id=override.id or existing.id,
        is_privileged=override.is_privileged or existing.is_privileged,
    )


def _to_int(val: object) -> int | None:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None

#!/usr/bin/env python3
"""
SOC Analyst Agent Installer — v2
Exchanges the one-time installer token for permanent runtime credentials,
copies agent files, and prepares the service entry point.

Called by bootstrap.ps1 BEFORE the Windows service is registered.
The service installer (service.py install) is called by bootstrap.ps1 afterwards.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path

# Make the soc_agent package importable when running from the extracted directory
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

from soc_agent.enrollment import bootstrap_enroll, EnrollmentError
from soc_agent.credential_store import store_credentials
from soc_agent.log_manager import setup_installer_logging
from soc_agent.config import write_config

# ─── Default paths (can be overridden via --install-dir) ─────────────────────

DEFAULT_INSTALL_DIR = Path("C:\\ProgramData\\SOCAnalyst") if platform.system() == "Windows" \
    else Path("/opt/soc-analyst")

AGENT_VERSION = "2.0.0"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SOC Analyst Agent Installer v2")
    p.add_argument("--token",       required=True,  help="One-time installer token")
    p.add_argument("--tenant-id",   required=True,  help="Tenant UUID")
    p.add_argument("--api-url",     required=True,  help="SOC Platform API base URL")
    p.add_argument("--install-dir", default=str(DEFAULT_INSTALL_DIR),
                   help="Installation directory")
    p.add_argument("--hostname",    default=socket.gethostname(),
                   help="Machine hostname (defaults to system hostname)")
    p.add_argument("--os-type",     default=_detect_os_type(),
                   choices=["windows", "linux", "macos"])
    p.add_argument("--ip-address",  default=_get_ip_address())
    p.add_argument("--force",       action="store_true",
                   help="Allow reinstall over an existing installation")
    return p.parse_args()


def _detect_os_type() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "macos"
    return "linux"


def _get_ip_address() -> str:
    try:
        # Connect to a public address to discover local IP (no actual packet sent)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


# ─── Directory helpers ────────────────────────────────────────────────────────

def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def _is_reinstall(install_dir: Path) -> bool:
    return (install_dir / "credentials" / "runtime.dat").exists()


def _check_not_running(log: "logging.Logger") -> None:
    """On Windows: verify the service is stopped before overwriting files."""
    if platform.system() != "Windows":
        return
    try:
        result = subprocess.run(
            ["sc", "query", "SOCAnalystAgent"],
            capture_output=True, text=True, timeout=10,
        )
        if "RUNNING" in result.stdout:
            log.warning("install_over_running_service",
                        hint="Run: Stop-Service SOCAnalystAgent first")
    except Exception:
        pass


# ─── File copy ────────────────────────────────────────────────────────────────

def copy_agent_files(src_dir: Path, install_dir: Path, log: "logging.Logger") -> None:
    """Copy agent runtime files from the extracted package to install_dir/bin."""
    bin_dir = install_dir / "bin"
    ensure_dir(bin_dir)

    agent_files = [
        "soc_agent/__init__.py",
        "soc_agent/config.py",
        "soc_agent/credential_store.py",
        "soc_agent/enrollment.py",
        "soc_agent/log_manager.py",
        "soc_agent/service.py",
        "requirements.txt",
    ]

    for rel in agent_files:
        src = src_dir / rel
        if not src.exists():
            log.warning("agent_file_missing", path=str(src))
            continue
        dst_parent = bin_dir / Path(rel).parent
        ensure_dir(dst_parent)
        shutil.copy2(src, bin_dir / rel)
        log.info("file_copied", src=str(src), dst=str(bin_dir / rel))

    # Make service.py executable on POSIX
    if platform.system() != "Windows":
        svc = bin_dir / "soc_agent" / "service.py"
        if svc.exists():
            svc.chmod(svc.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    log.info("agent_files_installed", bin_dir=str(bin_dir))


# ─── State file helpers ───────────────────────────────────────────────────────

def _write_install_state(install_dir: Path, meta: dict) -> None:
    state_file = install_dir / "state" / "install.json"
    with open(state_file, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, default=str)


def _read_install_state(install_dir: Path) -> dict:
    state_file = install_dir / "state" / "install.json"
    if not state_file.exists():
        return {}
    try:
        with open(state_file, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


# ─── Main install flow ────────────────────────────────────────────────────────

def main() -> None:
    import logging

    args = parse_args()
    install_dir = Path(args.install_dir)

    # Logging must come online before anything else
    log_dir = install_dir / "logs"
    ensure_dir(log_dir)
    log = setup_installer_logging(log_dir)
    log = log.bind(phase="install", hostname=args.hostname, tenant_id=args.tenant_id)

    log.info("installer_started", version=AGENT_VERSION, os=args.os_type,
             install_dir=str(install_dir))

    # Detect reinstall
    is_reinstall = _is_reinstall(install_dir)
    if is_reinstall and not args.force:
        prev_state = _read_install_state(install_dir)
        log.info(
            "reinstall_detected",
            previous_agent_id=prev_state.get("agent_id", "unknown"),
            hint="Re-enrolling with new installer token",
        )

    _check_not_running(log)

    # ── Step A: Create directory structure ────────────────────────────────────
    for sub in ("bin", "config", "credentials", "logs", "state", "tmp"):
        ensure_dir(install_dir / sub)
    log.info("directories_created", root=str(install_dir))

    # ── Step B: Bootstrap enrollment — exchange installer token for creds ─────
    log.info("enrollment_starting", api_url=args.api_url)
    try:
        creds = bootstrap_enroll(
            api_url=args.api_url,
            tenant_id=args.tenant_id,
            installer_token=args.token,
            machine_info={
                "hostname":      args.hostname,
                "os_type":       args.os_type,
                "ip_address":    args.ip_address,
                "agent_version": AGENT_VERSION,
            },
        )
    except EnrollmentError as exc:
        log.error("enrollment_failed", error=str(exc))
        # Do NOT store the raw token — exit with failure
        sys.exit(f"Enrollment failed: {exc}")
    except Exception as exc:
        log.error("enrollment_unexpected_error", error=str(exc), exc_info=True)
        sys.exit(f"Unexpected enrollment error: {exc}")

    log.info("enrollment_successful", agent_id=str(creds.agent_id))

    # ── Step C: Store runtime credentials via DPAPI ───────────────────────────
    cred_path = install_dir / "credentials" / "runtime.dat"
    log.info("storing_credentials", path=str(cred_path))
    try:
        store_credentials(
            creds=creds,
            path=cred_path,
        )
    except Exception as exc:
        log.error("credential_storage_failed", error=str(exc))
        sys.exit(f"Failed to store credentials: {exc}")

    log.info("credentials_stored")

    # ── Step D: Write agent config ────────────────────────────────────────────
    config_path = install_dir / "config" / "agent.ini"
    write_config(
        path=config_path,
        api_url=args.api_url,
        install_dir=str(install_dir),
        log_level="INFO",
    )
    log.info("config_written", path=str(config_path))

    # ── Step E: Copy agent files from extracted package ───────────────────────
    copy_agent_files(src_dir=_HERE, install_dir=install_dir, log=log)

    # ── Step F: Write install state manifest ─────────────────────────────────
    import datetime
    _write_install_state(install_dir, {
        "agent_id":         str(creds.agent_id),
        "tenant_id":        str(creds.tenant_id),
        "api_url":          args.api_url,
        "installer_version": AGENT_VERSION,
        "installed_at":     datetime.datetime.utcnow().isoformat() + "Z",
        "hostname":         args.hostname,
        "os_type":          args.os_type,
        "is_reinstall":     is_reinstall,
    })

    log.info(
        "install_complete",
        agent_id=str(creds.agent_id),
        install_dir=str(install_dir),
        config=str(config_path),
        credentials=str(cred_path),
    )

    # Print a summary for bootstrap.ps1 to display
    print(f"[INSTALL OK] agent_id={creds.agent_id} tenant={creds.tenant_id}")


if __name__ == "__main__":
    main()

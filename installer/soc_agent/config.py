"""Agent configuration management using a simple INI file."""
from __future__ import annotations

import configparser
from pathlib import Path


_DEFAULTS = {
    "heartbeat_interval_secs": "20",
    "log_collection_interval_secs": "10",
    "network_scan_interval_secs": "300",
    "process_scan_interval_secs": "300",
    "fim_interval_secs": "600",
    "log_level": "INFO",
    "log_max_bytes": str(10 * 1024 * 1024),
    "log_backup_count": "5",
    "request_timeout_secs": "30",
    "batch_size": "20",
    "max_queue_size": "10000",
}


def write_config(path: Path, api_url: str, install_dir: str, log_level: str = "INFO") -> None:
    cfg = configparser.ConfigParser()
    cfg["agent"] = {
        **_DEFAULTS,
        "api_url":     api_url,
        "install_dir": install_dir,
        "log_level":   log_level,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        cfg.write(fh)


def read_config(path: Path) -> configparser.SectionProxy:
    cfg = configparser.ConfigParser(defaults=_DEFAULTS)
    if path.exists():
        cfg.read(str(path), encoding="utf-8")
    if not cfg.has_section("agent"):
        cfg.add_section("agent")
    return cfg["agent"]


def locate_config(install_dir: Path | None = None) -> Path:
    if install_dir:
        return Path(install_dir) / "config" / "agent.ini"
    import platform
    base = "C:\\ProgramData\\SOCAnalyst" if platform.system() == "Windows" else "/opt/soc-analyst"
    return Path(base) / "config" / "agent.ini"

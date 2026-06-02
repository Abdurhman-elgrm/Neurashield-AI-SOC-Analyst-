"""
Structured JSON logging with automatic log rotation.
Used by both the installer and the Windows service.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOG_MAX_BYTES   = 10 * 1024 * 1024  # 10 MB per file
_LOG_BACKUP_COUNT = 5                  # keep up to 5 rotated files


# ─── Structured JSON formatter ────────────────────────────────────────────────

class _StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts":     datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level":  record.levelname,
            "logger": record.name,
            "msg":    record.getMessage(),
        }
        # Extra fields attached via Logger.bind()
        for key, val in record.__dict__.items():
            if key.startswith("_soc_"):
                entry[key[5:]] = val

        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry, default=str)


# ─── Bound logger ─────────────────────────────────────────────────────────────

class BoundLogger:
    """A thin wrapper that carries a dict of context fields appended to every log entry."""

    def __init__(self, logger: logging.Logger, context: dict[str, Any] | None = None) -> None:
        self._logger  = logger
        self._context = context or {}

    def bind(self, **kwargs: Any) -> "BoundLogger":
        return BoundLogger(self._logger, {**self._context, **kwargs})

    def _emit(self, level: int, msg: str, **kwargs: Any) -> None:
        extra = {f"_soc_{k}": v for k, v in {**self._context, **kwargs}.items()}
        self._logger.log(level, msg, extra=extra, stacklevel=3)

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._emit(logging.DEBUG, msg, **kwargs)

    def info(self, msg: str, **kwargs: Any) -> None:
        self._emit(logging.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._emit(logging.WARNING, msg, **kwargs)

    def error(self, msg: str, exc_info: bool = False, **kwargs: Any) -> None:
        if exc_info:
            kwargs["traceback"] = traceback.format_exc()
        self._emit(logging.ERROR, msg, **kwargs)

    def critical(self, msg: str, **kwargs: Any) -> None:
        self._emit(logging.CRITICAL, msg, **kwargs)


# ─── Factory functions ────────────────────────────────────────────────────────

def _make_handler(
    log_dir: Path,
    filename: str,
    max_bytes: int = _LOG_MAX_BYTES,
    backup_count: int = _LOG_BACKUP_COUNT,
) -> logging.handlers.RotatingFileHandler:
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        log_dir / filename,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(_StructuredFormatter())
    return handler


def setup_installer_logging(log_dir: Path) -> BoundLogger:
    """Configure logging for the installer process (install.py)."""
    logger = logging.getLogger("soc_agent.install")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    if not logger.handlers:
        logger.addHandler(_make_handler(log_dir, "installer.log"))

        # Also emit to stderr so bootstrap.ps1 captures output
        console = logging.StreamHandler()
        console.setFormatter(_StructuredFormatter())
        console.setLevel(logging.INFO)
        logger.addHandler(console)

    return BoundLogger(logger)


def setup_service_logging(
    log_dir: Path,
    log_level: str = "INFO",
    max_bytes: int = _LOG_MAX_BYTES,
    backup_count: int = _LOG_BACKUP_COUNT,
) -> BoundLogger:
    """Configure logging for the long-running Windows service."""
    level = getattr(logging, log_level.upper(), logging.INFO)
    logger = logging.getLogger("soc_agent.service")
    logger.setLevel(level)
    logger.propagate = False

    if not logger.handlers:
        logger.addHandler(_make_handler(log_dir, "agent.log", max_bytes, backup_count))

    return BoundLogger(logger)

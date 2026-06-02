from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Any

import structlog

from app.normalization.models import NormalizedEvent
from app.normalization.windows import normalize_windows_event
from app.normalization.linux import normalize_linux_event

logger = structlog.get_logger(__name__)

_SEVERITY_MAP = {
    "low": 1, "info": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def map_stream_message_to_normalized(message: dict[str, Any]) -> NormalizedEvent:
    """
    Entry point for the normalization pipeline.
    Converts a raw stream message into a NormalizedEvent.
    """
    now = datetime.now(tz=timezone.utc)

    ts_raw = message.get("timestamp")
    try:
        if isinstance(ts_raw, str):
            ts = datetime.fromisoformat(ts_raw)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        elif isinstance(ts_raw, (int, float)):
            ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
        else:
            ts = now
    except Exception:
        ts = now

    severity_raw = message.get("severity", "low")
    severity = _SEVERITY_MAP.get(str(severity_raw).lower(), 1) if isinstance(severity_raw, str) else int(severity_raw or 1)

    base = NormalizedEvent(
        event_id=str(message.get("event_id", "")),
        timestamp=ts,
        ingested_at=now,
        category=str(message.get("category", "other")),
        severity=severity,
        hostname=str(message.get("hostname", "")),
        os_type=str(message.get("os_type", "")).lower(),
        agent_id=str(message.get("agent_id", "")),
        tenant_id=str(message.get("tenant_id", "")),
        process=None,
        network=None,
        file=None,
        user=None,
        registry=message.get("registry"),
        tags=[],
        raw=message.get("raw") or {},
    )

    # Copy sub-objects that were already partially structured by the agent
    # (os-specific normalizers will enrich them further)
    if message.get("process"):
        from app.normalization.models import NormalizedProcess
        p = message["process"]
        if isinstance(p, dict):
            base.process = NormalizedProcess(**{k: p.get(k) for k in dataclasses.fields(NormalizedProcess) if k in p})

    if message.get("network"):
        from app.normalization.models import NormalizedNetwork
        n = message["network"]
        if isinstance(n, dict):
            base.network = NormalizedNetwork(**{k: n.get(k) for k in dataclasses.fields(NormalizedNetwork) if k in n})

    if message.get("file"):
        from app.normalization.models import NormalizedFile
        f = message["file"]
        if isinstance(f, dict):
            base.file = NormalizedFile(**{k: f.get(k) for k in dataclasses.fields(NormalizedFile) if k in f})

    if message.get("user"):
        from app.normalization.models import NormalizedUser
        u = message["user"]
        if isinstance(u, dict):
            base.user = NormalizedUser(**{k: u.get(k) for k in dataclasses.fields(NormalizedUser) if k in u})

    # OS-specific enrichment
    os_type = base.os_type
    if os_type == "windows":
        base = normalize_windows_event(message, base)
    elif os_type in ("linux", "macos"):
        base = normalize_linux_event(message, base)
    else:
        logger.debug("unknown_os_type_in_normalization", os_type=os_type)

    return base

from __future__ import annotations

import dataclasses
import re
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

# Human-readable labels used by the old agent format → Windows field names
_LABEL_TO_WIN_FIELD: dict[str, str] = {
    "Account Name":         "TargetUserName",
    "Subject Account Name": "SubjectUserName",
    "New Account Name":     "TargetUserName",
    "Target Account Name":  "TargetUserName",
    "Logon Account":        "TargetUserName",
    "Network Address":      "__src_ip",
    "New Process Name":     "Image",
    "Creator Process Name": "ParentImage",
    "Process Command Line": "CommandLine",
    "Service Name":         "ServiceName",
    "Image Path":           "Image",
    "Group Name":           "GroupName",
    "Member Name":          "MemberName",
    "Process Name":         "Image",
    "Logon Type":           "LogonType",
}


def _enrich_from_raw_message(message: dict[str, Any]) -> dict[str, Any]:
    """
    Fallback parser for old-format agent events where structured fields were
    not included at the top level of the stream message.

    Parses the agent's formatted text from raw.message, e.g.:
      "EventID 4688: Subject Account Name: ahmed\\nNew Process Name: C:\\cmd.exe"
    and injects the extracted fields back into the message dict so that
    normalize_windows_event() can process them normally.

    Also promotes windows_event_id and source_name from the raw sub-dict to the
    top level so normalize_windows_event() can always find them, even when the
    agent places them only inside the nested raw object.
    """
    raw_sub = message.get("raw")
    if not isinstance(raw_sub, dict):
        return message

    # Promote windows_event_id and source_name from raw sub-dict regardless of
    # whether we end up parsing the message body — these are always useful.
    promoted: dict[str, Any] = {}
    if raw_sub.get("source_name") and not message.get("source_name"):
        promoted["source_name"] = raw_sub["source_name"]
    if (
        raw_sub.get("windows_event_id")
        and not message.get("event_id_windows")
        and not message.get("EventID")
    ):
        promoted["event_id_windows"] = raw_sub["windows_event_id"]

    # Already has structured fields — only add the promoted enrichments.
    if message.get("event_id_windows") or message.get("EventID"):
        return {**message, **promoted} if promoted else message

    raw_msg: str = raw_sub.get("message", "")
    if not raw_msg:
        return {**message, **promoted} if promoted else message

    # ── Extract EventID ────────────────────────────────────────────────────────
    m = re.match(r"EventID\s+(\d+)[:\s]", raw_msg)
    if not m:
        return {**message, **promoted} if promoted else message

    eid = int(m.group(1))
    extra: dict[str, Any] = {"event_id_windows": eid}

    body = re.sub(r"^EventID\s+\d+:\s*", "", raw_msg).strip()

    # ── Parse "Key: Value" lines (classic Security log format) ─────────────────
    for line in body.splitlines():
        line = line.strip()
        if ": " in line:
            k, _, v = line.partition(": ")
            k = k.strip(); v = v.strip()
            if k and v and v not in ("-", ""):
                mapped = _LABEL_TO_WIN_FIELD.get(k)
                if mapped:
                    extra[mapped] = v
                elif "=" not in k:
                    # Unknown label — pass through as-is (may be useful for Sysmon fields)
                    extra[k] = v

    # ── Parse "Key=Value; Key2=Value2" (modern Sysmon/PowerShell channel format) ─
    if not extra.get("Image") and "=" in body:
        for part in body.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                k = k.strip(); v = v.strip()
                if k and v and v not in ("-", ""):
                    extra.setdefault(k, v)

    # ── Resolve source IP ──────────────────────────────────────────────────────
    src_ip = extra.pop("__src_ip", None) or extra.pop("IpAddress", None)
    if src_ip and src_ip not in ("-", "::1", "127.0.0.1", "0.0.0.0", ""):
        extra["source_ip"] = src_ip

    # promoted fields are lower priority than text-parsed fields
    return {**message, **promoted, **extra}


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

    _VALID_CATEGORIES = frozenset({
        "auth", "process", "network", "file", "registry", "dns", "system", "other",
    })
    category_raw = str(message.get("category", "other")).lower()
    category = category_raw if category_raw in _VALID_CATEGORIES else "other"

    base = NormalizedEvent(
        event_id=str(message.get("event_id", "")),
        timestamp=ts,
        ingested_at=now,
        category=category,
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

    # Fallback: parse raw.message text for old-format agent events that don't
    # include structured fields (event_id_windows, Image, CommandLine, etc.)
    # at the top level of the stream message.
    message = _enrich_from_raw_message(message)

    # OS-specific enrichment
    os_type = base.os_type
    if os_type == "windows":
        base = normalize_windows_event(message, base)
    elif os_type in ("linux", "macos"):
        base = normalize_linux_event(message, base)
    else:
        logger.debug("unknown_os_type_in_normalization", os_type=os_type)

    return base

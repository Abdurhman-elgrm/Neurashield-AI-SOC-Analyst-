"""
Generic / webhook connector parser.

Accepts any JSON and maps fields best-effort.  Useful for custom scripts,
alerting tools, or any vendor not covered by a dedicated parser.

Expected fields (all optional):
  event_id    string
  timestamp   ISO-8601 string
  hostname    string
  category    process|network|file|auth|registry|dns|other
  severity    1-4 integer OR "low"|"medium"|"high"|"critical"
  message     string (used for category auto-detection)
  source_ip   string
  dest_ip     string
  username    string
  process_name string
  extra fields passed through to raw
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.connectors.base import ConnectorParser, ParsedEvent

_SEV_STR: dict[str, int] = {
    "low": 1, "medium": 2, "high": 3, "critical": 4,
    "info": 1, "warning": 2, "error": 3, "fatal": 4,
}

_VALID_CATEGORIES = {"process", "network", "file", "auth", "registry", "dns", "other"}


def _parse_ts(raw: Any) -> datetime:
    try:
        s = str(raw).replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return datetime.now(tz=timezone.utc)


def _parse_sev(raw: Any) -> int:
    if isinstance(raw, int) and 1 <= raw <= 4:
        return raw
    if isinstance(raw, str):
        return _SEV_STR.get(raw.lower(), 1)
    return 1


class GenericParser(ConnectorParser):
    source_type = "generic"

    def parse(self, payload: Any) -> list[ParsedEvent]:
        try:
            items: list[dict[str, Any]] = (
                payload if isinstance(payload, list) else [payload]
            )
            return [e for e in (self._parse_one(i) for i in items if isinstance(i, dict)) if e]
        except Exception:
            return []

    def _parse_one(self, data: dict[str, Any]) -> ParsedEvent | None:
        hostname = (
            data.get("hostname") or data.get("host") or
            data.get("computer") or data.get("device") or "unknown"
        )
        ts = _parse_ts(data.get("timestamp") or data.get("time") or data.get("ts") or "")
        sev = _parse_sev(data.get("severity") or data.get("level") or data.get("priority") or 1)

        raw_cat = (data.get("category") or data.get("type") or "other").lower()
        category = raw_cat if raw_cat in _VALID_CATEGORIES else "other"

        # Network
        src_ip = data.get("source_ip") or data.get("src_ip") or data.get("srcip")
        dst_ip = data.get("dest_ip") or data.get("dst_ip") or data.get("dstip")
        network: dict[str, Any] | None = None
        if src_ip or dst_ip:
            network = {
                "src_ip":   src_ip,
                "dst_ip":   dst_ip,
                "dst_port": data.get("dest_port") or data.get("dst_port"),
                "protocol": data.get("protocol"),
            }

        # User
        username = data.get("username") or data.get("user") or data.get("actor")
        user: dict[str, Any] | None = {"name": username} if username else None

        # Process
        proc_name = data.get("process_name") or data.get("process") or data.get("process_id")
        process: dict[str, Any] | None = (
            {"name": proc_name, "command_line": data.get("command_line") or data.get("cmd")}
            if proc_name else None
        )

        return ParsedEvent(
            event_id=self._make_event_id(
                "generic", data.get("event_id") or data.get("id")
            ),
            timestamp=ts,
            category=category,
            hostname=str(hostname),
            os_type=str(data.get("os_type") or data.get("os") or "other").lower(),
            severity=sev,
            source_type=self.source_type,
            process=process,
            user=user,
            network=network,
            raw={k: v for k, v in data.items()},
        )

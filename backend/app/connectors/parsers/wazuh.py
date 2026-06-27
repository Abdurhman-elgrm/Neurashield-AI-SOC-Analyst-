"""
Wazuh SIEM connector parser.

Accepts Wazuh JSON alert objects (single or list).
Wazuh webhook delivers alerts via HTTP POST.

Rule level → severity:
  1-3   → 1 (low)
  4-7   → 2 (medium)
  8-11  → 3 (high)
  12-15 → 4 (critical)

Category mapping via rule.groups:
  authentication* → auth
  syscheck*       → file
  network*        → network
  process*        → process
  default         → other
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.connectors.base import ConnectorParser, ParsedEvent

_LEVEL_TO_SEV: list[tuple[int, int]] = [
    (12, 4),
    (8, 3),
    (4, 2),
    (1, 1),
]


def _map_level(level: int) -> int:
    for threshold, sev in _LEVEL_TO_SEV:
        if level >= threshold:
            return sev
    return 1


def _map_category(groups: list[str]) -> str:
    for g in groups:
        g = g.lower()
        if "authentication" in g or "logon" in g:
            return "auth"
        if "syscheck" in g or "fim" in g:
            return "file"
        if "network" in g:
            return "network"
        if "process" in g:
            return "process"
    return "other"


def _parse_ts(raw: str) -> datetime:
    try:
        # "2024-01-01T00:00:00.000+0000" or "2024-01-01T00:00:00.000Z"
        s = raw.replace("+0000", "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return datetime.now(tz=UTC)


class WazuhParser(ConnectorParser):
    source_type = "wazuh"

    def parse(self, payload: Any) -> list[ParsedEvent]:
        try:
            alerts: list[dict[str, Any]] = payload if isinstance(payload, list) else [payload]
            return [self._parse_one(a) for a in alerts if isinstance(a, dict)]
        except Exception:
            return []

    def _parse_one(self, alert: dict[str, Any]) -> ParsedEvent:
        rule = alert.get("rule") or {}
        agent = alert.get("agent") or {}
        data = alert.get("data") or {}

        level = int(rule.get("level", 3))
        groups: list[str] = rule.get("groups") or []
        hostname = agent.get("name") or alert.get("hostname") or "unknown"
        ts_raw = alert.get("timestamp") or ""
        ts = _parse_ts(ts_raw) if ts_raw else self._now()

        # Network sub-object
        network: dict[str, Any] | None = None
        src_ip = data.get("srcip") or data.get("src_ip")
        dst_ip = data.get("dstip") or data.get("dst_ip")
        if src_ip or dst_ip:
            network = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": data.get("dstport") or data.get("dst_port"),
                "protocol": data.get("protocol"),
            }

        # User sub-object
        user: dict[str, Any] | None = None
        username = data.get("dstuser") or data.get("srcuser") or data.get("user")
        if username:
            user = {"name": username}

        return ParsedEvent(
            event_id=self._make_event_id("wazuh", alert.get("id")),
            timestamp=ts,
            category=_map_category(groups),
            hostname=hostname,
            os_type="linux",
            severity=_map_level(level),
            source_type=self.source_type,
            network=network,
            user=user,
            raw={
                "wazuh_id": alert.get("id"),
                "rule_id": rule.get("id"),
                "rule_level": level,
                "description": rule.get("description"),
                "full_log": alert.get("full_log"),
                "groups": groups,
                "data": data,
            },
        )

"""
Syslog connector parser.

Accepts syslog messages as:
  - Plain RFC 3164 / RFC 5424 text (string body)
  - JSON wrapper: {"message": "<syslog line>", "host": "..."}
  - List of the above

Parses facility/severity from PRI, extracts host, timestamp, and message.

Syslog severity → internal severity:
  0-1 (emerg/alert)   → 4 critical
  2-3 (crit/err)      → 3 high
  4-5 (warning/notice)→ 2 medium
  6-7 (info/debug)    → 1 low
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from app.connectors.base import ConnectorParser, ParsedEvent

_PRI_RE = re.compile(r"^<(\d+)>")
_TS_3164 = re.compile(r"^<\d+>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+")
_TS_5424 = re.compile(r"^<\d+>\d+\s+(\d{4}-\d{2}-\d{2}T[\d:.+Z]+)\s+")
_HOST_3164 = re.compile(r"^<\d+>\w{3}\s+\d+\s+\d+:\d+:\d+\s+(\S+)\s+")
_HOST_5424 = re.compile(r"^<\d+>\d+\s+\S+\s+(\S+)\s+")

_SEV_MAP = {0: 4, 1: 4, 2: 3, 3: 3, 4: 2, 5: 2, 6: 1, 7: 1}

_AUTH_KEYWORDS = ("authentication", "login", "logon", "sudo", "su ", "ssh", "pam")
_NET_KEYWORDS = ("connect", "accept", "listen", "firewall", "iptables", "nftables")
_FILE_KEYWORDS = ("file", "open", "write", "delete", "rename", "chmod")


def _classify(message: str) -> str:
    m = message.lower()
    if any(k in m for k in _AUTH_KEYWORDS):
        return "auth"
    if any(k in m for k in _NET_KEYWORDS):
        return "network"
    if any(k in m for k in _FILE_KEYWORDS):
        return "file"
    return "other"


def _parse_syslog_line(line: str) -> tuple[int, str, datetime, str]:
    """Returns (sev, hostname, timestamp, message)."""
    syslog_sev = 6
    m_pri = _PRI_RE.match(line)
    if m_pri:
        pri = int(m_pri.group(1))
        syslog_sev = pri % 8

    hostname = "unknown"
    ts = datetime.now(tz=UTC)
    message = line

    m_host = _HOST_5424.match(line)
    if m_host:
        hostname = m_host.group(1)
        m_ts = _TS_5424.match(line)
        if m_ts:
            try:
                ts_str = m_ts.group(1).replace("Z", "+00:00")
                ts = datetime.fromisoformat(ts_str)
            except Exception:
                pass
    else:
        m_host = _HOST_3164.match(line)
        if m_host:
            hostname = m_host.group(1)
            m_ts = _TS_3164.match(line)
            if m_ts:
                try:
                    ts = datetime.strptime(
                        m_ts.group(1) + f" {ts.year}", "%b %d %H:%M:%S %Y"
                    ).replace(tzinfo=UTC)
                except Exception:
                    pass

    return syslog_sev, hostname, ts, message


class SyslogParser(ConnectorParser):
    source_type = "syslog"

    def parse(self, payload: Any) -> list[ParsedEvent]:
        try:
            lines = self._to_lines(payload)
            return [self._parse_one(line) for line in lines if line.strip()]
        except Exception:
            return []

    def _to_lines(self, payload: Any) -> list[str]:
        if isinstance(payload, str):
            return payload.splitlines()
        if isinstance(payload, dict):
            if "message" in payload:
                return [payload["message"]]
            if "messages" in payload:
                return [str(m) for m in payload["messages"]]
        if isinstance(payload, list):
            result: list[str] = []
            for item in payload:
                if isinstance(item, str):
                    result.append(item)
                elif isinstance(item, dict) and "message" in item:
                    result.append(item["message"])
            return result
        return [str(payload)]

    def _parse_one(self, line: str) -> ParsedEvent:
        syslog_sev, hostname, ts, message = _parse_syslog_line(line)
        sev = _SEV_MAP.get(syslog_sev, 1)
        category = _classify(message)

        return ParsedEvent(
            event_id=self._make_event_id("syslog"),
            timestamp=ts,
            category=category,
            hostname=hostname,
            os_type="linux",
            severity=sev,
            source_type=self.source_type,
            raw={
                "syslog_severity": syslog_sev,
                "message": line,
            },
        )

"""
Suricata EVE JSON connector parser.

Suricata can forward EVE JSON via HTTP using the eve-http output plugin,
or logs can be shipped via Filebeat/Vector.

Accepts:
  - Single EVE JSON object
  - List of EVE JSON objects
  - Newline-delimited JSON string (NDJSON)

event_type mapping:
  alert → network (or auth for SSH brute)
  dns   → dns
  http / tls / smtp → network
  fileinfo → file
  flow  → network

Suricata alert severity: 1=critical, 2=high, 3=medium, 4=low (inverse of ours)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from app.connectors.base import ConnectorParser, ParsedEvent

_SURICATA_SEV: dict[int, int] = {1: 4, 2: 3, 3: 2, 4: 1}


def _parse_ts(raw: str) -> datetime:
    try:
        # "2024-01-01T00:00:00.000000+0000"
        s = raw.replace("+0000", "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return datetime.now(tz=timezone.utc)


def _event_type_to_category(event_type: str) -> str:
    mapping = {
        "alert":    "network",
        "dns":      "dns",
        "http":     "network",
        "tls":      "network",
        "smtp":     "network",
        "flow":     "network",
        "ssh":      "auth",
        "fileinfo": "file",
    }
    return mapping.get(event_type.lower(), "other")


class SuricataParser(ConnectorParser):
    source_type = "suricata"

    def parse(self, payload: Any) -> list[ParsedEvent]:
        try:
            events = self._normalise_input(payload)
            return [e for e in (self._parse_one(ev) for ev in events) if e]
        except Exception:
            return []

    def _normalise_input(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [e for e in payload if isinstance(e, dict)]
        if isinstance(payload, dict):
            return [payload]
        if isinstance(payload, str):
            # Try NDJSON
            results = []
            for line in payload.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            return results
        return []

    def _parse_one(self, eve: dict[str, Any]) -> ParsedEvent | None:
        event_type = (eve.get("event_type") or "other").lower()
        ts_raw = eve.get("timestamp") or ""
        ts = _parse_ts(ts_raw) if ts_raw else self._now()
        hostname = eve.get("host") or eve.get("hostname") or "suricata"

        # Severity from alert block
        alert = eve.get("alert") or {}
        raw_sev = int(alert.get("severity", 3))
        sev = _SURICATA_SEV.get(raw_sev, 2)

        # Network
        src_ip = eve.get("src_ip")
        dst_ip = eve.get("dest_ip")
        network: dict[str, Any] | None = None
        if src_ip or dst_ip:
            network = {
                "src_ip":   src_ip,
                "src_port": eve.get("src_port"),
                "dst_ip":   dst_ip,
                "dst_port": eve.get("dest_port"),
                "protocol": eve.get("proto"),
            }

        # DNS
        dns_data = eve.get("dns") or {}
        if event_type == "dns" and dns_data:
            query = dns_data.get("rrname") or (
                (dns_data.get("query") or [{}])[0].get("rrname")
            )
            if query:
                network = {**(network or {}), "dns_query": query}

        return ParsedEvent(
            event_id=self._make_event_id("suricata", eve.get("flow_id")),
            timestamp=ts,
            category=_event_type_to_category(event_type),
            hostname=hostname,
            os_type="linux",
            severity=sev,
            source_type=self.source_type,
            network=network,
            raw={
                "event_type": event_type,
                "signature":  alert.get("signature"),
                "action":     alert.get("action"),
                "category":   alert.get("category"),
                "flow_id":    eve.get("flow_id"),
                "app_proto":  eve.get("app_proto"),
                "http":       eve.get("http"),
                "tls":        eve.get("tls"),
                "dns":        dns_data or None,
            },
        )

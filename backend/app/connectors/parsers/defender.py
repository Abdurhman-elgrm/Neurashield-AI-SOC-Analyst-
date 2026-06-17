"""
Microsoft Defender ATP / Microsoft 365 Defender connector parser.

Accepts alert objects from the Defender alerts API or webhook.

Severity mapping:
  Informational → 1
  Low           → 1
  Medium        → 2
  High          → 3
  Critical      → 4

Category mapping from Defender category strings to internal categories.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.connectors.base import ConnectorParser, ParsedEvent

_SEV_MAP: dict[str, int] = {
    "informational": 1,
    "low":           1,
    "medium":        2,
    "high":          3,
    "critical":      4,
}

_CAT_MAP: dict[str, str] = {
    "malware":             "process",
    "ransomware":          "file",
    "credential theft":    "auth",
    "lateral movement":    "auth",
    "privilege escalation":"auth",
    "suspicious activity": "other",
    "execution":           "process",
    "persistence":         "registry",
    "defense evasion":     "process",
    "discovery":           "network",
    "collection":          "file",
    "exfiltration":        "network",
    "command and control": "network",
}


def _parse_ts(raw: str) -> datetime:
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(tz=timezone.utc)


class DefenderParser(ConnectorParser):
    source_type = "defender"

    def parse(self, payload: Any) -> list[ParsedEvent]:
        try:
            alerts: list[dict[str, Any]] = (
                payload.get("value") or payload.get("alerts") or [payload]
                if isinstance(payload, dict) else payload
            )
            return [e for e in (self._parse_one(a) for a in alerts if isinstance(a, dict)) if e]
        except Exception:
            return []

    def _parse_one(self, alert: dict[str, Any]) -> ParsedEvent | None:
        sev_str = (alert.get("severity") or "medium").lower()
        sev = _SEV_MAP.get(sev_str, 2)

        cat_str = (alert.get("category") or "").lower()
        category = "other"
        for key, val in _CAT_MAP.items():
            if key in cat_str:
                category = val
                break

        hostname = (
            alert.get("computerDnsName")
            or alert.get("machineName")
            or alert.get("deviceDnsName")
            or "unknown"
        )
        ts = _parse_ts(alert.get("createdTime") or alert.get("alertCreationTime") or "")

        # Extract process from evidence
        process: dict[str, Any] | None = None
        user: dict[str, Any] | None = None
        network: dict[str, Any] | None = None

        for evidence in alert.get("evidence") or []:
            etype = (evidence.get("entityType") or "").lower()
            if etype == "process" and process is None:
                process = {
                    "name": evidence.get("processId") and evidence.get("fileName"),
                    "command_line": evidence.get("processCommandLine"),
                    "executable": evidence.get("filePath"),
                }
            elif etype == "user" and user is None:
                user = {
                    "name": evidence.get("accountName"),
                    "domain": evidence.get("domainName"),
                }
            elif etype in ("ip", "networkconnection") and network is None:
                network = {
                    "src_ip":  evidence.get("ipAddress") or evidence.get("localIpAddress"),
                    "dst_ip":  evidence.get("remoteIpAddress"),
                    "dst_port": evidence.get("remotePort"),
                }

        return ParsedEvent(
            event_id=self._make_event_id("defender", alert.get("id") or alert.get("alertId")),
            timestamp=ts,
            category=category,
            hostname=hostname,
            os_type="windows",
            severity=sev,
            source_type=self.source_type,
            process=process,
            user=user,
            network=network,
            raw={
                "defender_id":   alert.get("id") or alert.get("alertId"),
                "title":         alert.get("title"),
                "description":   alert.get("description"),
                "status":        alert.get("status"),
                "category":      alert.get("category"),
                "detector":      alert.get("detectionSource"),
                "machine_id":    alert.get("machineId"),
                "incident_id":   alert.get("incidentId"),
                "mitre_tactics": alert.get("mitreTechniques"),
            },
        )

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import structlog

from app.ai.llm_manager import get_llm_manager
from app.ai.prompt_guard import sanitize_field as _guard_sanitize_field

if TYPE_CHECKING:
    from app.normalization.models import NormalizedEvent

log = structlog.get_logger(__name__)

# ─── Allowed LLM output values ────────────────────────────────────────────────

VALID_SEVERITIES = {"benign", "suspicious", "malicious", "unknown"}
VALID_ACTIONS = {"Monitor", "Investigate", "Contain", "Escalate"}

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$")


def _sanitize_field(value: str | None, max_len: int = 200) -> str | None:
    """Delegate to the centralized prompt injection guard."""
    return _guard_sanitize_field(value, max_len=max_len)


def _validate_ip(ip: str | None) -> str | None:
    if ip is None:
        return None
    ip = ip.strip()
    return ip if _IP_RE.match(ip) else "[invalid_ip]"


@dataclass
class AnalysisResult:
    severity_assessment: str
    confidence: float
    mitre_technique: str | None
    mitre_tactic: str | None
    summary: str
    recommended_action: str
    indicators: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity_assessment": self.severity_assessment,
            "confidence": self.confidence,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "summary": self.summary,
            "recommended_action": self.recommended_action,
            "indicators": self.indicators,
        }


class AIAnalyzer:
    SYSTEM_PROMPT = """You are a senior SOC analyst AI. Analyze the security event and respond with JSON only — no markdown, no explanation, just valid JSON.

Required JSON format:
{
  "severity_assessment": "benign|suspicious|malicious",
  "confidence": 0.0-1.0,
  "mitre_technique": "T1234.001 or null",
  "mitre_tactic": "Tactic name or null",
  "summary": "1-2 sentence description of what happened and why it matters",
  "recommended_action": "Monitor|Investigate|Contain|Escalate",
  "indicators": ["list", "of", "key", "IOCs"]
}

Be precise. If unsure, reflect that in confidence score. Never make up MITRE techniques."""

    async def analyze(self, event: NormalizedEvent) -> AnalysisResult:
        """Analyze a normalized event. Returns default result on any error."""
        try:
            manager = get_llm_manager()
            prompt = self._build_prompt(event)
            response = await manager.generate(
                prompt=prompt,
                system_prompt=self.SYSTEM_PROMPT,
                max_tokens=512,
            )
            return self._parse_response(response)
        except Exception:
            log.warning("ai_analysis_failed", exc_info=True)
            return self._default_result()

    def _build_prompt(self, event: NormalizedEvent) -> str:
        """Build structured prompt from NormalizedEvent fields (sanitized, ~800 token limit)."""
        parts: list[str] = []

        host = _sanitize_field(event.hostname, max_len=100) or "unknown"
        parts.append(
            f"Category: {event.category} | Severity: {event.severity}\n"
            f"Timestamp: {event.timestamp}\n"
            f"Host: {host}" + (f" ({event.os_type})" if event.os_type else "")
        )

        if event.process:
            p = event.process
            proc_parts: list[str] = []
            proc_name = _sanitize_field(p.name, max_len=100)
            if proc_name:
                proc_parts.append(f"Process: {proc_name}" + (f" (PID: {p.pid})" if p.pid else ""))
            cmd = _sanitize_field(p.command_line, max_len=200)
            if cmd:
                proc_parts.append(f"  Command: {cmd}")
            exe = _sanitize_field(p.executable, max_len=100)
            if exe and exe != proc_name:
                proc_parts.append(f"  Executable: {exe}")
            if p.ppid:
                proc_parts.append(f"  Parent PID: {p.ppid}")
            if p.hash_sha256:
                proc_parts.append(f"  SHA256: {p.hash_sha256}")
            elif p.hash_md5:
                proc_parts.append(f"  MD5: {p.hash_md5}")
            if proc_parts:
                parts.append("\n".join(proc_parts))

        if event.network:
            n = event.network
            net_parts: list[str] = []
            src_ip = _validate_ip(n.src_ip)
            dst_ip = _validate_ip(n.dst_ip)
            src = f"{src_ip}:{n.src_port}" if src_ip and n.src_port else (src_ip or "")
            dst = f"{dst_ip}:{n.dst_port}" if dst_ip and n.dst_port else (dst_ip or "")
            if src or dst:
                net_parts.append(
                    f"Network: {src} -> {dst}" + (f" ({n.protocol})" if n.protocol else "")
                )
            if n.direction:
                net_parts.append(f"  Direction: {n.direction}")
            if net_parts:
                parts.append("\n".join(net_parts))

        if event.user:
            u = event.user
            user_str = _sanitize_field(u.name, max_len=100) or ""
            domain = _sanitize_field(u.domain, max_len=100)
            if domain:
                user_str = f"{user_str}@{domain}"
            if user_str:
                parts.append(f"User: {user_str}" + (" [PRIVILEGED]" if u.is_privileged else ""))

        if event.file:
            f = event.file
            file_parts: list[str] = []
            path = _sanitize_field(f.path, max_len=200)
            name = _sanitize_field(f.name, max_len=100)
            action = _sanitize_field(f.action, max_len=50)
            if path:
                file_parts.append(f"File: {path}" + (f" ({action})" if action else ""))
            elif name:
                file_parts.append(f"File: {name}" + (f" ({action})" if action else ""))
            if f.hash_sha256:
                file_parts.append(f"  SHA256: {f.hash_sha256}")
            elif f.hash_md5:
                file_parts.append(f"  MD5: {f.hash_md5}")
            if file_parts:
                parts.append("\n".join(file_parts))

        if event.tags:
            parts.append(f"Tags: {', '.join(event.tags)}")

        return "\n\n".join(parts)

    def _parse_response(self, response: str) -> AnalysisResult:
        """Parse LLM JSON response, validating all values before storing."""
        try:
            # Strip markdown fences if present
            text = re.sub(r"^```(?:json)?\s*", "", response.strip())
            text = re.sub(r"\s*```$", "", text.strip())
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1:
                text = text[start : end + 1]

            data = json.loads(text)

            def _nullable_str(val: Any) -> str | None:
                if val is None or val == "null":
                    return None
                return str(val) if val else None

            # Validate severity against allowed values
            severity = str(data.get("severity_assessment", "unknown")).lower()
            if severity not in VALID_SEVERITIES:
                severity = "unknown"

            # Validate confidence in [0.0, 1.0]
            try:
                confidence = float(data.get("confidence", 0.5))
                confidence = max(0.0, min(1.0, confidence))
            except (TypeError, ValueError):
                confidence = 0.5

            # Validate action against allowed values
            action = str(data.get("recommended_action", "Monitor"))
            if action not in VALID_ACTIONS:
                action = "Monitor"

            # Sanitize text fields before storing
            summary = (
                _sanitize_field(str(data.get("summary", "")), max_len=500) or "Analysis complete"
            )

            # Validate indicators list — each must be a short string
            indicators: list[str] = []
            for item in data.get("indicators", [])[:10]:
                if isinstance(item, str):
                    sanitized = _sanitize_field(item, max_len=100)
                    if sanitized:
                        indicators.append(sanitized)

            return AnalysisResult(
                severity_assessment=severity,
                confidence=confidence,
                mitre_technique=_nullable_str(data.get("mitre_technique")),
                mitre_tactic=_nullable_str(data.get("mitre_tactic")),
                summary=summary,
                recommended_action=action,
                indicators=indicators,
            )
        except Exception:
            log.warning("ai_response_parse_failed", response_snippet=response[:200])
            return self._default_result()

    def _default_result(self) -> AnalysisResult:
        return AnalysisResult(
            severity_assessment="unknown",
            confidence=0.0,
            mitre_technique=None,
            mitre_tactic=None,
            summary="Analysis unavailable",
            recommended_action="Monitor",
            indicators=[],
        )


_analyzer: AIAnalyzer | None = None


def get_analyzer() -> AIAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = AIAnalyzer()
    return _analyzer

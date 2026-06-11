from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import structlog

from app.ai.llm_manager import get_llm_manager

if TYPE_CHECKING:
    from app.normalization.models import NormalizedEvent

log = structlog.get_logger(__name__)


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

    async def analyze(self, event: "NormalizedEvent") -> AnalysisResult:
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

    def _build_prompt(self, event: "NormalizedEvent") -> str:
        """Build structured prompt from NormalizedEvent fields (non-null only, ~800 token limit)."""
        parts: list[str] = []

        parts.append(
            f"Category: {event.category} | Severity: {event.severity}\n"
            f"Timestamp: {event.timestamp}\n"
            f"Host: {event.hostname or 'unknown'}"
            + (f" ({event.os_type})" if event.os_type else "")
        )

        if event.process:
            p = event.process
            proc_parts: list[str] = []
            if p.name:
                proc_parts.append(f"Process: {p.name}" + (f" (PID: {p.pid})" if p.pid else ""))
            if p.command_line:
                proc_parts.append(f"  Command: {p.command_line}")
            if p.executable and p.executable != p.name:
                proc_parts.append(f"  Executable: {p.executable}")
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
            src = f"{n.src_ip}:{n.src_port}" if n.src_ip and n.src_port else (n.src_ip or "")
            dst = f"{n.dst_ip}:{n.dst_port}" if n.dst_ip and n.dst_port else (n.dst_ip or "")
            if src or dst:
                net_parts.append(f"Network: {src} -> {dst}" + (f" ({n.protocol})" if n.protocol else ""))
            if n.direction:
                net_parts.append(f"  Direction: {n.direction}")
            if net_parts:
                parts.append("\n".join(net_parts))

        if event.user:
            u = event.user
            user_str = u.name or ""
            if u.domain:
                user_str = f"{user_str}@{u.domain}"
            if user_str:
                parts.append(
                    f"User: {user_str}" + (" [PRIVILEGED]" if u.is_privileged else "")
                )

        if event.file:
            f = event.file
            file_parts: list[str] = []
            if f.path:
                file_parts.append(f"File: {f.path}" + (f" ({f.action})" if f.action else ""))
            elif f.name:
                file_parts.append(f"File: {f.name}" + (f" ({f.action})" if f.action else ""))
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
        """Parse LLM JSON response into AnalysisResult. Returns safe default on parse error."""
        try:
            # Strip markdown fences if present
            text = re.sub(r"^```(?:json)?\s*", "", response.strip())
            text = re.sub(r"\s*```$", "", text.strip())
            # Extract JSON object if surrounded by other text
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1:
                text = text[start : end + 1]

            data = json.loads(text)

            def _nullable_str(val: Any) -> str | None:
                if val is None or val == "null":
                    return None
                return str(val) if val else None

            confidence = float(data.get("confidence", 0.0))
            confidence = max(0.0, min(1.0, confidence))

            return AnalysisResult(
                severity_assessment=str(data.get("severity_assessment", "unknown")),
                confidence=confidence,
                mitre_technique=_nullable_str(data.get("mitre_technique")),
                mitre_tactic=_nullable_str(data.get("mitre_tactic")),
                summary=str(data.get("summary", "No summary available")),
                recommended_action=str(data.get("recommended_action", "Monitor")),
                indicators=list(data.get("indicators", [])),
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

"""
AI Investigation Analyzer — Phase 2 core.

Takes a completed InvestigationResult (or equivalent dict) and produces
a rich analysis using RAG context + LLM reasoning.

No blocking I/O: RAG query + LLM call are both async.
Never raises: all exceptions are caught and a safe default is returned.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.llm_manager import get_llm_manager
from app.ai.rag import retrieve as rag_retrieve

log = structlog.get_logger(__name__)

KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives",
]

_CONFIDENCE_MAP = {"low": 0.30, "medium": 0.60, "high": 0.85}

SYSTEM_PROMPT = """You are an expert SOC analyst AI. Analyze this security investigation and respond with JSON ONLY — no markdown, no explanation.

Required format:
{
  "executive_summary": "2-3 sentence non-technical summary for management",
  "attack_narrative": "Technical step-by-step description of what happened",
  "kill_chain_stage": "one of: Reconnaissance|Weaponization|Delivery|Exploitation|Installation|Command & Control|Actions on Objectives",
  "kill_chain_index": 0-6,
  "threat_actor_attribution": "Actor name or Unknown",
  "threat_actor_confidence": 0.0-1.0,
  "threat_actor_matching_ttps": ["T1059.001"],
  "evidence_strong": ["finding 1", "finding 2"],
  "evidence_circumstantial": ["finding 1"],
  "evidence_noise": ["finding 1"],
  "recommended_actions": ["Isolate host X", "Reset credentials for Y", "Block IP Z"],
  "verdict": "true_positive|false_positive|needs_investigation",
  "verdict_confidence": 0.0-1.0
}

Use the threat intelligence context provided to inform attribution.
Be specific — use actual hostnames, IPs, usernames from the investigation data.
Never make up MITRE technique IDs."""


@dataclass
class InvestigationAnalysis:
    executive_summary: str
    attack_narrative: str
    kill_chain_stage: str
    kill_chain_index: int
    threat_actor_attribution: str
    threat_actor_details: dict
    evidence_strength: dict
    recommended_actions: list[str]
    verdict_suggestion: str
    verdict_confidence: float
    rag_sources_used: list[str]

    def to_dict(self) -> dict:
        return {
            "executive_summary":       self.executive_summary,
            "attack_narrative":        self.attack_narrative,
            "kill_chain_stage":        self.kill_chain_stage,
            "kill_chain_index":        self.kill_chain_index,
            "threat_actor_attribution": self.threat_actor_attribution,
            "threat_actor_details":    self.threat_actor_details,
            "evidence_strength":       self.evidence_strength,
            "recommended_actions":     self.recommended_actions,
            "verdict_suggestion":      self.verdict_suggestion,
            "verdict_confidence":      self.verdict_confidence,
            "rag_sources_used":        self.rag_sources_used,
        }


class InvestigationAIAnalyzer:

    async def analyze(
        self,
        db: AsyncSession,
        investigation_data: dict,
    ) -> InvestigationAnalysis:
        """
        Produce AI analysis for a completed investigation.

        investigation_data keys:
          id, title, threat_score, confidence (str or float),
          behaviors_json, timeline_json, context_json, graph_json
        """
        try:
            ttps     = self._extract_ttps(investigation_data)
            keywords = self._extract_keywords(investigation_data)

            rag_chunks  = await rag_retrieve(db, ttps=ttps, keywords=keywords, limit=8)
            rag_context = self._format_rag_context(rag_chunks)

            prompt  = self._build_prompt(investigation_data, rag_context)
            manager = get_llm_manager()
            response = await manager.generate(
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT,
                max_tokens=2048,
            )

            return self._parse_response(
                response,
                rag_chunks=[c.chunk_id for c in rag_chunks],
            )

        except Exception:
            log.warning("investigation_ai_analysis_failed", exc_info=True)
            return self._default_result()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_ttps(self, data: dict) -> list[str]:
        ttps: list[str] = []
        raw = data.get("behaviors_json") or []
        if isinstance(raw, dict):
            raw = raw.get("detected_behaviors", [])
        for behavior in raw:
            if not isinstance(behavior, dict):
                continue
            for key in ("mitre_technique", "technique_id"):
                val = behavior.get(key)
                if val and isinstance(val, str):
                    ttps.append(val)
            for key in ("mitre_tactics", "tactics", "techniques"):
                val = behavior.get(key)
                if isinstance(val, list):
                    ttps.extend(v for v in val if isinstance(v, str))
        return list(set(ttps))

    def _extract_keywords(self, data: dict) -> list[str]:
        ctx = data.get("context_json") or {}
        if not isinstance(ctx, dict):
            return []
        keywords: list[str] = []
        keywords.extend(ctx.get("involved_hosts", ctx.get("hosts", []))[:3])
        keywords.extend(ctx.get("suspicious_processes", ctx.get("processes", []))[:5])
        return [k for k in keywords if isinstance(k, str) and k]

    def _format_rag_context(self, chunks: list) -> str:
        if not chunks:
            return "No relevant threat intelligence found."
        parts = []
        for chunk in chunks:
            parts.append(f"[{chunk.source.upper()}] {chunk.title}\n{chunk.content[:400]}")
        return "\n\n---\n\n".join(parts)

    def _build_prompt(self, data: dict, rag_context: str) -> str:
        conf_val = data.get("confidence", 0)
        if isinstance(conf_val, str):
            conf_val = _CONFIDENCE_MAP.get(conf_val, 0.5)

        behaviors_raw = data.get("behaviors_json") or {}
        context       = data.get("context_json") or {}
        timeline      = data.get("timeline_json") or {}

        if not isinstance(context, dict):
            context = {}
        if not isinstance(timeline, dict):
            timeline = {}

        hosts     = context.get("involved_hosts", context.get("hosts", []))
        users     = context.get("involved_users", context.get("users", []))
        src_ips   = context.get("source_ips", [])
        dst_ips   = context.get("dest_ips", [])
        processes = context.get("suspicious_processes", context.get("processes", []))

        behaviors_str = json.dumps(behaviors_raw, indent=2)[:1500]

        return f"""INVESTIGATION ANALYSIS REQUEST

Title: {data.get('title', 'Unknown')}
Threat Score: {data.get('threat_score', 0)}/100
Confidence: {conf_val:.0%}

DETECTED BEHAVIORS:
{behaviors_str}

ENTITIES INVOLVED:
Hosts: {hosts}
Users: {users}
IPs: {src_ips + dst_ips}
Processes: {processes}

ATTACK TIMELINE:
Duration: {timeline.get('duration_seconds', 0)} seconds
Events: {timeline.get('total_events', 0)}
First seen: {timeline.get('first_seen')}
Last seen: {timeline.get('last_seen')}

THREAT INTELLIGENCE CONTEXT:
{rag_context}

Analyze this investigation and provide your assessment in the required JSON format."""

    def _parse_response(
        self, response: str, rag_chunks: list[str]
    ) -> InvestigationAnalysis:
        try:
            text = response.strip()
            # Strip markdown fences if present
            if text.startswith("```"):
                lines = text.split("\n")
                text = "\n".join(
                    lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
                )
            # Find outermost JSON object
            start = text.find("{")
            end   = text.rfind("}")
            if start != -1 and end > start:
                text = text[start : end + 1]
            data = json.loads(text)

            kc_stage = data.get("kill_chain_stage", "Exploitation")
            try:
                kc_index = KILL_CHAIN_STAGES.index(kc_stage)
            except ValueError:
                kc_index = int(data.get("kill_chain_index", 3))
                kc_stage = KILL_CHAIN_STAGES[min(kc_index, 6)]

            return InvestigationAnalysis(
                executive_summary=data.get("executive_summary", "Analysis unavailable"),
                attack_narrative=data.get("attack_narrative", ""),
                kill_chain_stage=kc_stage,
                kill_chain_index=kc_index,
                threat_actor_attribution=data.get("threat_actor_attribution", "Unknown"),
                threat_actor_details={
                    "name":         data.get("threat_actor_attribution", "Unknown"),
                    "confidence":   float(data.get("threat_actor_confidence", 0.0)),
                    "matching_ttps": data.get("threat_actor_matching_ttps", []),
                },
                evidence_strength={
                    "strong":        data.get("evidence_strong", []),
                    "circumstantial": data.get("evidence_circumstantial", []),
                    "noise":         data.get("evidence_noise", []),
                },
                recommended_actions=data.get("recommended_actions", []),
                verdict_suggestion=data.get("verdict", "needs_investigation"),
                verdict_confidence=float(data.get("verdict_confidence", 0.5)),
                rag_sources_used=rag_chunks,
            )
        except Exception:
            log.warning("investigation_analysis_parse_failed", exc_info=True)
            return self._default_result()

    def _default_result(self) -> InvestigationAnalysis:
        return InvestigationAnalysis(
            executive_summary="AI analysis unavailable",
            attack_narrative="",
            kill_chain_stage="Exploitation",
            kill_chain_index=3,
            threat_actor_attribution="Unknown",
            threat_actor_details={"name": "Unknown", "confidence": 0.0, "matching_ttps": []},
            evidence_strength={"strong": [], "circumstantial": [], "noise": []},
            recommended_actions=[],
            verdict_suggestion="needs_investigation",
            verdict_confidence=0.0,
            rag_sources_used=[],
        )


# ── Singleton ─────────────────────────────────────────────────────────────────

_analyzer: InvestigationAIAnalyzer | None = None


def get_investigation_analyzer() -> InvestigationAIAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = InvestigationAIAnalyzer()
    return _analyzer

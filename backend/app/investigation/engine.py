from __future__ import annotations

"""
Investigation Engine — orchestration layer.

process_group() is the single entry point:
  1. Build attack timeline from event snapshots
  2. Build in-memory attack graph
  3. Analyze behaviors (MITRE-mapped)
  4. Build analyst-ready context
  5. Score the investigation
  6. Generate deterministic summary
  7. Persist to database
  8. Return InvestigationResult

All timestamps from events, never from wall clock (replay-safe).
No external AI / LLM calls in this phase.
"""

import time
from typing import Any

import structlog

from app.investigation.behavior import analyze_behaviors
from app.investigation.context import build_context
from app.investigation.graph import build_attack_graph
from app.investigation.schemas import InvestigationResult
from app.investigation.scoring import score_investigation
from app.investigation.summary import generate_summary
from app.investigation.timeline import build_timeline

logger = structlog.get_logger(__name__)


class InvestigationEngine:
    """
    Stateless engine — all state comes in via parameters.
    Instantiate once and reuse across events.
    """

    def __init__(self, tenant_id: str) -> None:
        self._tenant_id = tenant_id

    async def process_group(
        self,
        investigation_id: str,
        snapshots: list[dict[str, Any]],
        group_meta: dict[str, Any] | None = None,
        historical_group_ids: list[str] | None = None,
    ) -> InvestigationResult:
        """
        Build a full InvestigationResult from a list of event snapshots.

        snapshots: list of enriched event dicts (from correlated_events stream)
        group_meta: CorrelationGrouper.get_group() snapshot (optional)
        historical_group_ids: other investigation IDs sharing entity keys
        """
        now = time.time()

        # Gather correlation metadata from group_meta
        correlation_score = int((group_meta or {}).get("score", 0))
        matched_rules: list[str] = list((group_meta or {}).get("matched_rules") or [])

        # ── 1. Timeline ────────────────────────────────────────────────────────
        timeline = build_timeline(investigation_id, self._tenant_id, snapshots)

        # ── 2. Attack graph ────────────────────────────────────────────────────
        graph = build_attack_graph(investigation_id, snapshots)

        # ── 3. Behavior analysis ───────────────────────────────────────────────
        behaviors = analyze_behaviors(investigation_id, timeline, snapshots)

        # ── 4. Context ────────────────────────────────────────────────────────
        context = build_context(
            investigation_id=investigation_id,
            tenant_id=self._tenant_id,
            timeline=timeline,
            graph=graph,
            behaviors=behaviors,
            snapshots=snapshots,
            historical_group_ids=historical_group_ids,
        )

        # ── 5. Score ──────────────────────────────────────────────────────────
        inv_score = score_investigation(
            timeline=timeline,
            behaviors=behaviors,
            context=context,
            correlation_score=correlation_score,
            matched_rules=matched_rules,
        )

        # ── 6. Summary ────────────────────────────────────────────────────────
        summary = generate_summary(
            investigation_id=investigation_id,
            timeline=timeline,
            behaviors=behaviors,
            context=context,
            score=inv_score,
        )

        result = InvestigationResult(
            investigation_id=investigation_id,
            tenant_id=self._tenant_id,
            investigation_group_id=investigation_id,
            status="active" if inv_score.threat_score >= 10 else "new",
            timeline=timeline,
            graph=graph,
            behaviors=behaviors,
            context=context,
            score=inv_score,
            summary=summary,
            created_at=now,
            updated_at=now,
        )

        logger.info(
            "investigation_processed",
            tenant_id=self._tenant_id,
            investigation_id=investigation_id,
            threat_score=inv_score.threat_score,
            confidence=inv_score.confidence,
            behaviors=behaviors.behavior_count,
            mitre_tactics=behaviors.mitre_tactics,
            total_events=timeline.total_events,
        )

        return result

    async def persist(
        self,
        result: InvestigationResult,
        db: Any,
    ) -> None:
        """Upsert investigation record in the database."""
        from sqlalchemy import text

        db_dict = result.to_db_dict()
        await db.execute(
            text(
                """
                INSERT INTO investigations (
                    id, tenant_id, investigation_group_id,
                    threat_score, confidence, tp_probability, fp_probability,
                    executive_summary, technical_summary,
                    attack_progression, recommended_actions, status,
                    created_at, updated_at
                ) VALUES (
                    :investigation_id, :tenant_id, :investigation_group_id,
                    :threat_score, :confidence, :tp_probability, :fp_probability,
                    :executive_summary, :technical_summary,
                    :attack_progression, :recommended_actions, :status,
                    NOW(), NOW()
                )
                ON CONFLICT (id) DO UPDATE SET
                    threat_score        = EXCLUDED.threat_score,
                    confidence          = EXCLUDED.confidence,
                    tp_probability      = EXCLUDED.tp_probability,
                    fp_probability      = EXCLUDED.fp_probability,
                    executive_summary   = EXCLUDED.executive_summary,
                    technical_summary   = EXCLUDED.technical_summary,
                    attack_progression  = EXCLUDED.attack_progression,
                    recommended_actions = EXCLUDED.recommended_actions,
                    status              = EXCLUDED.status,
                    updated_at          = NOW()
                """
            ),
            {
                "investigation_id": db_dict["investigation_id"],
                "tenant_id": db_dict["tenant_id"],
                "investigation_group_id": db_dict["investigation_group_id"],
                "threat_score": db_dict["threat_score"],
                "confidence": db_dict["confidence"],
                "tp_probability": db_dict["tp_probability"],
                "fp_probability": db_dict["fp_probability"],
                "executive_summary": db_dict["executive_summary"],
                "technical_summary": db_dict["technical_summary"],
                "attack_progression": __import__("json").dumps(db_dict["attack_progression"]),
                "recommended_actions": __import__("json").dumps(db_dict["recommended_actions"]),
                "status": db_dict["status"],
            },
        )

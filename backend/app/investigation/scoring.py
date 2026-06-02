from __future__ import annotations

"""
Investigation threat scoring engine.

Computes threat_score (0-100), tp_probability, fp_probability,
and confidence band from all available investigation signals.

All scoring is additive with explicit factor weights. Deterministic.
"""

from typing import Any

from app.investigation.schemas import (
    AttackTimeline,
    BehaviorAnalysis,
    InvestigationContext,
    InvestigationScore,
)

# ─── Scoring factor weights ────────────────────────────────────────────────────

_WEIGHT_CORR_RULE_BASE    = 5.0   # per correlated rule (from Phase 3.2)
_WEIGHT_BEHAVIOR_BASE     = 8.0   # per detected behavior
_WEIGHT_BEHAVIOR_CONF     = 5.0   # × behavior confidence bonus
_WEIGHT_CROSS_HOST        = 10.0  # same user on 2+ hosts
_WEIGHT_EXTRA_HOST        = 4.0   # each additional host beyond first 2
_WEIGHT_PERSISTENCE       = 12.0  # persistence behavior present
_WEIGHT_CREDENTIAL        = 10.0  # credential access behavior
_WEIGHT_LATERAL           = 10.0  # lateral movement behavior
_WEIGHT_SUSPICIOUS_PROC   = 6.0   # per suspicious process
_WEIGHT_SUSPICIOUS_CMD    = 4.0   # per suspicious command
_WEIGHT_CHAIN_DEPTH       = 2.0   # per hop in process tree depth
_WEIGHT_HIGH_SEV_EVENT    = 1.5   # per high-severity (≥7) event

_MAX_RULE_CONTRIBUTION    = 20.0
_MAX_BEHAVIOR_CONTRIBUTION = 40.0
_MAX_PROC_CONTRIBUTION    = 12.0
_MAX_CMD_CONTRIBUTION     = 8.0

# TP/FP confidence mapping
_TP_BY_SCORE: list[tuple[int, float]] = [
    (85, 0.90),
    (70, 0.75),
    (50, 0.55),
    (30, 0.35),
    (10, 0.15),
    (0,  0.05),
]


class InvestigationScorer:
    """
    Stateless scorer — call score() per investigation.
    """

    def score(
        self,
        timeline: AttackTimeline,
        behaviors: BehaviorAnalysis,
        context: InvestigationContext,
        correlation_score: int = 0,
        matched_rules: list[str] | None = None,
    ) -> InvestigationScore:
        factors: dict[str, float] = {}
        breakdown: list[str] = []

        # 1. Correlation rules from Phase 3.2
        rule_count = len(matched_rules or [])
        rule_contrib = min(rule_count * _WEIGHT_CORR_RULE_BASE, _MAX_RULE_CONTRIBUTION)
        if rule_contrib:
            factors["correlation_rules"] = rule_contrib
            breakdown.append(f"{rule_count} correlation rule(s) matched (+{rule_contrib:.0f})")

        # 2. Detected behaviors
        beh_contrib = 0.0
        for b in behaviors.detected_behaviors:
            raw = _WEIGHT_BEHAVIOR_BASE + _WEIGHT_BEHAVIOR_CONF * b.confidence
            beh_contrib += raw
        beh_contrib = min(beh_contrib, _MAX_BEHAVIOR_CONTRIBUTION)
        if beh_contrib:
            factors["detected_behaviors"] = beh_contrib
            breakdown.append(
                f"{behaviors.behavior_count} behavior(s) detected (+{beh_contrib:.0f})"
            )

        # 3. High-value specific behaviors
        behavior_names = {b.behavior_name for b in behaviors.detected_behaviors}
        extra = 0.0
        if "persistence" in behavior_names:
            extra += _WEIGHT_PERSISTENCE
            breakdown.append(f"Persistence indicator (+{_WEIGHT_PERSISTENCE:.0f})")
        if "credential_access" in behavior_names:
            extra += _WEIGHT_CREDENTIAL
            breakdown.append(f"Credential access indicator (+{_WEIGHT_CREDENTIAL:.0f})")
        if "lateral_movement" in behavior_names:
            extra += _WEIGHT_LATERAL
            breakdown.append(f"Lateral movement indicator (+{_WEIGHT_LATERAL:.0f})")
        if extra:
            factors["high_value_behaviors"] = extra

        # 4. Cross-host activity
        if timeline.distinct_hosts >= 2:
            cross = _WEIGHT_CROSS_HOST + (timeline.distinct_hosts - 2) * _WEIGHT_EXTRA_HOST
            factors["cross_host_activity"] = cross
            breakdown.append(
                f"{timeline.distinct_hosts} distinct host(s) (+{cross:.0f})"
            )

        # 5. Suspicious processes & commands
        proc_contrib = min(
            len(context.suspicious_processes) * _WEIGHT_SUSPICIOUS_PROC,
            _MAX_PROC_CONTRIBUTION,
        )
        cmd_contrib = min(
            len(context.suspicious_commands) * _WEIGHT_SUSPICIOUS_CMD,
            _MAX_CMD_CONTRIBUTION,
        )
        if proc_contrib:
            factors["suspicious_processes"] = proc_contrib
            breakdown.append(
                f"{len(context.suspicious_processes)} suspicious process(es) (+{proc_contrib:.0f})"
            )
        if cmd_contrib:
            factors["suspicious_commands"] = cmd_contrib
            breakdown.append(
                f"{len(context.suspicious_commands)} suspicious command(s) (+{cmd_contrib:.0f})"
            )

        # 6. Process tree depth (chain depth)
        tree_depth = len(timeline.process_tree_groups)
        chain_contrib = min(tree_depth * _WEIGHT_CHAIN_DEPTH, 10.0)
        if chain_contrib:
            factors["chain_depth"] = chain_contrib
            breakdown.append(f"Process tree depth {tree_depth} (+{chain_contrib:.0f})")

        # 7. High-severity events
        high_sev = sum(
            1 for e in timeline.entries if e.severity >= 7
        )
        sev_contrib = min(high_sev * _WEIGHT_HIGH_SEV_EVENT, 15.0)
        if sev_contrib:
            factors["high_severity_events"] = sev_contrib
            breakdown.append(
                f"{high_sev} high-severity event(s) (+{sev_contrib:.0f})"
            )

        raw_score = sum(factors.values())
        threat_score = int(min(raw_score, 100))
        confidence = self._band(threat_score)
        tp_prob, fp_prob = self._tp_fp(threat_score)

        return InvestigationScore(
            threat_score=threat_score,
            tp_probability=round(tp_prob, 2),
            fp_probability=round(fp_prob, 2),
            confidence=confidence,
            scoring_factors={k: round(v, 2) for k, v in factors.items()},
            score_breakdown=breakdown,
        )

    def _band(self, score: int) -> str:
        if score >= 75:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    def _tp_fp(self, score: int) -> tuple[float, float]:
        for threshold, tp in _TP_BY_SCORE:
            if score >= threshold:
                return tp, round(1.0 - tp, 2)
        return 0.05, 0.95


_default_scorer = InvestigationScorer()


def score_investigation(
    timeline: AttackTimeline,
    behaviors: BehaviorAnalysis,
    context: InvestigationContext,
    correlation_score: int = 0,
    matched_rules: list[str] | None = None,
) -> InvestigationScore:
    return _default_scorer.score(
        timeline, behaviors, context, correlation_score, matched_rules
    )

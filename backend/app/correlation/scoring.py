from __future__ import annotations

"""
Weighted, explainable correlation scoring.

score = min(sum(rule.weight for rule in matched_rules), 100)
Confidence bands: high ≥ 75, medium ≥ 40, low < 40.
"""

from dataclasses import dataclass

from app.correlation.matcher import MatchResult, RuleMatch

# ─── Output ───────────────────────────────────────────────────────────────────


@dataclass
class CorrelationScore:
    score: int  # 0–100
    confidence: str  # "low" | "medium" | "high"
    matched_rules: list[RuleMatch]  # ordered by weight desc
    reasons: list[str]  # human-readable explanations

    @property
    def is_significant(self) -> bool:
        """True when score is high enough to warrant an investigation group."""
        return self.score >= 10


# ─── Scorer ───────────────────────────────────────────────────────────────────


class CorrelationScorer:
    """Converts a MatchResult into a CorrelationScore. No I/O."""

    _HIGH_THRESHOLD = 75
    _MEDIUM_THRESHOLD = 40

    def score(self, match_result: MatchResult) -> CorrelationScore:
        rules = sorted(
            match_result.matched_rules,
            key=lambda r: r.rule.weight,
            reverse=True,
        )
        total = min(sum(r.rule.weight for r in rules), 100)
        confidence = self._band(total)
        reasons = [self._reason(r) for r in rules]
        return CorrelationScore(
            score=total,
            confidence=confidence,
            matched_rules=rules,
            reasons=reasons,
        )

    def _band(self, score: int) -> str:
        if score >= self._HIGH_THRESHOLD:
            return "high"
        if score >= self._MEDIUM_THRESHOLD:
            return "medium"
        return "low"

    def _reason(self, match: RuleMatch) -> str:
        return (
            f"{match.rule.name}: {match.event_count} events in window (weight={match.rule.weight})"
        )


# ─── Singleton ────────────────────────────────────────────────────────────────
_default_scorer = CorrelationScorer()


def score_match(match_result: MatchResult) -> CorrelationScore:
    return _default_scorer.score(match_result)

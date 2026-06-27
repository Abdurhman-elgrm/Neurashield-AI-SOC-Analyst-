from __future__ import annotations

"""
Correlation engine — orchestration layer.

process_event() is the single entry point:
  1. Parse the normalized event payload.
  2. Add to all relevant temporal windows (using event timestamp for determinism).
  3. Fetch window counts and pass to the stateless matcher.
  4. Score the match result.
  5. If significant, upsert the investigation group.
  6. Return a CorrelationResult for the worker to publish.

IMPORTANT: All timestamps come from the event payload, never from wall clock.
This ensures identical results when replaying historical events.
"""

import time
from dataclasses import dataclass
from typing import Any

import structlog

from app.core.redis import TenantRedisClient
from app.correlation.grouping import CorrelationGrouper
from app.correlation.matcher import GroupContext, MatchResult, match_event
from app.correlation.rules import (
    HIGH_FREQUENCY_SOURCE,
    SAME_EVENT_CHAIN,
    SAME_HOST_BURST,
    SAME_LOGON_SESSION,
    SAME_PROCESS_TREE,
    SAME_USER_MULTI_HOST,
    SHARED_DEST_IP,
    SHARED_DOMAIN,
    SHARED_FILE_HASH,
    SHARED_SOURCE_IP,
)
from app.correlation.scoring import CorrelationScore, score_match
from app.correlation.window import TemporalWindowManager

logger = structlog.get_logger(__name__)

_CORR_SUBSYSTEM = "corr"


# ─── Result ───────────────────────────────────────────────────────────────────


@dataclass
class CorrelationResult:
    event_id: str
    tenant_id: str
    investigation_id: str | None  # None when score is not significant
    score: int
    confidence: str
    matched_rules: list[str]
    reasons: list[str]
    group_keys: list[str]
    is_significant: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "investigation_id": self.investigation_id,
            "score": self.score,
            "confidence": self.confidence,
            "matched_rules": self.matched_rules,
            "reasons": self.reasons,
            "group_keys": self.group_keys,
            "is_significant": self.is_significant,
        }


# ─── Engine ───────────────────────────────────────────────────────────────────


class CorrelationEngine:
    """
    Stateful (Redis-backed) correlation engine scoped to one tenant.
    Instantiate once per tenant worker; reuse across events.
    """

    def __init__(self, tenant_id: str, client: TenantRedisClient) -> None:
        self._tenant_id = tenant_id
        self._windows = TemporalWindowManager(client)
        self._grouper = CorrelationGrouper(client=client, tenant_id=tenant_id)

    async def process_event(self, payload: dict[str, Any]) -> CorrelationResult:
        event_id = payload.get("event_id") or payload.get("event_db_id", "")
        event_ts = self._event_timestamp(payload)

        # ── 1. Add to temporal windows ────────────────────────────────────────
        window_keys = self._collect_window_keys(payload)
        for wk, window_seconds in window_keys:
            await self._windows.add(wk, event_id, event_ts, window_seconds)

        # ── 2. Fetch window counts ────────────────────────────────────────────
        ctx = await self._build_context(payload, event_ts, window_keys)

        # ── 3. Match rules ────────────────────────────────────────────────────
        match_result: MatchResult = match_event(payload, ctx)

        # ── 4. Score ──────────────────────────────────────────────────────────
        corr_score: CorrelationScore = score_match(match_result)

        # ── 5. Upsert investigation group ─────────────────────────────────────
        investigation_id: str | None = None
        if corr_score.is_significant:
            investigation_id = await self._grouper.get_or_create_group(
                payload, corr_score, event_ts
            )
            await self._grouper.add_event_to_group(investigation_id, event_id, event_ts)

        result = CorrelationResult(
            event_id=event_id,
            tenant_id=self._tenant_id,
            investigation_id=investigation_id,
            score=corr_score.score,
            confidence=corr_score.confidence,
            matched_rules=[r.rule.name for r in corr_score.matched_rules],
            reasons=corr_score.reasons,
            group_keys=match_result.group_keys,
            is_significant=corr_score.is_significant,
        )

        logger.debug(
            "correlation_processed",
            tenant_id=self._tenant_id,
            event_id=event_id,
            score=corr_score.score,
            confidence=corr_score.confidence,
            investigation_id=investigation_id,
            matched_rules=[r.rule.name for r in corr_score.matched_rules],
        )

        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _event_timestamp(self, payload: dict[str, Any]) -> float:
        """
        Use the event's own timestamp for replay determinism.
        Fall back to current time only as a last resort (live events without ts).
        """
        ts = payload.get("timestamp") or payload.get("event_timestamp")
        if ts is not None:
            try:
                return float(ts)
            except (TypeError, ValueError):
                pass
        return time.time()

    def _collect_window_keys(self, payload: dict[str, Any]) -> list[tuple[str, int]]:
        """
        Return (window_key, window_seconds) pairs for every index we want to
        maintain for this event. One event can appear in multiple windows.
        """
        pairs: list[tuple[str, int]] = []

        cid = payload.get("correlation_id")
        if cid:
            pairs.append((f"cid:{cid}", SAME_HOST_BURST.window_seconds))
            pairs.append((f"cid:{cid}", HIGH_FREQUENCY_SOURCE.window_seconds))

        sid = payload.get("session_id")
        if sid:
            pairs.append((f"sid:{sid}", SAME_LOGON_SESSION.window_seconds))

        ptid = payload.get("process_tree_id")
        if ptid:
            pairs.append((f"ptid:{ptid}", SAME_PROCESS_TREE.window_seconds))

        ecid = payload.get("event_chain_id")
        if ecid:
            pairs.append((f"ecid:{ecid}", SAME_EVENT_CHAIN.window_seconds))

        entities = payload.get("entities", [])
        # Handle both flat list (new format) and nested dict (legacy format)
        if isinstance(entities, dict):
            entities = [e for group in entities.values() if isinstance(group, list) for e in group]
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            ek = entity.get("key", "")
            if not ek:
                continue
            ek_lower = ek.lower()
            if ek_lower.startswith("ip:"):
                direction = entity.get("direction", "")
                ws = (
                    SHARED_SOURCE_IP.window_seconds
                    if direction == "inbound"
                    else SHARED_DEST_IP.window_seconds
                )
                pairs.append((ek, ws))
            elif ek_lower.startswith("domain:"):
                pairs.append((ek, SHARED_DOMAIN.window_seconds))
            elif ek_lower.startswith("user:"):
                pairs.append((ek, SAME_USER_MULTI_HOST.window_seconds))
            elif ek_lower.startswith("hash:"):
                pairs.append((ek, SHARED_FILE_HASH.window_seconds))

        return pairs

    async def _build_context(
        self,
        payload: dict[str, Any],
        event_ts: float,
        window_keys: list[tuple[str, int]],
    ) -> GroupContext:
        counts: dict[tuple[str, int], int] = {}
        for wk, ws in window_keys:
            counts[(wk, ws)] = await self._windows.count_in_window(wk, event_ts, ws)

        cid = payload.get("correlation_id")
        ptid = payload.get("process_tree_id")
        sid = payload.get("session_id")

        has_cid_group = bool(
            cid and await self._grouper.resolve_investigation_id({"correlation_id": cid})
        )
        has_ptid_group = bool(
            ptid and await self._grouper.resolve_investigation_id({"process_tree_id": ptid})
        )
        has_sid_group = bool(
            sid and await self._grouper.resolve_investigation_id({"session_id": sid})
        )

        return GroupContext(
            window_counts=counts,
            has_correlation_group=has_cid_group,
            has_session_group=has_sid_group,
            has_process_tree_group=has_ptid_group,
        )

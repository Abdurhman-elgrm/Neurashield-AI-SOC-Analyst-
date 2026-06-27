from __future__ import annotations

"""
Stateless event matcher.

The matcher receives a pre-fetched GroupContext (window counts, existing group
membership) and produces a MatchResult.  No I/O — all async Redis work is done
by the engine before calling match().
"""

from dataclasses import dataclass, field

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
    CorrelationRule,
)

# Minimum event count in window for burst / high-frequency rules to fire.
_BURST_THRESHOLD = 3
_HIGH_FREQ_THRESHOLD = 10


# ─── Data types ───────────────────────────────────────────────────────────────


@dataclass
class RuleMatch:
    rule: CorrelationRule
    window_key: str  # The entity/session key that triggered the match
    event_count: int  # Events in the relevant window at match time


@dataclass
class GroupContext:
    """
    Pre-fetched data passed from the engine to the matcher.
    All window counts are already scoped to the correct window_seconds.
    """

    # Window counts keyed by (window_key, window_seconds)
    window_counts: dict[tuple[str, int], int] = field(default_factory=dict)

    # Whether a correlation / session / process-tree mapping already exists
    has_correlation_group: bool = False
    has_session_group: bool = False
    has_process_tree_group: bool = False


@dataclass
class MatchResult:
    matched_rules: list[RuleMatch] = field(default_factory=list)
    # All entity / correlation keys relevant to this event (used for grouping)
    group_keys: list[str] = field(default_factory=list)

    @property
    def any_matched(self) -> bool:
        return bool(self.matched_rules)


# ─── Matcher ──────────────────────────────────────────────────────────────────


class EventMatcher:
    """
    Pure function object: match(event_payload, ctx) -> MatchResult.
    No state, no I/O, no side effects.
    """

    def match(self, payload: dict, ctx: GroupContext) -> MatchResult:
        result = MatchResult()

        correlation_id = payload.get("correlation_id")
        session_id = payload.get("session_id")
        process_tree_id = payload.get("process_tree_id")
        event_chain_id = payload.get("event_chain_id")

        entities = payload.get("entities", [])
        if isinstance(entities, dict):
            entities = [e for group in entities.values() if isinstance(group, list) for e in group]
        entity_keys: list[str] = [
            e.get("key", "") for e in entities if isinstance(e, dict) and e.get("key")
        ]

        # ── same_host_burst ──────────────────────────────────────────────────
        if correlation_id:
            wk = f"cid:{correlation_id}"
            count = ctx.window_counts.get((wk, SAME_HOST_BURST.window_seconds), 0)
            if count >= _BURST_THRESHOLD:
                result.matched_rules.append(RuleMatch(SAME_HOST_BURST, wk, count))
            result.group_keys.append(wk)

        # ── same_logon_session ───────────────────────────────────────────────
        if session_id:
            wk = f"sid:{session_id}"
            count = ctx.window_counts.get((wk, SAME_LOGON_SESSION.window_seconds), 0)
            if count >= 2:
                result.matched_rules.append(RuleMatch(SAME_LOGON_SESSION, wk, count))
            result.group_keys.append(wk)

        # ── same_process_tree ────────────────────────────────────────────────
        if process_tree_id:
            wk = f"ptid:{process_tree_id}"
            count = ctx.window_counts.get((wk, SAME_PROCESS_TREE.window_seconds), 0)
            if count >= 2:
                result.matched_rules.append(RuleMatch(SAME_PROCESS_TREE, wk, count))
            result.group_keys.append(wk)

        # ── same_event_chain ─────────────────────────────────────────────────
        if event_chain_id:
            wk = f"ecid:{event_chain_id}"
            count = ctx.window_counts.get((wk, SAME_EVENT_CHAIN.window_seconds), 0)
            if count >= 2:
                result.matched_rules.append(RuleMatch(SAME_EVENT_CHAIN, wk, count))
            result.group_keys.append(wk)

        # ── entity-level rules (IP, domain, user, hash) ──────────────────────
        for ek in entity_keys:
            ek_lower = ek.lower()

            if ek_lower.startswith("ip:"):
                # Distinguish src / dst by direction field if present.
                direction = self._entity_direction(entities, ek)
                if direction == "inbound":
                    count = ctx.window_counts.get((ek, SHARED_SOURCE_IP.window_seconds), 0)
                    if count >= 2:
                        result.matched_rules.append(RuleMatch(SHARED_SOURCE_IP, ek, count))
                else:
                    count = ctx.window_counts.get((ek, SHARED_DEST_IP.window_seconds), 0)
                    if count >= 2:
                        result.matched_rules.append(RuleMatch(SHARED_DEST_IP, ek, count))
                result.group_keys.append(ek)

            elif ek_lower.startswith("domain:"):
                count = ctx.window_counts.get((ek, SHARED_DOMAIN.window_seconds), 0)
                if count >= 2:
                    result.matched_rules.append(RuleMatch(SHARED_DOMAIN, ek, count))
                result.group_keys.append(ek)

            elif ek_lower.startswith("user:"):
                count = ctx.window_counts.get((ek, SAME_USER_MULTI_HOST.window_seconds), 0)
                if count >= 2:
                    result.matched_rules.append(RuleMatch(SAME_USER_MULTI_HOST, ek, count))
                result.group_keys.append(ek)

            elif ek_lower.startswith("hash:"):
                count = ctx.window_counts.get((ek, SHARED_FILE_HASH.window_seconds), 0)
                if count >= 2:
                    result.matched_rules.append(RuleMatch(SHARED_FILE_HASH, ek, count))
                result.group_keys.append(ek)

        # ── high_frequency_source ────────────────────────────────────────────
        if correlation_id:
            wk = f"cid:{correlation_id}"
            count = ctx.window_counts.get((wk, HIGH_FREQUENCY_SOURCE.window_seconds), 0)
            if count >= _HIGH_FREQ_THRESHOLD:
                result.matched_rules.append(RuleMatch(HIGH_FREQUENCY_SOURCE, wk, count))

        # Deduplicate group_keys while preserving order.
        seen: set[str] = set()
        deduped: list[str] = []
        for k in result.group_keys:
            if k not in seen:
                seen.add(k)
                deduped.append(k)
        result.group_keys = deduped

        return result

    def _entity_direction(self, entities: list[dict], key: str) -> str:
        for e in entities:
            if e.get("key") == key:
                return e.get("direction", "")
        return ""


# ─── Singleton ────────────────────────────────────────────────────────────────
_default_matcher = EventMatcher()


def match_event(payload: dict, ctx: GroupContext) -> MatchResult:
    return _default_matcher.match(payload, ctx)

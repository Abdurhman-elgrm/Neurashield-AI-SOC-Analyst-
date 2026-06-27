from __future__ import annotations

"""
Investigation group state management.

Each investigation group is stored in Redis as:
  HASH  corr:grp:{investigation_id}          → metadata fields
  ZSET  corr:grp:{investigation_id}:events   → score=timestamp, member=event_id

Mappings allow looking up the group that owns a correlation_id / process_tree_id:
  STRING corr:cid:{correlation_id}            → investigation_id
  STRING corr:ptid:{process_tree_id}          → investigation_id
  STRING corr:sid:{session_id}                → investigation_id

All keys are tenant-prefixed by TenantRedisClient (subsystem "corr").
"""

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from app.core.redis import TenantRedisClient
from app.correlation.scoring import CorrelationScore
from app.correlation.utils import deterministic_uuid

# ─── Namespace for investigation IDs ─────────────────────────────────────────
_NS_INVESTIGATION = uuid.UUID("e5f6a7b8-c9d0-1234-ef01-345678901234")

# Group TTL — expire investigation state after 7 days of inactivity.
# 24 hours was too short: slow-moving campaigns (e.g. APT lateral movement
# over several days) would lose their correlation history mid-investigation,
# causing new events to start fresh groups instead of enriching the existing one.
_GROUP_TTL_SECONDS = 86_400 * 7

# Maximum events stored per group ZSET (oldest pruned).
_MAX_GROUP_EVENTS = 5_000


# ─── Models ───────────────────────────────────────────────────────────────────


class InvestigationGroup(BaseModel):
    """Snapshot of a group's current state (read from Redis)."""

    investigation_id: str
    tenant_id: str
    event_count: int = 0
    score: int = 0
    confidence: str = "low"
    entity_keys: list[str] = field(default_factory=list)  # type: ignore[assignment]
    process_tree_ids: list[str] = field(default_factory=list)  # type: ignore[assignment]
    session_ids: list[str] = field(default_factory=list)  # type: ignore[assignment]
    matched_rules: list[str] = field(default_factory=list)  # type: ignore[assignment]
    created_at: float = 0.0
    updated_at: float = 0.0

    model_config = {"arbitrary_types_allowed": True}


# ─── Grouper ──────────────────────────────────────────────────────────────────


@dataclass
class CorrelationGrouper:
    """
    Async Redis group manager.
    Every method is scoped to a single tenant via TenantRedisClient.
    """

    client: TenantRedisClient
    tenant_id: str

    # ── Key builders ──────────────────────────────────────────────────────────

    def _grp_key(self, inv_id: str) -> str:
        return f"grp:{inv_id}"

    def _grp_events_key(self, inv_id: str) -> str:
        return f"grp:{inv_id}:events"

    def _cid_key(self, correlation_id: str) -> str:
        return f"cid:{correlation_id}"

    def _ptid_key(self, process_tree_id: str) -> str:
        return f"ptid:{process_tree_id}"

    def _sid_key(self, session_id: str) -> str:
        return f"sid:{session_id}"

    # ── ID resolution ─────────────────────────────────────────────────────────

    def make_investigation_id(self, correlation_id: str) -> str:
        """Deterministic investigation ID from tenant + correlation_id."""
        return str(deterministic_uuid(_NS_INVESTIGATION, f"{self.tenant_id}|{correlation_id}"))

    async def resolve_investigation_id(self, payload: dict[str, Any]) -> str | None:
        """
        Find an existing investigation_id for this event's correlation keys,
        or return None if no group exists yet.
        """
        for key_fn, id_val in [
            (self._cid_key, payload.get("correlation_id")),
            (self._ptid_key, payload.get("process_tree_id")),
            (self._sid_key, payload.get("session_id")),
        ]:
            if id_val:
                inv_id = await self.client.get(key_fn(id_val))
                if inv_id:
                    return inv_id
        return None

    # ── Group lifecycle ───────────────────────────────────────────────────────

    async def get_or_create_group(
        self,
        payload: dict[str, Any],
        score: CorrelationScore,
        event_ts: float,
    ) -> str:
        """
        Return the investigation_id for this event. Creates a new group if none
        exists. Updates score, entity sets, and mapping keys every call.
        """
        inv_id = await self.resolve_investigation_id(payload)

        if inv_id is None:
            cid = payload.get("correlation_id", "")
            inv_id = self.make_investigation_id(cid or payload.get("event_id", ""))
            # Persist mapping keys so future events resolve to this group.
            await self._write_mapping_keys(payload, inv_id)
            # Initialise metadata hash.
            await self._init_group(inv_id, event_ts)

        await self._update_group(inv_id, payload, score, event_ts)
        return inv_id

    async def add_event_to_group(self, inv_id: str, event_id: str, event_ts: float) -> None:
        """Append event_id to the group's ZSET; prune oldest if over cap."""
        zset_key = self._grp_events_key(inv_id)
        await self.client.zadd(zset_key, {event_id: event_ts})
        count = await self.client.zcount(zset_key, "-inf", "+inf")
        if count > _MAX_GROUP_EVENTS:
            excess = count - _MAX_GROUP_EVENTS
            await self.client.zremrangebyrank(zset_key, 0, excess - 1)
        await self.client.expire(zset_key, _GROUP_TTL_SECONDS)

    async def get_group(self, inv_id: str) -> InvestigationGroup | None:
        raw = await self.client.hgetall(self._grp_key(inv_id))
        if not raw:
            return None
        return InvestigationGroup(
            investigation_id=inv_id,
            tenant_id=self.tenant_id,
            event_count=int(raw.get("event_count", 0)),
            score=int(raw.get("score", 0)),
            confidence=raw.get("confidence", "low"),
            entity_keys=json.loads(raw.get("entity_keys", "[]")),
            process_tree_ids=json.loads(raw.get("process_tree_ids", "[]")),
            session_ids=json.loads(raw.get("session_ids", "[]")),
            matched_rules=json.loads(raw.get("matched_rules", "[]")),
            created_at=float(raw.get("created_at", 0)),
            updated_at=float(raw.get("updated_at", 0)),
        )

    # ── Snapshot storage (for investigation engine) ───────────────────────────

    async def store_event_snapshot(
        self, inv_id: str, event_id: str, snapshot: dict[str, Any]
    ) -> None:
        """Persist a compact event snapshot so the investigation engine can read it."""
        key = f"grp:{inv_id}:snap:{event_id}"
        await self.client.set(key, json.dumps(snapshot, default=str), ex=_GROUP_TTL_SECONDS)

    async def get_event_snapshots(self, inv_id: str) -> list[dict[str, Any]]:
        """Return all stored event snapshots for an investigation group."""
        event_ids = await self.client.zrange(self._grp_events_key(inv_id), 0, -1)
        snapshots: list[dict[str, Any]] = []
        for eid in event_ids:
            raw = await self.client.get(f"grp:{inv_id}:snap:{eid}")
            if raw:
                try:
                    snapshots.append(json.loads(raw))
                except Exception:
                    pass
        return snapshots

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _write_mapping_keys(self, payload: dict[str, Any], inv_id: str) -> None:
        for key_fn, id_val in [
            (self._cid_key, payload.get("correlation_id")),
            (self._ptid_key, payload.get("process_tree_id")),
            (self._sid_key, payload.get("session_id")),
        ]:
            if id_val:
                await self.client.set(key_fn(id_val), inv_id, ex=_GROUP_TTL_SECONDS)

    async def _init_group(self, inv_id: str, event_ts: float) -> None:
        await self.client.hset(
            self._grp_key(inv_id),
            {
                "event_count": "0",
                "score": "0",
                "confidence": "low",
                "entity_keys": "[]",
                "process_tree_ids": "[]",
                "session_ids": "[]",
                "matched_rules": "[]",
                "created_at": str(event_ts),
                "updated_at": str(event_ts),
            },
        )
        await self.client.expire(self._grp_key(inv_id), _GROUP_TTL_SECONDS)

    async def _update_group(
        self,
        inv_id: str,
        payload: dict[str, Any],
        score: CorrelationScore,
        event_ts: float,
    ) -> None:
        raw = await self.client.hgetall(self._grp_key(inv_id))
        if not raw:
            return

        event_count = int(raw.get("event_count", 0)) + 1
        new_score = min(max(int(raw.get("score", 0)), score.score), 100)

        entity_keys: list[str] = json.loads(raw.get("entity_keys", "[]"))
        process_tree_ids: list[str] = json.loads(raw.get("process_tree_ids", "[]"))
        session_ids: list[str] = json.loads(raw.get("session_ids", "[]"))
        matched_rules: list[str] = json.loads(raw.get("matched_rules", "[]"))

        # Merge entity keys.
        incoming_keys: list[str] = payload.get("related_entity_keys", [])
        for k in incoming_keys:
            if k not in entity_keys:
                entity_keys.append(k)

        ptid = payload.get("process_tree_id")
        if ptid and ptid not in process_tree_ids:
            process_tree_ids.append(ptid)

        sid = payload.get("session_id")
        if sid and sid not in session_ids:
            session_ids.append(sid)

        for rm in score.matched_rules:
            if rm.rule.name not in matched_rules:
                matched_rules.append(rm.rule.name)

        confidence = score.confidence if new_score >= score.score else raw.get("confidence", "low")

        await self.client.hset(
            self._grp_key(inv_id),
            {
                "event_count": str(event_count),
                "score": str(new_score),
                "confidence": confidence,
                "entity_keys": json.dumps(entity_keys),
                "process_tree_ids": json.dumps(process_tree_ids),
                "session_ids": json.dumps(session_ids),
                "matched_rules": json.dumps(matched_rules),
                "updated_at": str(event_ts),
            },
        )
        await self.client.expire(self._grp_key(inv_id), _GROUP_TTL_SECONDS)

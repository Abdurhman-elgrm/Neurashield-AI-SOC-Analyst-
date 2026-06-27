from __future__ import annotations

"""
Entity pivot / search engine.

Analysts can pivot from any entity (user, host, IP, process, hash, domain)
to all investigations that mention it.

Strategy:
  - The investigations.context_json JSONB field stores the full InvestigationContext
    (involved_users, involved_hosts, involved_ips, suspicious_processes,
     suspicious_domains, suspicious_hashes).
  - For each entity type, we query for investigations where the entity appears
    in the relevant context list using PostgreSQL JSONB array operators.
  - Cross-investigation lookups are scoped to tenant_id.

No raw SQL string interpolation — all values are parameterized.
"""

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyst.schemas import PivotResult
from app.models.investigation import Investigation

logger = structlog.get_logger(__name__)

# Entity type → context_json key
_ENTITY_TYPE_MAP: dict[str, str] = {
    "user": "involved_users",
    "host": "involved_hosts",
    "ip": "involved_ips",
    "process": "suspicious_processes",
    "domain": "suspicious_domains",
    "hash": "suspicious_hashes",
}


class PivotEngine:
    @staticmethod
    async def pivot(
        db: AsyncSession,
        tenant_id: UUID,
        entity_type: str,
        entity_value: str,
        limit: int = 50,
    ) -> PivotResult:
        """Find all investigations in this tenant that reference the given entity."""
        limit = min(limit, 200)
        entity_type = entity_type.lower()

        context_key = _ENTITY_TYPE_MAP.get(entity_type)
        if context_key is None:
            # Fallback: search the executive_summary for the value
            return await PivotEngine._text_search(db, tenant_id, entity_type, entity_value, limit)

        # Use PostgreSQL JSONB array containment operator
        # context_json -> 'context_key' @> '["entity_value"]'
        # This checks if the JSON array at context_key contains entity_value.
        stmt = (
            select(Investigation)
            .where(
                Investigation.tenant_id == tenant_id,
                Investigation.context_json.isnot(None),
                func.jsonb_exists(
                    Investigation.context_json[context_key],
                    entity_value,
                ),
            )
            .order_by(Investigation.threat_score.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        rows = list(result.scalars().all())

        # If no JSONB results (column might be null), fall back to text search
        if not rows:
            return await PivotEngine._text_search(db, tenant_id, entity_type, entity_value, limit)

        return _build_pivot_result(entity_type, entity_value, rows)

    @staticmethod
    async def _text_search(
        db: AsyncSession,
        tenant_id: UUID,
        entity_type: str,
        entity_value: str,
        limit: int,
    ) -> PivotResult:
        """Fallback: full-text search in executive_summary/technical_summary."""
        stmt = (
            select(Investigation)
            .where(
                Investigation.tenant_id == tenant_id,
                Investigation.executive_summary.ilike(f"%{entity_value}%"),
            )
            .order_by(Investigation.threat_score.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        rows = list(result.scalars().all())
        return _build_pivot_result(entity_type, entity_value, rows)

    @staticmethod
    async def cross_investigation_entity_summary(
        db: AsyncSession,
        tenant_id: UUID,
        entity_key: str,
    ) -> dict[str, Any]:
        """
        Given an entity key like "user:alice" or "ip:1.2.3.4", return a
        summary of all investigations mentioning this entity.
        """
        parts = entity_key.split(":", 1)
        entity_type = parts[0] if len(parts) == 2 else "host"
        entity_value = parts[1] if len(parts) == 2 else entity_key

        pivot = await PivotEngine.pivot(db, tenant_id, entity_type, entity_value)
        return {
            "entity_key": entity_key,
            "entity_type": entity_type,
            "entity_value": entity_value,
            "investigation_count": pivot.total,
            "investigation_ids": pivot.investigation_ids,
            "max_threat_score": max(
                (r.get("threat_score", 0) for r in pivot.investigation_refs),
                default=0,
            ),
        }

    @staticmethod
    async def list_entity_types() -> list[str]:
        return list(_ENTITY_TYPE_MAP.keys())


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _build_pivot_result(
    entity_type: str,
    entity_value: str,
    rows: list[Investigation],
) -> PivotResult:
    entity_key = f"{entity_type}:{entity_value}"
    investigation_ids = [str(r.investigation_group_id) for r in rows]
    refs = [
        {
            "investigation_id": str(r.investigation_group_id),
            "threat_score": r.threat_score,
            "confidence": r.confidence,
            "status": r.status,
            "verdict": r.verdict,
            "executive_summary": r.executive_summary[:200] if r.executive_summary else "",
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
    return PivotResult(
        entity_key=entity_key,
        entity_type=entity_type,
        investigation_ids=investigation_ids,
        total=len(investigation_ids),
        investigation_refs=refs,
    )

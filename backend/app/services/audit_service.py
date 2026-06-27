from __future__ import annotations

from datetime import UTC
from typing import Any
from uuid import UUID, uuid4

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_request_id
from app.models.audit_log import AuditLog

logger = structlog.get_logger(__name__)


class AuditService:
    """
    Records immutable audit entries for every security-relevant mutation.
    All methods are fire-and-continue: failures are logged but never raised
    to the caller (audit logging must not block or break primary operations).

    Hash chaining: each entry carries `prev_hash` (the previous entry's
    `entry_hash` in this tenant's chain) and `entry_hash` (SHA-256 of the
    canonical serialization of all fields including prev_hash).  This allows
    offline forensic verification that no rows were inserted, modified, or
    deleted between two known checkpoints.
    """

    @staticmethod
    async def log(
        db: AsyncSession,
        *,
        action: str,
        actor_id: UUID | None = None,
        tenant_id: UUID | None = None,
        actor_role: str | None = None,
        permission_used: str | None = None,
        resource_type: str | None = None,
        resource_id: UUID | None = None,
        changes: dict[str, Any] | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """
        Persist an audit log entry with hash chaining.
        Called from services — never from routes.
        Errors are swallowed to prevent audit failures from blocking operations.
        """
        try:
            # SAVEPOINT: a failure here rolls back only this nested transaction,
            # leaving the parent session transaction intact so the caller can
            # still commit the primary operation (e.g. the installer token row).
            async with db.begin_nested():
                # Fetch the most recent entry in this tenant's chain to get prev_hash.
                prev_entry = None
                if tenant_id is not None:
                    result = await db.execute(
                        select(AuditLog.entry_hash)
                        .where(AuditLog.tenant_id == tenant_id)
                        .order_by(AuditLog.created_at.desc())
                        .limit(1)
                    )
                    row = result.first()
                    prev_entry = row[0] if row else None

                # Explicitly generate the UUID so it's available for hash computation
                # before flush (SQLAlchemy populates default=uuid4 only at flush time).
                from datetime import datetime

                entry_id = uuid4()
                now = datetime.now(tz=UTC)
                entry = AuditLog(
                    id=entry_id,
                    action=action,
                    actor_id=actor_id,
                    tenant_id=tenant_id,
                    actor_role=actor_role,
                    permission_used=permission_used,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    changes=changes,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    request_id=get_request_id(),
                    created_at=now,
                    prev_hash=prev_entry,
                )
                entry.entry_hash = entry.compute_entry_hash(prev_entry)
                db.add(entry)
            logger.debug(
                "audit_log_written",
                action=action,
                actor_id=str(actor_id) if actor_id else None,
                tenant_id=str(tenant_id) if tenant_id else None,
            )
        except Exception as exc:
            logger.error(
                "audit_log_failed",
                action=action,
                error=str(exc),
                error_type=type(exc).__name__,
            )

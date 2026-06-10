from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_request_id
from app.models.audit_log import AuditLog

logger = structlog.get_logger(__name__)


class AuditService:
    """
    Records immutable audit entries for every security-relevant mutation.
    All methods are fire-and-continue: failures are logged but never raised
    to the caller (audit logging must not block or break primary operations).
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
        Persist an audit log entry. Called from services — never from routes.
        Errors are swallowed to prevent audit failures from blocking operations.
        """
        try:
            # SAVEPOINT: a failure here rolls back only this nested transaction,
            # leaving the parent session transaction intact so the caller can
            # still commit the primary operation (e.g. the installer token row).
            async with db.begin_nested():
                entry = AuditLog(
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
                )
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

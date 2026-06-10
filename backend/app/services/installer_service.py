from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.core.security import hash_password, verify_password
from app.models.installer_token import InstallerToken, InstallerTokenStatus
from app.schemas.installer import (
    InstallerTokenGenerateRequest,
    InstallerTokenGenerateResponse,
    InstallerTokenResponse,
)
from app.services.audit_service import AuditService

logger = structlog.get_logger(__name__)

# Token TTL: 1 hour per spec
_TOKEN_TTL_MINUTES = 60
# Prefix makes tokens recognisable in logs / bug reports
_TOKEN_PREFIX = "inst_"
# 32 random bytes → 43 URL-safe base64 chars (≈ 256 bits of entropy)
_TOKEN_RANDOM_BYTES = 32


class InstallerService:

    # ─── Generation ───────────────────────────────────────────────────────────

    @staticmethod
    async def generate_installer_token(
        db: AsyncSession,
        tenant_id: UUID,
        payload: InstallerTokenGenerateRequest,
        created_by_id: UUID,
    ) -> InstallerTokenGenerateResponse:
        raw_token = _TOKEN_PREFIX + secrets.token_urlsafe(_TOKEN_RANDOM_BYTES)
        token_hash = hash_password(raw_token)
        # Preview = prefix + first 3 chars of the random part (8 chars total)
        token_preview = raw_token[:8]
        expires_at = datetime.now(tz=timezone.utc) + timedelta(minutes=_TOKEN_TTL_MINUTES)

        token = InstallerToken(
            tenant_id=tenant_id,
            token_hash=token_hash,
            token_preview=token_preview,
            organization=payload.organization,
            machine_name=payload.machine_name,
            status=InstallerTokenStatus.PENDING,
            expires_at=expires_at,
            token_metadata=payload.token_metadata,
            created_by_id=created_by_id,
        )
        db.add(token)
        try:
            await db.flush()
        except Exception as flush_err:
            logger.error(
                "installer_token_flush_failed",
                error=str(flush_err),
                error_type=type(flush_err).__name__,
                tenant_id=str(tenant_id),
            )
            raise

        await AuditService.log(
            db,
            action="installer_token.generated",
            actor_id=created_by_id,
            tenant_id=tenant_id,
            resource_type="installer_token",
            resource_id=token.id,
            changes={
                "organization": payload.organization,
                "machine_name": payload.machine_name,
                "expires_at": expires_at.isoformat(),
            },
        )

        logger.info(
            "installer_token_generated",
            token_id=str(token.id),
            tenant_id=str(tenant_id),
            machine_name=payload.machine_name,
            expires_at=expires_at.isoformat(),
        )

        expires_in = int((expires_at - datetime.now(tz=timezone.utc)).total_seconds())
        return InstallerTokenGenerateResponse(
            id=token.id,
            raw_token=raw_token,
            token_preview=token_preview,
            organization=payload.organization,
            machine_name=payload.machine_name,
            expires_at=expires_at,
            expires_in_seconds=expires_in,
        )

    # ─── Verification (for use by installer self-service endpoint) ────────────

    @staticmethod
    async def verify_installer_token(
        db: AsyncSession,
        token_id: UUID,
        raw_token: str,
    ) -> InstallerToken:
        """
        Validates the raw token against the stored hash.
        Checks: existence, PENDING status, not expired.
        Does NOT transition status — call mark_installing() after.

        Raises NotFoundError or ValidationError on any failure.
        Constant-time: always calls verify_password even on miss to prevent timing attacks.
        """
        result = await db.execute(
            select(InstallerToken).where(InstallerToken.id == token_id)
        )
        token = result.scalar_one_or_none()

        dummy_hash = "$argon2id$v=19$m=65536,t=2,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

        # Always verify hash — prevents timing oracle even on miss
        hash_to_check = token.token_hash if token else dummy_hash
        token_raw_to_check = raw_token if raw_token else ""
        hash_ok = verify_password(token_raw_to_check, hash_to_check)

        if token is None or not hash_ok:
            logger.warning("installer_token_verify_failed", token_id=str(token_id))
            raise NotFoundError("Installer token not found or invalid")

        if token.status != InstallerTokenStatus.PENDING:
            raise ValidationError(
                f"Token cannot be used: status is {token.status.value}",
                details={"status": token.status.value},
            )

        if token.is_expired:
            # Opportunistically mark it expired
            token.status = InstallerTokenStatus.EXPIRED
            await db.flush()
            raise ValidationError(
                "Installer token has expired",
                details={"expired_at": token.expires_at.isoformat()},
            )

        return token

    # ─── Status transitions ───────────────────────────────────────────────────

    @staticmethod
    async def mark_installing(
        db: AsyncSession,
        token: InstallerToken,
    ) -> InstallerToken:
        """
        Atomically transitions PENDING → INSTALLING using SELECT FOR UPDATE.
        Raises ConflictError if another process already claimed the token.
        """
        result = await db.execute(
            select(InstallerToken)
            .where(
                InstallerToken.id == token.id,
                InstallerToken.status == InstallerTokenStatus.PENDING,
            )
            .with_for_update(skip_locked=True)
        )
        locked_token = result.scalar_one_or_none()

        if locked_token is None:
            raise ConflictError(
                "Token is already in use or has been revoked",
                details={"token_id": str(token.id)},
            )

        now = datetime.now(tz=timezone.utc)
        locked_token.status = InstallerTokenStatus.INSTALLING
        locked_token.used_at = now
        await db.flush()

        logger.info(
            "installer_token_mark_installing",
            token_id=str(locked_token.id),
            tenant_id=str(locked_token.tenant_id),
        )
        return locked_token

    @staticmethod
    async def mark_used(
        db: AsyncSession,
        token: InstallerToken,
        device_id: str | None = None,
    ) -> InstallerToken:
        """Transitions INSTALLING → ACTIVE after successful installation."""
        if token.status != InstallerTokenStatus.INSTALLING:
            raise ValidationError(
                "Token must be in INSTALLING state to mark as used",
                details={"status": token.status.value},
            )

        now = datetime.now(tz=timezone.utc)
        token.status = InstallerTokenStatus.ACTIVE
        token.installed_at = now
        if device_id:
            token.device_id = device_id

        await db.flush()
        logger.info(
            "installer_token_activated",
            token_id=str(token.id),
            tenant_id=str(token.tenant_id),
            device_id=device_id,
        )
        return token

    @staticmethod
    async def mark_failed(
        db: AsyncSession,
        token: InstallerToken,
        reason: str | None = None,
    ) -> InstallerToken:
        """Transitions INSTALLING → FAILED when the installer reports an error."""
        if token.status != InstallerTokenStatus.INSTALLING:
            raise ValidationError(
                "Token must be in INSTALLING state to mark as failed",
                details={"status": token.status.value},
            )

        token.status = InstallerTokenStatus.FAILED
        if reason:
            meta = dict(token.token_metadata or {})
            meta["failure_reason"] = reason
            token.token_metadata = meta

        await db.flush()
        logger.warning(
            "installer_token_failed",
            token_id=str(token.id),
            tenant_id=str(token.tenant_id),
            reason=reason,
        )
        return token

    # ─── Revocation ───────────────────────────────────────────────────────────

    @staticmethod
    async def revoke_token(
        db: AsyncSession,
        tenant_id: UUID,
        token_id: UUID,
        revoked_by_id: UUID,
        reason: str | None = None,
    ) -> InstallerToken:
        result = await db.execute(
            select(InstallerToken).where(
                InstallerToken.id == token_id,
                InstallerToken.tenant_id == tenant_id,
            )
        )
        token = result.scalar_one_or_none()
        if token is None:
            raise NotFoundError(f"Installer token {token_id} not found")

        terminal = {InstallerTokenStatus.EXPIRED, InstallerTokenStatus.REVOKED, InstallerTokenStatus.ACTIVE}
        if token.status in terminal:
            raise ConflictError(
                f"Token cannot be revoked: status is {token.status.value}",
                details={"status": token.status.value},
            )

        previous_status = token.status.value  # capture BEFORE mutation

        now = datetime.now(tz=timezone.utc)
        token.status = InstallerTokenStatus.REVOKED
        token.revoked_at = now
        token.revoked_by_id = revoked_by_id
        if reason:
            meta = dict(token.token_metadata or {})
            meta["revocation_reason"] = reason
            token.token_metadata = meta

        await db.flush()

        await AuditService.log(
            db,
            action="installer_token.revoked",
            actor_id=revoked_by_id,
            tenant_id=tenant_id,
            resource_type="installer_token",
            resource_id=token_id,
            changes={"reason": reason, "previous_status": previous_status},
        )

        logger.info(
            "installer_token_revoked",
            token_id=str(token_id),
            tenant_id=str(tenant_id),
            revoked_by=str(revoked_by_id),
        )
        return token

    # ─── Expiry sweep ─────────────────────────────────────────────────────────

    @staticmethod
    async def expire_old_tokens(db: AsyncSession) -> int:
        """
        Bulk-marks PENDING tokens whose expires_at has passed as EXPIRED.
        Designed to be called periodically by a maintenance worker.
        Returns count of tokens expired.
        """
        now = datetime.now(tz=timezone.utc)
        result = await db.execute(
            update(InstallerToken)
            .where(
                InstallerToken.status == InstallerTokenStatus.PENDING,
                InstallerToken.expires_at < now,
            )
            .values(status=InstallerTokenStatus.EXPIRED)
            .returning(InstallerToken.id)
        )
        rows = result.fetchall()
        count = len(rows)

        if count:
            await db.flush()
            logger.info("installer_tokens_expired", count=count)

        return count

    # ─── Bootstrap enrollment ────────────────────────────────────────────────

    @staticmethod
    async def find_pending_by_preview(
        db: AsyncSession,
        tenant_id: UUID,
        token_preview: str,
    ) -> list[InstallerToken]:
        """
        Returns PENDING tokens that match tenant_id + token_preview.
        Used by the bootstrap-enroll endpoint to locate the token record
        without requiring the caller to know the internal token UUID.
        Result set is typically 1 row; caller must Argon2id-verify each.
        """
        result = await db.execute(
            select(InstallerToken).where(
                InstallerToken.tenant_id == tenant_id,
                InstallerToken.token_preview == token_preview,
                InstallerToken.status == InstallerTokenStatus.PENDING,
            )
        )
        return list(result.scalars().all())

    # ─── Read ─────────────────────────────────────────────────────────────────

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        token_id: UUID,
    ) -> InstallerToken | None:
        result = await db.execute(
            select(InstallerToken).where(
                InstallerToken.id == token_id,
                InstallerToken.tenant_id == tenant_id,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def require_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        token_id: UUID,
    ) -> InstallerToken:
        token = await InstallerService.get_by_id(db, tenant_id, token_id)
        if token is None:
            raise NotFoundError(f"Installer token {token_id} not found")
        return token

    @staticmethod
    async def list_tokens(
        db: AsyncSession,
        tenant_id: UUID,
        page: int = 1,
        limit: int = 25,
        status_filter: InstallerTokenStatus | None = None,
    ) -> tuple[list[InstallerToken], int]:
        filters = [InstallerToken.tenant_id == tenant_id]
        if status_filter is not None:
            filters.append(InstallerToken.status == status_filter)

        total = (await db.execute(select(func.count()).where(*filters))).scalar_one()
        offset = (page - 1) * limit
        result = await db.execute(
            select(InstallerToken)
            .where(*filters)
            .order_by(InstallerToken.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(result.scalars().all()), total

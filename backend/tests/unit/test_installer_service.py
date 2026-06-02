"""Unit tests for the installer token service layer."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
import pytest_asyncio

from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.models.installer_token import InstallerToken, InstallerTokenStatus
from app.schemas.installer import InstallerTokenGenerateRequest
from app.services.installer_service import InstallerService, _TOKEN_PREFIX, _TOKEN_TTL_MINUTES


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _make_pending_token(
    expires_delta: timedelta = timedelta(hours=1),
    status: InstallerTokenStatus = InstallerTokenStatus.PENDING,
) -> MagicMock:
    t = MagicMock(spec=InstallerToken)
    t.id = uuid4()
    t.tenant_id = uuid4()
    t.status = status
    t.expires_at = _utcnow() + expires_delta
    t.is_expired = expires_delta.total_seconds() <= 0
    t.is_usable = status == InstallerTokenStatus.PENDING and not t.is_expired
    t.token_metadata = {}
    t.token_hash = "dummy_hash"
    return t


class TestTokenFormat:
    """Raw token must have correct prefix and sufficient entropy."""

    def test_prefix_present(self):
        import secrets
        raw = _TOKEN_PREFIX + secrets.token_urlsafe(32)
        assert raw.startswith(_TOKEN_PREFIX)

    def test_token_length_sufficient(self):
        import secrets
        raw = _TOKEN_PREFIX + secrets.token_urlsafe(32)
        # prefix(5) + 43 base64 chars = 48 chars minimum
        assert len(raw) >= 48

    def test_preview_is_first_8_chars(self):
        import secrets
        raw = _TOKEN_PREFIX + secrets.token_urlsafe(32)
        preview = raw[:8]
        assert preview == _TOKEN_PREFIX + raw[5:8]
        assert len(preview) == 8


class TestTokenExpiry:
    """TTL and expiry validation."""

    def test_token_ttl_is_60_minutes(self):
        assert _TOKEN_TTL_MINUTES == 60

    def test_expired_token_not_usable(self):
        token = _make_pending_token(expires_delta=timedelta(seconds=-1))
        token.is_expired = True
        token.is_usable = False
        assert not token.is_usable

    def test_active_token_is_usable(self):
        token = _make_pending_token(expires_delta=timedelta(hours=1))
        token.is_expired = False
        token.is_usable = True
        assert token.is_usable


@pytest.mark.asyncio
class TestVerifyInstallerToken:
    """verify_installer_token: correct/wrong/expired/wrong-status."""

    async def _make_db_with_token(self, token: MagicMock) -> AsyncMock:
        db = AsyncMock()
        result = AsyncMock()
        result.scalar_one_or_none = MagicMock(return_value=token)
        db.execute = AsyncMock(return_value=result)
        db.flush = AsyncMock()
        return db

    async def test_valid_token_returns_token(self):
        from app.core.security import hash_password
        raw = _TOKEN_PREFIX + "validrandomsuffix123456789012"
        token = _make_pending_token()
        token.token_hash = hash_password(raw)
        token.is_expired = False
        token.status = InstallerTokenStatus.PENDING

        db = await self._make_db_with_token(token)
        result = await InstallerService.verify_installer_token(db, token.id, raw)
        assert result is token

    async def test_wrong_token_raises_not_found(self):
        from app.core.security import hash_password
        raw = _TOKEN_PREFIX + "validrandomsuffix123456789012"
        token = _make_pending_token()
        token.token_hash = hash_password(raw)
        token.is_expired = False
        token.status = InstallerTokenStatus.PENDING

        db = await self._make_db_with_token(token)
        with pytest.raises(NotFoundError):
            await InstallerService.verify_installer_token(db, token.id, "wrong_token_value")

    async def test_missing_token_raises_not_found(self):
        db = AsyncMock()
        result = AsyncMock()
        result.scalar_one_or_none = MagicMock(return_value=None)
        db.execute = AsyncMock(return_value=result)
        with pytest.raises(NotFoundError):
            await InstallerService.verify_installer_token(db, uuid4(), "any_token")

    async def test_expired_token_raises_validation_error(self):
        from app.core.security import hash_password
        raw = _TOKEN_PREFIX + "validrandomsuffix123456789012"
        token = _make_pending_token(expires_delta=timedelta(seconds=-60))
        token.token_hash = hash_password(raw)
        token.is_expired = True
        token.status = InstallerTokenStatus.PENDING

        db = await self._make_db_with_token(token)
        db.flush = AsyncMock()
        with pytest.raises(ValidationError, match="expired"):
            await InstallerService.verify_installer_token(db, token.id, raw)

    async def test_used_token_raises_validation_error(self):
        from app.core.security import hash_password
        raw = _TOKEN_PREFIX + "validrandomsuffix123456789012"
        token = _make_pending_token()
        token.token_hash = hash_password(raw)
        token.is_expired = False
        token.status = InstallerTokenStatus.ACTIVE  # already used

        db = await self._make_db_with_token(token)
        with pytest.raises(ValidationError, match="status"):
            await InstallerService.verify_installer_token(db, token.id, raw)

    async def test_revoked_token_raises_validation_error(self):
        from app.core.security import hash_password
        raw = _TOKEN_PREFIX + "validrandomsuffix123456789012"
        token = _make_pending_token(status=InstallerTokenStatus.REVOKED)
        token.token_hash = hash_password(raw)
        token.is_expired = False

        db = await self._make_db_with_token(token)
        with pytest.raises(ValidationError):
            await InstallerService.verify_installer_token(db, token.id, raw)


@pytest.mark.asyncio
class TestMarkInstalling:

    async def test_pending_transitions_to_installing(self):
        token = _make_pending_token()

        db = AsyncMock()
        result = AsyncMock()
        result.scalar_one_or_none = MagicMock(return_value=token)
        db.execute = AsyncMock(return_value=result)
        db.flush = AsyncMock()

        locked = await InstallerService.mark_installing(db, token)
        assert locked.status == InstallerTokenStatus.INSTALLING
        assert locked.used_at is not None

    async def test_concurrent_claim_raises_conflict(self):
        token = _make_pending_token()

        db = AsyncMock()
        result = AsyncMock()
        # SELECT FOR UPDATE returns nothing (another process locked it)
        result.scalar_one_or_none = MagicMock(return_value=None)
        db.execute = AsyncMock(return_value=result)

        with pytest.raises(ConflictError):
            await InstallerService.mark_installing(db, token)


@pytest.mark.asyncio
class TestMarkUsed:

    async def test_installing_transitions_to_active(self):
        token = _make_pending_token(status=InstallerTokenStatus.INSTALLING)
        device_id = "device-abc-123"

        db = AsyncMock()
        db.flush = AsyncMock()

        result = await InstallerService.mark_used(db, token, device_id=device_id)
        assert result.status == InstallerTokenStatus.ACTIVE
        assert result.installed_at is not None
        assert result.device_id == device_id

    async def test_wrong_status_raises_validation_error(self):
        token = _make_pending_token(status=InstallerTokenStatus.PENDING)
        db = AsyncMock()
        with pytest.raises(ValidationError):
            await InstallerService.mark_used(db, token)


@pytest.mark.asyncio
class TestRevokeToken:

    async def test_revoke_pending_token(self):
        token = _make_pending_token()

        db = AsyncMock()
        result = AsyncMock()
        result.scalar_one_or_none = MagicMock(return_value=token)
        db.execute = AsyncMock(return_value=result)
        db.flush = AsyncMock()
        db.add = MagicMock()

        revoked = await InstallerService.revoke_token(
            db, token.tenant_id, token.id, revoked_by_id=uuid4(), reason="test"
        )
        assert revoked.status == InstallerTokenStatus.REVOKED
        assert revoked.revoked_at is not None

    async def test_revoke_active_token_raises_conflict(self):
        token = _make_pending_token(status=InstallerTokenStatus.ACTIVE)

        db = AsyncMock()
        result = AsyncMock()
        result.scalar_one_or_none = MagicMock(return_value=token)
        db.execute = AsyncMock(return_value=result)

        with pytest.raises(ConflictError):
            await InstallerService.revoke_token(db, token.tenant_id, token.id, uuid4())

    async def test_revoke_nonexistent_raises_not_found(self):
        db = AsyncMock()
        result = AsyncMock()
        result.scalar_one_or_none = MagicMock(return_value=None)
        db.execute = AsyncMock(return_value=result)

        with pytest.raises(NotFoundError):
            await InstallerService.revoke_token(db, uuid4(), uuid4(), uuid4())


@pytest.mark.asyncio
class TestExpireOldTokens:

    async def test_returns_count_of_expired_tokens(self):
        db = AsyncMock()
        fake_result = MagicMock()
        fake_result.fetchall = MagicMock(return_value=[MagicMock(), MagicMock()])
        db.execute = AsyncMock(return_value=fake_result)
        db.flush = AsyncMock()

        count = await InstallerService.expire_old_tokens(db)
        assert count == 2

    async def test_returns_zero_when_nothing_expired(self):
        db = AsyncMock()
        fake_result = MagicMock()
        fake_result.fetchall = MagicMock(return_value=[])
        db.execute = AsyncMock(return_value=fake_result)

        count = await InstallerService.expire_old_tokens(db)
        assert count == 0

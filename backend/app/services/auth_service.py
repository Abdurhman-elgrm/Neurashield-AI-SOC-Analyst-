from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import ConflictError, UnauthorizedError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import TokenPair
from app.services.audit_service import AuditService
from app.services.user_service import UserService

logger = structlog.get_logger(__name__)


class AuthService:

    @staticmethod
    async def register(
        db: AsyncSession,
        email: str,
        password: str,
        full_name: str,
        ip_address: str | None = None,
    ) -> tuple[User, TokenPair]:
        """
        Registers a new global user account.
        Raises ConflictError if the email is already in use.
        """
        if await UserService.email_exists(db, email):
            raise ConflictError("An account with this email address already exists")

        password_hash = hash_password(password)
        user = await UserService.create(db, email, password_hash, full_name)

        token_pair = await AuthService._issue_token_pair(db, user)

        await AuditService.log(
            db,
            action="user.registered",
            actor_id=user.id,
            resource_type="user",
            resource_id=user.id,
            ip_address=ip_address,
        )

        return user, token_pair

    @staticmethod
    async def login(
        db: AsyncSession,
        email: str,
        password: str,
        ip_address: str | None = None,
    ) -> tuple[User, TokenPair]:
        """
        Authenticates a user by email/password.
        Always takes the same time path regardless of whether the user exists
        to prevent user enumeration via timing attacks.
        """
        user = await UserService.get_by_email(db, email)

        if user is None:
            # Perform a dummy hash to normalize timing
            hash_password(password)
            raise UnauthorizedError("Invalid email or password")

        if not verify_password(password, user.password_hash):
            await AuditService.log(
                db,
                action="user.login_failed",
                actor_id=user.id,
                resource_type="user",
                resource_id=user.id,
                ip_address=ip_address,
            )
            raise UnauthorizedError("Invalid email or password")

        if not user.is_active:
            raise UnauthorizedError("Account is disabled")

        # Upgrade hash if parameters changed (transparent to user)
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
            await db.flush([user])

        token_pair = await AuthService._issue_token_pair(db, user)

        await AuditService.log(
            db,
            action="user.login",
            actor_id=user.id,
            resource_type="user",
            resource_id=user.id,
            ip_address=ip_address,
        )

        return user, token_pair

    @staticmethod
    async def refresh(
        db: AsyncSession,
        refresh_token_str: str,
    ) -> TokenPair:
        """
        Validates a refresh token and issues a new token pair.
        Implements token rotation: the old refresh token is revoked and replaced.
        """
        payload = decode_refresh_token(refresh_token_str)

        try:
            user_id = UUID(payload.sub)
        except ValueError:
            raise UnauthorizedError("Malformed refresh token")

        # Look up the persisted token record by JTI
        assert payload.jti is not None
        stored = await AuthService._get_refresh_token_by_jti(db, payload.jti)
        if stored is None or not stored.is_valid:
            raise UnauthorizedError("Refresh token has been revoked or expired")

        user = await UserService.get_by_id(db, user_id)
        if user is None or not user.is_active:
            raise UnauthorizedError("User not found or inactive")

        # Revoke the old token before issuing new one (token rotation)
        stored.revoke()
        await db.flush([stored])

        token_pair = await AuthService._issue_token_pair(db, user)
        logger.info("refresh_token_rotated", user_id=str(user_id))
        return token_pair

    @staticmethod
    async def logout(db: AsyncSession, refresh_token_str: str) -> None:
        """
        Revokes the refresh token. Access token expiry is handled by its short TTL.
        """
        try:
            payload = decode_refresh_token(refresh_token_str)
            assert payload.jti is not None
            stored = await AuthService._get_refresh_token_by_jti(db, payload.jti)
            if stored and stored.revoked_at is None:
                stored.revoke()
                await db.flush([stored])
        except Exception:
            # Logout should never raise — silently discard invalid tokens
            pass

    # ─── Private helpers ──────────────────────────────────────────────────────

    @staticmethod
    async def _issue_token_pair(db: AsyncSession, user: User) -> TokenPair:
        """Creates and persists a new access + refresh token pair."""
        access_token = create_access_token(subject=str(user.id))
        refresh_token_str, jti = create_refresh_token(subject=str(user.id))

        expire = datetime.now(tz=timezone.utc) + timedelta(
            days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
        )
        token_record = RefreshToken(
            user_id=user.id,
            jti=jti,
            expires_at=expire,
        )
        db.add(token_record)
        await db.flush([token_record])

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token_str,
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    @staticmethod
    async def _get_refresh_token_by_jti(
        db: AsyncSession, jti: str
    ) -> RefreshToken | None:
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.jti == jti)
        )
        return result.scalar_one_or_none()

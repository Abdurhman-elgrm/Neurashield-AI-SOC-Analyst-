from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ServiceUnavailableError,
    UnauthorizedError,
)
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

_VERIFICATION_TOKEN_BYTES = 32
_VERIFICATION_EXPIRY_HOURS = 24


def _generate_verification_token() -> str:
    return secrets.token_urlsafe(_VERIFICATION_TOKEN_BYTES)


def _hash_token_for_storage(token: str) -> str:
    """SHA-256 hex of a one-time token. Stored in DB; raw token goes in the email link."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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
        Sends a verification email; the account is functional immediately
        but login will be blocked after the first session until verified.
        """
        if await UserService.email_exists(db, email):
            raise ConflictError("An account with this email address already exists")

        password_hash = hash_password(password)
        verification_token = _generate_verification_token()

        user = await UserService.create(
            db,
            email,
            password_hash,
            full_name,
            email_verified=False,
            email_verification_token=_hash_token_for_storage(verification_token),
        )

        # Issue a *limited* token pair — access token carries an `unverified`
        # claim so middleware/guards can restrict sensitive actions until the
        # email is confirmed.  Full access is granted only after verification
        # (the /login flow already enforces email_verified == True).
        token_pair = await AuthService._issue_token_pair(db, user, email_verified=False)

        await AuditService.log(
            db,
            action="user.registered",
            actor_id=user.id,
            resource_type="user",
            resource_id=user.id,
            ip_address=ip_address,
        )

        # Send verification email synchronously before returning — must be awaited here
        # because the SQLAlchemy session commits and closes after this method returns,
        # which would expire ORM attributes, making them inaccessible from a background task.
        from app.services.email_service import send_verification_email

        verify_url = f"{settings.FRONTEND_URL}/verify-email?token={verification_token}"
        # Use local string variables (not ORM attributes) so there's no session dependency.
        _email = email.lower().strip()
        _full_name = full_name.strip()
        _user_id = str(user.id)

        try:
            sent = await send_verification_email(_email, _full_name, verify_url)
            if not sent:
                logger.warning("verification_email_not_sent", user_id=_user_id)
            else:
                logger.info("verification_email_sent", user_id=_user_id)
        except Exception as exc:
            logger.warning("verification_email_error", user_id=_user_id, error=str(exc))

        return user, token_pair

    @staticmethod
    async def login(
        db: AsyncSession,
        email: str,
        password: str,
        ip_address: str | None = None,
        mfa_code: str | None = None,
    ) -> tuple[User, TokenPair]:
        """
        Authenticates a user by email/password.
        Always takes the same time path regardless of whether the user exists
        to prevent user enumeration via timing attacks.
        Raises ForbiddenError if the email has not been verified.
        """
        user = await UserService.get_by_email(db, email)

        if user is None:
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

        if not user.email_verified:
            raise ForbiddenError(
                "Please verify your email address before logging in. "
                "Check your inbox or request a new verification link.",
                details={"code": "EMAIL_NOT_VERIFIED"},
            )

        if user.totp_enabled:
            if mfa_code is None:
                raise ForbiddenError(
                    "Multi-factor authentication is required for this account",
                    details={"code": "MFA_REQUIRED"},
                )
            from app.services.mfa_service import MFAService

            if not MFAService.verify_totp(user, mfa_code) and not MFAService.verify_backup_code(
                user, mfa_code
            ):
                await AuditService.log(
                    db,
                    action="user.mfa_failed",
                    actor_id=user.id,
                    resource_type="user",
                    resource_id=user.id,
                    ip_address=ip_address,
                )
                raise UnauthorizedError("Invalid MFA code")

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
    async def verify_email(db: AsyncSession, token: str) -> User:
        """
        Verifies the email address associated with the given token.
        Raises NotFoundError if the token is invalid or expired.
        """
        user = await UserService.get_by_verification_token(db, _hash_token_for_storage(token))
        if user is None:
            raise NotFoundError("Verification link is invalid or has already been used")

        # Check expiry (24 hours)
        if user.email_verification_sent_at:
            sent_at = user.email_verification_sent_at
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=UTC)
            if datetime.now(tz=UTC) - sent_at > timedelta(hours=_VERIFICATION_EXPIRY_HOURS):
                raise NotFoundError("Verification link has expired. Please request a new one.")

        user.email_verified = True
        user.email_verification_token = None
        user.email_verification_sent_at = None
        await db.flush([user])

        await AuditService.log(
            db,
            action="user.email_verified",
            actor_id=user.id,
            resource_type="user",
            resource_id=user.id,
        )

        logger.info("email_verified", user_id=str(user.id), email=user.email)
        return user

    @staticmethod
    async def resend_verification(db: AsyncSession, email: str) -> None:
        """
        Generates a new verification token and resends the verification email.
        Silently succeeds even if the email is not found (prevents enumeration).
        """
        user = await UserService.get_by_email(db, email)
        if user is None or user.email_verified:
            return

        # Rate limit: don't resend if last email was sent < 1 minute ago.
        if user.email_verification_sent_at:
            sent_at = user.email_verification_sent_at
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=UTC)
            if datetime.now(tz=UTC) - sent_at < timedelta(minutes=1):
                logger.info(
                    "resend_verification_rate_limited",
                    user_id=str(user.id),
                    retry_after_seconds=int(
                        (sent_at + timedelta(minutes=1) - datetime.now(tz=UTC)).total_seconds()
                    ),
                )
                return

        new_token = _generate_verification_token()
        user.email_verification_token = _hash_token_for_storage(new_token)
        user.email_verification_sent_at = datetime.now(tz=UTC)
        await db.flush([user])

        from app.services.email_service import send_verification_email

        verify_url = f"{settings.FRONTEND_URL}/verify-email?token={new_token}"
        try:
            sent = await send_verification_email(user.email, user.full_name, verify_url)
            if not sent:
                logger.warning("resend_verification_email_not_sent", user_id=str(user.id))
            else:
                logger.info("resend_verification_email_sent", user_id=str(user.id))
        except Exception as exc:
            logger.warning("resend_verification_email_error", user_id=str(user.id), error=str(exc))

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
            raise UnauthorizedError("Malformed refresh token") from None

        if payload.jti is None:
            raise UnauthorizedError("Refresh token missing JTI")
        stored = await AuthService._get_refresh_token_by_jti(db, payload.jti)
        if stored is None or not stored.is_valid:
            raise UnauthorizedError("Refresh token has been revoked or expired")

        user = await UserService.get_by_id(db, user_id)
        if user is None or not user.is_active:
            raise UnauthorizedError("User not found or inactive")

        # Issue the new token pair BEFORE revoking the old one.
        # If _issue_token_pair raises (e.g. DB constraint), the old token
        # stays valid so the client can retry — otherwise they would be
        # permanently locked out with no usable token.
        token_pair = await AuthService._issue_token_pair(db, user)

        stored.revoke()
        await db.flush([stored])

        logger.info("refresh_token_rotated", user_id=str(user_id))
        return token_pair

    @staticmethod
    async def logout(db: AsyncSession, refresh_token_str: str) -> None:
        """
        Revokes the refresh token. Access token expiry is handled by its short TTL.
        Swallows invalid/expired token errors; raises ServiceUnavailableError on DB failure.
        """
        try:
            payload = decode_refresh_token(refresh_token_str)
        except Exception:
            return

        if payload.jti is None:
            return

        jti = payload.jti
        try:
            stored = await AuthService._get_refresh_token_by_jti(db, jti)
            if stored and stored.revoked_at is None:
                stored.revoke()
                await db.flush([stored])
        except Exception as exc:
            logger.warning(
                "refresh_token_revocation_failed",
                jti=jti,
                error=str(exc),
            )
            raise ServiceUnavailableError("Logout failed — please try again") from exc

    # ─── Private helpers ──────────────────────────────────────────────────────

    @staticmethod
    async def _issue_token_pair(
        db: AsyncSession,
        user: User,
        email_verified: bool | None = None,
    ) -> TokenPair:
        # Allow caller to override the verified claim (e.g. during registration
        # before the user has clicked the link).  Defaults to the DB value.
        verified = email_verified if email_verified is not None else user.email_verified
        access_token = create_access_token(
            subject=str(user.id),
            extra={"email_verified": verified},
        )
        refresh_token_str, jti = create_refresh_token(subject=str(user.id))

        expire = datetime.now(tz=UTC) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
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
    async def forgot_password(db: AsyncSession, email: str) -> None:
        """
        Silently succeeds for unknown/inactive emails to prevent user enumeration.
        Rate-limited: only 1 reset email allowed per 1-minute window per account.
        """
        user = await UserService.get_by_email(db, email)
        if user is None or not user.is_active:
            return

        if user.password_reset_sent_at:
            sent_at = user.password_reset_sent_at
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=UTC)
            if datetime.now(tz=UTC) - sent_at < timedelta(minutes=1):
                logger.info(
                    "forgot_password_rate_limited",
                    user_id=str(user.id),
                    retry_after_seconds=int(
                        (sent_at + timedelta(minutes=1) - datetime.now(tz=UTC)).total_seconds()
                    ),
                )
                return

        token = _generate_verification_token()
        user.password_reset_token = _hash_token_for_storage(token)
        user.password_reset_sent_at = datetime.now(tz=UTC)
        await db.flush([user])

        from app.services.email_service import send_password_reset_email

        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
        try:
            sent = await send_password_reset_email(user.email, user.full_name, reset_url)
            if not sent:
                logger.warning("forgot_password_email_not_sent", user_id=str(user.id))
            else:
                logger.info("forgot_password_email_sent", user_id=str(user.id))
        except Exception as exc:
            logger.warning("forgot_password_email_error", user_id=str(user.id), error=str(exc))

    @staticmethod
    async def reset_password(db: AsyncSession, token: str, new_password: str) -> None:
        """
        Validates the reset token (1-hour expiry), updates the password hash,
        and clears the token so it cannot be reused.
        """
        result = await db.execute(
            select(User).where(User.password_reset_token == _hash_token_for_storage(token))
        )
        user = result.scalar_one_or_none()

        if user is None:
            raise NotFoundError("Password reset link is invalid or has already been used")

        if user.password_reset_sent_at:
            sent_at = user.password_reset_sent_at
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=UTC)
            if datetime.now(tz=UTC) - sent_at > timedelta(hours=1):
                raise NotFoundError("Password reset link has expired — please request a new one")

        user.password_hash = hash_password(new_password)
        user.password_reset_token = None
        user.password_reset_sent_at = None
        revoked = await AuthService._revoke_all_user_sessions(db, user.id)
        logger.info("sessions_revoked_on_password_reset", user_id=str(user.id), count=revoked)
        await db.flush([user])

        await AuditService.log(
            db,
            action="user.password_reset",
            actor_id=user.id,
            resource_type="user",
            resource_id=user.id,
        )
        logger.info("password_reset_completed", user_id=str(user.id))

    @staticmethod
    async def change_password(
        db: AsyncSession,
        user_id: UUID,
        current_password: str,
        new_password: str,
    ) -> None:
        """Verifies current password then replaces the hash."""
        user = await UserService.get_by_id(db, user_id)
        if user is None:
            raise NotFoundError("User not found")
        if not verify_password(current_password, user.password_hash):
            raise UnauthorizedError("Current password is incorrect")
        user.password_hash = hash_password(new_password)
        revoked = await AuthService._revoke_all_user_sessions(db, user.id)
        logger.info("sessions_revoked_on_password_change", user_id=str(user.id), count=revoked)
        await db.flush([user])
        await AuditService.log(
            db,
            action="user.password_changed",
            actor_id=user.id,
            resource_type="user",
            resource_id=user.id,
        )

    @staticmethod
    async def _revoke_all_user_sessions(db: AsyncSession, user_id: UUID) -> int:
        """Revokes all active refresh tokens for a user. Returns count revoked."""
        from datetime import datetime

        from sqlalchemy import update as sa_update

        result = await db.execute(
            sa_update(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(tz=UTC))
            .execution_options(synchronize_session=False)
        )
        return result.rowcount

    @staticmethod
    async def _get_refresh_token_by_jti(db: AsyncSession, jti: str) -> RefreshToken | None:
        result = await db.execute(select(RefreshToken).where(RefreshToken.jti == jti))
        return result.scalar_one_or_none()

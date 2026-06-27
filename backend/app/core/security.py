from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import structlog
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from jose import ExpiredSignatureError, JWTError, jwt

from app.core.config import settings

logger = structlog.get_logger(__name__)

# ─── Argon2id password hasher ─────────────────────────────────────────────────
# Parameters tuned for security/performance balance on typical server hardware.
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, plain)
    except VerifyMismatchError:
        return False
    except (InvalidHashError, VerificationError) as exc:
        logger.warning("password_verify_error", error=str(exc))
        return False


def needs_rehash(hashed: str) -> bool:
    return _hasher.check_needs_rehash(hashed)


# ─── Agent enrollment token hashing (HMAC-SHA256) ────────────────────────────
# Agent enrollment tokens are server-generated (256-bit random) so they do not
# need the brute-force resistance of Argon2id. HMAC-SHA256 is ~10 000× faster
# and safe for machine-generated tokens, making it viable on the hot ingest path.
#
# Format stored in the DB: "hmac_sha256:{hex_digest}"
# Legacy Argon2id hashes (prefix "$argon2id$") are still accepted to allow a
# zero-downtime migration; they are not automatically re-hashed because that
# would require the plaintext token to be available again at verify time.

_HMAC_AGENT_PREFIX = "hmac_sha256:"


def hash_agent_token(raw_token: str) -> str:
    """Return an HMAC-SHA256 digest of raw_token keyed with JWT_SECRET."""
    digest = hmac.new(
        settings.JWT_SECRET.encode(),
        raw_token.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{_HMAC_AGENT_PREFIX}{digest}"


def verify_agent_token(raw_token: str, stored_hash: str) -> bool:
    """
    Verify a raw agent enrollment token against its stored hash.
    Supports both HMAC-SHA256 (new) and legacy Argon2id hashes.
    Always constant-time to prevent timing oracles.
    """
    if stored_hash.startswith(_HMAC_AGENT_PREFIX):
        expected = hash_agent_token(raw_token)
        return hmac.compare_digest(expected, stored_hash)
    # Legacy Argon2id path — used during migration window.
    return verify_password(raw_token, stored_hash)


# ─── JWT ─────────────────────────────────────────────────────────────────────


def _get_encode_key_access() -> str:
    """Return the signing key for access tokens (private key for RS256, secret for HS256)."""
    if settings.JWT_ALGORITHM == "RS256":
        return settings.JWT_PRIVATE_KEY
    return settings.JWT_SECRET


def _get_decode_key_access() -> str:
    """Return the verification key for access tokens (public key for RS256, secret for HS256)."""
    if settings.JWT_ALGORITHM == "RS256":
        return settings.JWT_PUBLIC_KEY
    return settings.JWT_SECRET


def _get_encode_key_refresh() -> str:
    if settings.JWT_ALGORITHM == "RS256":
        return settings.JWT_PRIVATE_KEY
    return settings.JWT_REFRESH_SECRET


def _get_decode_key_refresh() -> str:
    if settings.JWT_ALGORITHM == "RS256":
        return settings.JWT_PUBLIC_KEY
    return settings.JWT_REFRESH_SECRET


class TokenPayload:
    def __init__(
        self,
        sub: str,
        token_type: str,
        jti: str | None = None,
        email_verified: bool = True,
    ) -> None:
        self.sub = sub
        self.token_type = token_type
        self.jti = jti
        self.email_verified = email_verified


def create_access_token(subject: str, extra: dict[str, Any] | None = None) -> str:
    """
    Creates a short-lived JWT access token.
    subject: user UUID as string.
    """
    expire = datetime.now(tz=UTC) + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": "access",
        "exp": expire,
        "iat": datetime.now(tz=UTC),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, _get_encode_key_access(), algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str) -> tuple[str, str]:
    """
    Creates a refresh token with a unique JTI for revocation support.
    Returns (encoded_token, jti).
    """
    jti = str(uuid4())
    expire = datetime.now(tz=UTC) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": "refresh",
        "jti": jti,
        "exp": expire,
        "iat": datetime.now(tz=UTC),
    }
    token = jwt.encode(payload, _get_encode_key_refresh(), algorithm=settings.JWT_ALGORITHM)
    return token, jti


def decode_access_token(token: str) -> TokenPayload:
    """
    Decodes and validates an access token.
    Raises UnauthorizedError on any failure — callers should not catch JWTError.
    """
    from app.core.exceptions import UnauthorizedError

    try:
        payload = jwt.decode(
            token,
            _get_decode_key_access(),
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("type") != "access":
            raise UnauthorizedError("Invalid token type")
        sub: str | None = payload.get("sub")
        if not sub:
            raise UnauthorizedError("Token missing subject")
        # email_verified defaults to True for backward-compat with tokens
        # issued before this claim was introduced.
        email_verified: bool = payload.get("email_verified", True)
        return TokenPayload(sub=sub, token_type="access", email_verified=email_verified)
    except ExpiredSignatureError:
        raise UnauthorizedError("Token has expired") from None
    except JWTError as exc:
        logger.debug("jwt_decode_failed", error=str(exc))
        raise UnauthorizedError("Invalid token") from None


def decode_refresh_token(token: str) -> TokenPayload:
    """Decodes and validates a refresh token."""
    from app.core.exceptions import UnauthorizedError

    try:
        payload = jwt.decode(
            token,
            _get_decode_key_refresh(),
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("type") != "refresh":
            raise UnauthorizedError("Invalid token type")
        sub: str | None = payload.get("sub")
        jti: str | None = payload.get("jti")
        if not sub or not jti:
            raise UnauthorizedError("Token missing required claims")
        return TokenPayload(sub=sub, token_type="refresh", jti=jti)
    except ExpiredSignatureError:
        raise UnauthorizedError("Refresh token has expired") from None
    except JWTError as exc:
        logger.debug("refresh_token_decode_failed", error=str(exc))
        raise UnauthorizedError("Invalid refresh token") from None

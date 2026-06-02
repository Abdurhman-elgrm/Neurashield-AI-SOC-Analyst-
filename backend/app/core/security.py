from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import structlog
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError
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


# ─── JWT ─────────────────────────────────────────────────────────────────────

class TokenPayload:
    def __init__(self, sub: str, token_type: str, jti: str | None = None) -> None:
        self.sub = sub
        self.token_type = token_type
        self.jti = jti


def create_access_token(subject: str, extra: dict[str, Any] | None = None) -> str:
    """
    Creates a short-lived JWT access token.
    subject: user UUID as string.
    """
    expire = datetime.now(tz=timezone.utc) + timedelta(
        minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload: dict[str, Any] = {
        "sub": subject,
        "type": "access",
        "exp": expire,
        "iat": datetime.now(tz=timezone.utc),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str) -> tuple[str, str]:
    """
    Creates a refresh token with a unique JTI for revocation support.
    Returns (encoded_token, jti).
    """
    jti = str(uuid4())
    expire = datetime.now(tz=timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": "refresh",
        "jti": jti,
        "exp": expire,
        "iat": datetime.now(tz=timezone.utc),
    }
    token = jwt.encode(payload, settings.JWT_REFRESH_SECRET, algorithm=settings.JWT_ALGORITHM)
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
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("type") != "access":
            raise UnauthorizedError("Invalid token type")
        sub: str | None = payload.get("sub")
        if not sub:
            raise UnauthorizedError("Token missing subject")
        return TokenPayload(sub=sub, token_type="access")
    except ExpiredSignatureError:
        raise UnauthorizedError("Token has expired")
    except JWTError as exc:
        logger.debug("jwt_decode_failed", error=str(exc))
        raise UnauthorizedError("Invalid token")


def decode_refresh_token(token: str) -> TokenPayload:
    """Decodes and validates a refresh token."""
    from app.core.exceptions import UnauthorizedError

    try:
        payload = jwt.decode(
            token,
            settings.JWT_REFRESH_SECRET,
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
        raise UnauthorizedError("Refresh token has expired")
    except JWTError as exc:
        logger.debug("refresh_token_decode_failed", error=str(exc))
        raise UnauthorizedError("Invalid refresh token")

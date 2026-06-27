from __future__ import annotations

import threading
import time as _monotime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import CurrentUser
from app.core.exceptions import RateLimitError, UnauthorizedError
from app.core.redis import get_redis_optional
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenPair
from app.schemas.common import APIResponse, EmptyResponse
from app.schemas.user import UserResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])

_LOGIN_RATE_LIMIT       = 10     # attempts
_LOGIN_RATE_WINDOW      = 900    # 15 minutes
_REGISTER_RATE_LIMIT    = 5      # attempts
_REGISTER_RATE_WINDOW   = 3600   # 1 hour
_ACCOUNT_LOCKOUT_LIMIT  = 20     # total failed attempts across all IPs
_ACCOUNT_LOCKOUT_WINDOW = 1800   # 30-minute lockout window


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=7 * 24 * 3600,
        path="/api/v1/auth",
    )


def _extract_client_ip(request: Request) -> str:
    """
    Resolve the real client IP.

    On Railway (and most PaaS) the platform sets X-Forwarded-For and the
    direct TCP peer is the platform's own load-balancer.  We take the
    *last* (rightmost) non-private IP appended by a trusted proxy to
    prevent spoofing: an attacker-controlled header like
      X-Forwarded-For: 1.1.1.1
    would appear as the *first* entry while the load-balancer appends the
    real client address at the right.

    Falls back to the TCP peer address when no XFF header is present
    (local dev, direct connection).
    """
    import ipaddress

    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        candidates = [ip.strip() for ip in reversed(xff.split(",")) if ip.strip()]
        for candidate in candidates:
            try:
                addr = ipaddress.ip_address(candidate)
                if not addr.is_private and not addr.is_loopback and not addr.is_link_local:
                    return candidate
            except ValueError:
                continue
        # All candidates are private/loopback — take the first one (internal network)
        if candidates:
            return candidates[-1]

    return request.client.host if request.client else "unknown"



# Atomic Lua script: INCR + EXPIRE in a single round-trip.
# Eliminates the INCR/EXPIRE race condition where a crash between the two
# operations would leave the key without a TTL (counter lives forever).
_RATE_LIMIT_LUA = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""


class _InMemoryRateLimiter:
    """
    Thread-safe fixed-window rate limiter used when Redis is unavailable.
    Bounded to _MAX_KEYS entries to prevent unbounded memory growth.
    """
    _MAX_KEYS = 10_000

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, tuple[int, float]] = {}  # key → (count, window_start)

    def check_and_increment(self, key: str, limit: int, window: int) -> int:
        """Increments counter and returns new count. Thread-safe."""
        now = _monotime.monotonic()
        with self._lock:
            count, start = self._counters.get(key, (0, now))
            if now - start >= window:
                count, start = 0, now
            count += 1
            self._counters[key] = (count, start)
            if len(self._counters) > self._MAX_KEYS:
                oldest_key = min(self._counters, key=lambda k: self._counters[k][1])
                del self._counters[oldest_key]
            return count


_in_memory_limiter = _InMemoryRateLimiter()


async def _check_rate_limit(
    redis: object | None,
    key: str,
    limit: int,
    window: int,
) -> None:
    """
    Fixed-window rate limiter. Uses Redis when available; falls back to an
    in-process counter when Redis is down. Always enforces the limit —
    never silently allows unlimited requests.
    """
    if redis is None:
        import structlog as _structlog
        _structlog.get_logger(__name__).warning(
            "rate_limit_redis_unavailable_memory_fallback",
            key=key,
        )
        current = _in_memory_limiter.check_and_increment(key, limit, window)
        if current > limit:
            raise RateLimitError(
                f"Too many attempts — try again in {window // 60} minutes",
                retry_after=window,
            )
        return

    from redis.asyncio import Redis as _RedisType
    from redis.exceptions import RedisError

    r: _RedisType = redis  # type: ignore[assignment]
    try:
        current = int(await r.eval(_RATE_LIMIT_LUA, 1, key, window))
        if current > limit:
            raise RateLimitError(
                f"Too many attempts — try again in {window // 60} minutes",
                retry_after=window,
            )
    except RateLimitError:
        raise
    except RedisError as exc:
        import structlog as _structlog
        _structlog.get_logger(__name__).error(
            "rate_limit_redis_error_using_memory_fallback",
            key=key,
            error=str(exc),
        )
        current = _in_memory_limiter.check_and_increment(key, limit, window)
        if current > limit:
            raise RateLimitError(
                f"Too many attempts — try again in {window // 60} minutes",
                retry_after=window,
            )


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=10)
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        from app.schemas.auth import _validate_password_strength
        return _validate_password_strength(v)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        from app.schemas.auth import _validate_password_strength
        return _validate_password_strength(v)


@router.post(
    "/register",
    response_model=APIResponse[TokenPair],
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(
    payload: RegisterRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[TokenPair]:
    ip = _extract_client_ip(request)
    await _check_rate_limit(redis, f"auth_register_ip:{ip}", _REGISTER_RATE_LIMIT, _REGISTER_RATE_WINDOW)

    _user, token_pair = await AuthService.register(
        db,
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
        ip_address=ip,
    )
    _set_refresh_cookie(response, token_pair.refresh_token)
    return APIResponse.ok(token_pair)


@router.post(
    "/login",
    response_model=APIResponse[TokenPair],
    summary="Authenticate and receive token pair",
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[TokenPair]:
    ip = _extract_client_ip(request)
    await _check_rate_limit(redis, f"auth_login_ip:{ip}", _LOGIN_RATE_LIMIT, _LOGIN_RATE_WINDOW)

    # Per-account lockout — SHA-256 prefix of email so no PII is stored in Redis
    import hashlib as _hashlib
    _email_key = f"auth_lockout_acct:{_hashlib.sha256(payload.email.lower().encode()).hexdigest()[:24]}"
    await _check_rate_limit(redis, _email_key, _ACCOUNT_LOCKOUT_LIMIT, _ACCOUNT_LOCKOUT_WINDOW)

    _user, token_pair = await AuthService.login(
        db,
        email=payload.email,
        password=payload.password,
        ip_address=ip,
        mfa_code=payload.mfa_code,
    )
    _set_refresh_cookie(response, token_pair.refresh_token)
    return APIResponse.ok(token_pair)


@router.post(
    "/refresh",
    response_model=APIResponse[TokenPair],
    summary="Rotate tokens using a valid refresh token",
)
async def refresh_tokens(
    request: Request,
    response: Response,
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> APIResponse[TokenPair]:
    refresh_token = payload.refresh_token
    if not refresh_token:
        refresh_token = request.cookies.get("refresh_token", "")
    if not refresh_token:
        raise UnauthorizedError("Refresh token required")

    token_pair = await AuthService.refresh(db, refresh_token)
    _set_refresh_cookie(response, token_pair.refresh_token)
    return APIResponse.ok(token_pair)


@router.post(
    "/logout",
    response_model=APIResponse[EmptyResponse],
    summary="Revoke refresh token",
)
async def logout(
    request: Request,
    response: Response,
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> APIResponse[EmptyResponse]:
    refresh_token = payload.refresh_token
    if not refresh_token:
        refresh_token = request.cookies.get("refresh_token", "")
    await AuthService.logout(db, refresh_token)
    response.delete_cookie(key="refresh_token", path="/api/v1/auth")
    return APIResponse.ok(EmptyResponse())


@router.get(
    "/me",
    response_model=APIResponse[UserResponse],
    summary="Get the currently authenticated user",
)
async def get_me(current_user: CurrentUser) -> APIResponse[UserResponse]:
    return APIResponse.ok(UserResponse.model_validate(current_user))


@router.get(
    "/verify-email",
    response_model=APIResponse[EmptyResponse],
    summary="Verify email address using one-time token",
)
async def verify_email(
    token: str = Query(..., min_length=10, description="Email verification token"),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[EmptyResponse]:
    await AuthService.verify_email(db, token)
    return APIResponse.ok(EmptyResponse())


@router.post(
    "/resend-verification",
    response_model=APIResponse[EmptyResponse],
    summary="Resend email verification link",
)
async def resend_verification(
    payload: ResendVerificationRequest,
    db: AsyncSession = Depends(get_db),
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[EmptyResponse]:
    import hashlib as _hashlib
    _email_hash = _hashlib.sha256(payload.email.lower().encode()).hexdigest()[:24]
    await _check_rate_limit(
        redis,
        f"auth_resend_verify:{_email_hash}",
        limit=10,
        window=3600,
    )
    await AuthService.resend_verification(db, payload.email)
    return APIResponse.ok(EmptyResponse())



@router.post(
    "/forgot-password",
    response_model=APIResponse[EmptyResponse],
    summary="Request a password reset email",
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[EmptyResponse]:
    import hashlib as _hashlib
    _email_hash = _hashlib.sha256(payload.email.lower().encode()).hexdigest()[:24]
    await _check_rate_limit(
        redis,
        f"auth_forgot_pw:{_email_hash}",
        limit=10,
        window=3600,
    )
    await AuthService.forgot_password(db, payload.email)
    return APIResponse.ok(EmptyResponse())


@router.post(
    "/reset-password",
    response_model=APIResponse[EmptyResponse],
    summary="Reset password using a one-time token",
)
async def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[EmptyResponse]:
    ip = _extract_client_ip(request)
    await _check_rate_limit(redis, f"auth_reset_pw_ip:{ip}", limit=10, window=3600)
    await AuthService.reset_password(db, payload.token, payload.new_password)
    return APIResponse.ok(EmptyResponse())


@router.post(
    "/change-password",
    response_model=APIResponse[EmptyResponse],
    summary="Change password for the authenticated user",
)
async def change_password(
    payload: ChangePasswordRequest,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[EmptyResponse]:
    import hashlib as _hashlib
    _uid_hash = _hashlib.sha256(str(current_user.id).encode()).hexdigest()[:24]
    await _check_rate_limit(redis, f"auth_change_pw:{_uid_hash}", limit=10, window=3600)
    await AuthService.change_password(
        db, current_user.id, payload.current_password, payload.new_password
    )
    await db.commit()
    return APIResponse.ok(EmptyResponse())


# ─── Demo mode endpoint ──────────────────────────────────────────────────────

@router.post(
    "/demo",
    response_model=APIResponse[TokenPair],
    summary="One-click demo login — no credentials required",
)
async def demo_login(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[TokenPair]:
    ip = _extract_client_ip(request)
    await _check_rate_limit(redis, f"auth_demo_ip:{ip}", limit=10, window=3600)
    from app.services.demo_service import demo_login as _demo_login
    token_pair = await _demo_login(db)
    _set_refresh_cookie(response, token_pair.refresh_token)
    return APIResponse.ok(token_pair)


# ─── MFA endpoints ────────────────────────────────────────────────────────────

class MFASetupResponse(BaseModel):
    provisioning_uri: str
    encrypted_secret: str


class MFAVerifyRequest(BaseModel):
    encrypted_secret: str
    code: str = Field(..., min_length=6, max_length=8)


class MFABackupCodesResponse(BaseModel):
    backup_codes: list[str]


class MFADisableRequest(BaseModel):
    password: str = Field(..., min_length=1)
    code: str = Field(..., min_length=6, max_length=8)


@router.post(
    "/mfa/setup",
    response_model=APIResponse[MFASetupResponse],
    summary="Begin MFA setup — returns provisioning URI for QR code display",
)
async def mfa_setup(
    current_user: CurrentUser,
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[MFASetupResponse]:
    import hashlib as _hashlib
    _uid_hash = _hashlib.sha256(str(current_user.id).encode()).hexdigest()[:24]
    await _check_rate_limit(redis, f"auth_mfa_setup:{_uid_hash}", limit=10, window=3600)
    from app.services.mfa_service import MFAService
    result = MFAService.generate_totp_setup(current_user)
    return APIResponse.ok(MFASetupResponse(
        provisioning_uri=result["provisioning_uri"],
        encrypted_secret=result["encrypted_secret"],
    ))


@router.post(
    "/mfa/verify",
    response_model=APIResponse[MFABackupCodesResponse],
    summary="Verify TOTP code and activate MFA — returns backup codes (shown once)",
)
async def mfa_verify(
    payload: MFAVerifyRequest,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[MFABackupCodesResponse]:
    import hashlib as _hashlib
    _uid_hash = _hashlib.sha256(str(current_user.id).encode()).hexdigest()[:24]
    await _check_rate_limit(redis, f"auth_mfa_verify:{_uid_hash}", limit=10, window=900)
    from app.services.mfa_service import MFAService
    from app.core.exceptions import ValidationError
    try:
        raw_codes = MFAService.verify_and_activate_mfa(
            current_user, payload.encrypted_secret, payload.code
        )
    except ValueError as exc:
        raise ValidationError(str(exc))
    await db.flush([current_user])
    await db.commit()
    return APIResponse.ok(MFABackupCodesResponse(backup_codes=raw_codes))


@router.post(
    "/mfa/disable",
    response_model=APIResponse[EmptyResponse],
    summary="Disable MFA — requires password and current TOTP code",
)
async def mfa_disable(
    payload: MFADisableRequest,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[EmptyResponse]:
    import hashlib as _hashlib
    _uid_hash = _hashlib.sha256(str(current_user.id).encode()).hexdigest()[:24]
    await _check_rate_limit(redis, f"auth_mfa_disable:{_uid_hash}", limit=5, window=3600)
    from app.core.exceptions import UnauthorizedError, ValidationError
    from app.core.security import verify_password
    from app.services.mfa_service import MFAService

    if not verify_password(payload.password, current_user.password_hash):
        raise UnauthorizedError("Incorrect password")

    if not current_user.totp_enabled:
        raise ValidationError("MFA is not enabled on this account")

    if not MFAService.verify_totp(current_user, payload.code):
        raise UnauthorizedError("Invalid MFA code")

    MFAService.disable_mfa(current_user)
    await db.flush([current_user])
    await db.commit()
    return APIResponse.ok(EmptyResponse())

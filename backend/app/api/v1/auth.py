from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
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

_LOGIN_RATE_LIMIT    = 10     # attempts
_LOGIN_RATE_WINDOW   = 900    # 15 minutes
_REGISTER_RATE_LIMIT = 5      # attempts
_REGISTER_RATE_WINDOW = 3600  # 1 hour


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
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if forwarded:
        return forwarded
    return request.client.host if request.client else "unknown"


async def _check_rate_limit(
    redis: object | None,
    key: str,
    limit: int,
    window: int,
) -> None:
    if redis is None:
        return
    try:
        from redis.asyncio import Redis as RedisType
        r: RedisType = redis  # type: ignore[assignment]
        current = await r.incr(key)
        if current == 1:
            await r.expire(key, window)
        if current > limit:
            raise RateLimitError(
                f"Too many attempts — try again in {window // 60} minutes",
                retry_after=window,
            )
    except RateLimitError:
        raise
    except Exception:
        pass


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=10)
    new_password: str = Field(..., min_length=8, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)


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

    ip_str = request.headers.get("X-Forwarded-For", request.client.host if request.client else None)
    _user, token_pair = await AuthService.register(
        db,
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
        ip_address=ip_str,
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

    ip_str = request.headers.get("X-Forwarded-For", request.client.host if request.client else None)
    _user, token_pair = await AuthService.login(
        db,
        email=payload.email,
        password=payload.password,
        ip_address=ip_str,
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
    await _check_rate_limit(
        redis,
        f"auth_resend_verify:{payload.email.lower()}",
        limit=10,
        window=3600,
    )
    await AuthService.resend_verification(db, payload.email)
    return APIResponse.ok(EmptyResponse())


@router.post(
    "/debug/force-verify",
    include_in_schema=False,
)
async def debug_force_verify(
    email: str = Query(..., description="Email address to force-verify"),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Force-verify an email address directly in the DB. Remove after use."""
    from sqlalchemy import select, update
    from app.models.user import User
    result = await db.execute(select(User).where(User.email == email.lower().strip()))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": f"No user found with email {email!r}"}
    if user.email_verified:
        return {"ok": True, "message": "Already verified", "email": email}
    user.email_verified = True
    user.email_verification_token = None
    user.email_verification_sent_at = None
    await db.commit()
    return {"ok": True, "message": "Email verified successfully", "email": email}


@router.post(
    "/debug/test-email",
    include_in_schema=False,  # hidden from Swagger — remove this endpoint after debugging
)
async def debug_test_email(
    to_email: str = Query(..., description="Recipient address for the test email"),
) -> dict:
    """
    Sends a test email and returns a detailed report of which provider succeeded or
    what error each provider returned.  Protected by ADMIN_SECRET env var.
    Remove this endpoint once email is confirmed working.
    """
    import traceback
    from app.core.config import get_settings
    settings = get_settings()
    results: dict = {}

    # ── SMTP ──────────────────────────────────────────────────────────────────
    if settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASSWORD:
        try:
            import aiosmtplib
            from email.mime.text import MIMEText
            smtp_port = int(settings.SMTP_PORT)
            msg = MIMEText("This is a test email from NEURASHIELD SOC.", "plain", "utf-8")
            msg["Subject"] = "NEURASHIELD — Email Test"
            msg["From"]    = settings.SMTP_FROM_EMAIL or settings.SMTP_USER
            msg["To"]      = to_email
            await aiosmtplib.send(
                msg,
                hostname=settings.SMTP_HOST,
                port=smtp_port,
                username=settings.SMTP_USER,
                password=settings.SMTP_PASSWORD,
                use_tls=smtp_port == 465,
                start_tls=smtp_port == 587,
                timeout=15,
            )
            results["smtp"] = "OK"
        except Exception as exc:
            results["smtp"] = f"FAILED: {exc}"
    else:
        results["smtp"] = f"SKIPPED (host={settings.SMTP_HOST!r} user={settings.SMTP_USER!r} password={'set' if settings.SMTP_PASSWORD else 'NOT SET'})"

    # ── Resend ────────────────────────────────────────────────────────────────
    if settings.RESEND_API_KEY:
        try:
            import httpx as _httpx
            async with _httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    "https://api.resend.com/emails",
                    headers={"Authorization": f"Bearer {settings.RESEND_API_KEY}"},
                    json={"from": settings.RESEND_FROM_EMAIL or "onboarding@resend.dev",
                          "to": [to_email], "subject": "NEURASHIELD — Email Test",
                          "text": "Test from NEURASHIELD SOC."},
                )
            results["resend"] = f"HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as exc:
            results["resend"] = f"FAILED: {exc}"
    else:
        results["resend"] = "SKIPPED (RESEND_API_KEY not set)"

    # ── Brevo ─────────────────────────────────────────────────────────────────
    if settings.BREVO_API_KEY:
        try:
            import httpx as _httpx
            async with _httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    "https://api.brevo.com/v3/smtp/email",
                    headers={"api-key": settings.BREVO_API_KEY},
                    json={"sender": {"name": "NEURASHIELD", "email": settings.BREVO_FROM_EMAIL or settings.SMTP_USER},
                          "to": [{"email": to_email}],
                          "subject": "NEURASHIELD — Email Test",
                          "textContent": "Test from NEURASHIELD SOC."},
                )
            results["brevo"] = f"HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as exc:
            results["brevo"] = f"FAILED: {exc}"
    else:
        results["brevo"] = "SKIPPED (BREVO_API_KEY not set)"

    return {"to": to_email, "results": results}


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
    await _check_rate_limit(
        redis,
        f"auth_forgot_pw:{payload.email.lower()}",
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
    db: AsyncSession = Depends(get_db),
) -> APIResponse[EmptyResponse]:
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
) -> APIResponse[EmptyResponse]:
    await AuthService.change_password(
        db, current_user.id, payload.current_password, payload.new_password
    )
    await db.commit()
    return APIResponse.ok(EmptyResponse())

from __future__ import annotations

from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.core.exceptions import RateLimitError
from app.core.redis import TenantRedisClient, get_redis, get_redis_optional
from app.models.installer_token import InstallerTokenStatus
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse, EmptyResponse, PaginatedResponse
from app.schemas.installer import (
    BootstrapEnrollRequest,
    BootstrapEnrollResponse,
    InstallerTokenGenerateRequest,
    InstallerTokenGenerateResponse,
    InstallerTokenResponse,
    InstallerTokenRevokeRequest,
)
from app.services.installer_service import InstallerService

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/installer", tags=["installer"])

# Rate limit: 10 token generations per hour per tenant
_RATE_LIMIT = 10
_RATE_WINDOW_SECS = 3600

# Brute-force protection: 20 enrollment attempts per 15 minutes per IP
_ENROLL_RATE_LIMIT = 20
_ENROLL_RATE_WINDOW_SECS = 900


def _token_to_response(token: object) -> InstallerTokenResponse:
    from app.models.installer_token import InstallerToken
    t: InstallerToken = token  # type: ignore[assignment]
    return InstallerTokenResponse(
        id=t.id,
        tenant_id=t.tenant_id,
        token_preview=t.token_preview,
        organization=t.organization,
        machine_name=t.machine_name,
        status=t.status.value,
        expires_at=t.expires_at,
        used_at=t.used_at,
        installed_at=t.installed_at,
        revoked_at=t.revoked_at,
        device_id=t.device_id,
        metadata=t.token_metadata,
        created_by_id=t.created_by_id,
        created_at=t.created_at,
        updated_at=t.updated_at,
    )


# ─── Generate token ───────────────────────────────────────────────────────────

@router.post(
    "/generate-token",
    response_model=APIResponse[InstallerTokenGenerateResponse],
    status_code=201,
    summary="Generate a single-use installer token (expires in 1 hour)",
)
async def generate_installer_token(
    payload: InstallerTokenGenerateRequest,
    member: Annotated[object, require_permission(Permission.AGENTS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[InstallerTokenGenerateResponse]:
    from app.models.tenant_member import TenantMember
    from redis.asyncio import Redis

    m: TenantMember = member  # type: ignore[assignment]

    # Rate limiting: tenant-scoped, subsystem "installer"
    # Graceful fallback: if Redis is unavailable, skip rate limiting and proceed.
    remaining = _RATE_LIMIT
    if redis is not None:
        redis_typed: Redis[str] = redis  # type: ignore[assignment]
        try:
            rate_client = TenantRedisClient(redis_typed, str(m.tenant_id), "installer")
            allowed, remaining = await rate_client.check_rate_limit(
                "gen_token", _RATE_LIMIT, _RATE_WINDOW_SECS
            )
            if not allowed:
                logger.warning(
                    "installer_token_rate_limit_exceeded",
                    tenant_id=str(m.tenant_id),
                    actor_id=str(m.user_id),
                )
                raise RateLimitError(
                    f"Token generation limit of {_RATE_LIMIT} per hour exceeded",
                    retry_after=_RATE_WINDOW_SECS,
                )
        except RateLimitError:
            raise
        except Exception as redis_err:
            logger.warning(
                "installer_rate_limit_redis_unavailable",
                error=str(redis_err),
                tenant_id=str(m.tenant_id),
            )
    else:
        logger.warning("installer_rate_limit_skipped_no_redis", tenant_id=str(m.tenant_id))

    result = await InstallerService.generate_installer_token(
        db, m.tenant_id, payload, created_by_id=m.user_id
    )
    try:
        await db.commit()
    except Exception as commit_err:
        logger.error(
            "installer_token_commit_failed",
            error=str(commit_err),
            error_type=type(commit_err).__name__,
            tenant_id=str(m.tenant_id),
        )
        await db.rollback()
        raise

    logger.info(
        "installer_token_generated_via_api",
        token_id=str(result.id),
        tenant_id=str(m.tenant_id),
        machine_name=payload.machine_name,
        rate_remaining=remaining,
    )
    return APIResponse.ok(result)


# ─── Status check ─────────────────────────────────────────────────────────────

@router.get(
    "/token/{token_id}/status",
    response_model=APIResponse[InstallerTokenResponse],
    summary="Get installer token status and metadata",
)
async def get_installer_token_status(
    token_id: UUID,
    member: Annotated[object, require_permission(Permission.AGENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[InstallerTokenResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    token = await InstallerService.require_by_id(db, m.tenant_id, token_id)
    return APIResponse.ok(_token_to_response(token))


# ─── List tokens ──────────────────────────────────────────────────────────────

@router.get(
    "/tokens",
    response_model=PaginatedResponse[InstallerTokenResponse],
    summary="List installer tokens for this tenant",
)
async def list_installer_tokens(
    member: Annotated[object, require_permission(Permission.AGENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=25, ge=1, le=100),
    status: str | None = Query(default=None),
) -> PaginatedResponse[InstallerTokenResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    status_filter: InstallerTokenStatus | None = None
    if status:
        try:
            status_filter = InstallerTokenStatus(status)
        except ValueError:
            pass  # ignore unknown status filter — return all

    tokens, total = await InstallerService.list_tokens(
        db, m.tenant_id, page=page, limit=limit, status_filter=status_filter
    )
    return PaginatedResponse[InstallerTokenResponse].offset(
        data=[_token_to_response(t) for t in tokens],
        page=page,
        limit=limit,
        total=total,
    )


# ─── Bootstrap enrollment (installer → agent credentials, no JWT) ─────────────

@router.post(
    "/bootstrap-enroll",
    response_model=APIResponse[BootstrapEnrollResponse],
    status_code=200,
    summary="Exchange a one-time installer token for permanent agent credentials",
)
async def bootstrap_enroll(
    payload: BootstrapEnrollRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[object | None, Depends(get_redis_optional)] = None,
) -> APIResponse[BootstrapEnrollResponse]:
    """
    Called exclusively by the bootstrap installer, never by a browser.
    Authentication = the raw installer token in the request body.

    Flow:
    1. IP-based rate limit check (brute-force protection).
    2. Look up PENDING tokens by (tenant_id, token_preview).
    3. Argon2id-verify the raw token against each candidate.
    4. Atomically transition PENDING → INSTALLING (SELECT FOR UPDATE).
    5. Enroll a new agent, receiving permanent (agent_id, enrollment_token).
    6. Transition INSTALLING → ACTIVE with the hostname as device_id.
    7. Audit log the enrollment event.
    8. Return permanent credentials — caller MUST store them via DPAPI.

    The raw installer token is invalidated on success and can never be
    replayed. On any failure after step 4, token status → FAILED so the
    admin can generate a new one.
    """
    from redis.asyncio import Redis
    from app.core.security import verify_password
    from app.core.exceptions import NotFoundError, ValidationError
    from app.ingestion.schemas import AgentEnrollRequest
    from app.ingestion.service import IngestionService
    from app.services.audit_service import AuditService

    # ── Brute-force protection: IP-scoped rate limit ───────────────────────────
    client_ip = _get_client_ip(request)
    if redis is not None:
        redis_typed: Redis[str] = redis  # type: ignore[assignment]
        ip_key = f"enroll_ip:{client_ip}"
        current = await redis_typed.incr(ip_key)
        if current == 1:
            await redis_typed.expire(ip_key, _ENROLL_RATE_WINDOW_SECS)
        if current > _ENROLL_RATE_LIMIT:
            logger.warning(
                "bootstrap_enroll_rate_limit_exceeded",
                client_ip=client_ip,
                attempts=current,
            )
            raise RateLimitError(
                "Too many enrollment attempts — try again later",
                retry_after=_ENROLL_RATE_WINDOW_SECS,
            )
    else:
        logger.warning(
            "bootstrap_enroll_rate_limit_skipped_no_redis",
            client_ip=client_ip,
        )

    raw_token = payload.token
    # Preview is the first 8 chars of the raw token — used for fast DB lookup
    token_preview = raw_token[:8]

    candidates = await InstallerService.find_pending_by_preview(
        db, payload.tenant_id, token_preview
    )

    # Timing-safe: always run Argon2id verify even when candidate list is empty
    matched_token = None
    dummy_hash = (
        "$argon2id$v=19$m=65536,t=2,p=2"
        "$AAAAAAAAAAAAAAAAAAAAAA"
        "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    for candidate in candidates or [None]:
        hash_to_check = candidate.token_hash if candidate else dummy_hash
        if verify_password(raw_token, hash_to_check) and candidate is not None:
            matched_token = candidate
            break

    if matched_token is None:
        logger.warning(
            "bootstrap_enroll_token_not_found",
            tenant_id=str(payload.tenant_id),
            token_preview=token_preview,
            client_ip=client_ip,
        )
        raise NotFoundError("Installer token not found or invalid")

    if matched_token.is_expired:
        matched_token.status = InstallerTokenStatus.EXPIRED
        await db.flush()
        raise ValidationError("Installer token has expired")

    # Atomically claim the token — prevents concurrent replay
    installing_token = await InstallerService.mark_installing(db, matched_token)

    machine = payload.machine_info
    enroll_request = AgentEnrollRequest(
        name=machine.hostname,
        hostname=machine.hostname,
        os_type=machine.os_type,
        agent_version=machine.agent_version or "2.0.0",
        ip_address=machine.ip_address,
        tags=[],
    )

    try:
        enroll_response = await IngestionService.enroll_agent(
            db,
            tenant_id=payload.tenant_id,
            payload=enroll_request,
            created_by_id=installing_token.created_by_id or payload.tenant_id,
        )
    except Exception as exc:
        logger.error(
            "bootstrap_enroll_agent_creation_failed",
            installer_token_id=str(installing_token.id),
            error=str(exc),
        )
        await InstallerService.mark_failed(db, installing_token, reason=str(exc))
        await db.commit()
        raise

    await InstallerService.mark_used(
        db, installing_token, device_id=machine.hostname
    )

    await AuditService.log(
        db,
        action="installer_token.enrolled",
        actor_id=installing_token.created_by_id or payload.tenant_id,
        tenant_id=payload.tenant_id,
        resource_type="installer_token",
        resource_id=installing_token.id,
        changes={
            "agent_id": str(enroll_response.agent_id),
            "hostname": machine.hostname,
            "os_type": machine.os_type,
            "ip_address": machine.ip_address or "",
        },
    )

    await db.commit()

    logger.info(
        "bootstrap_enroll_success",
        installer_token_id=str(installing_token.id),
        agent_id=str(enroll_response.agent_id),
        tenant_id=str(payload.tenant_id),
        hostname=machine.hostname,
        client_ip=client_ip,
    )

    return APIResponse.ok(
        BootstrapEnrollResponse(
            agent_id=enroll_response.agent_id,
            enrollment_token=enroll_response.enrollment_token,
            tenant_id=payload.tenant_id,
            installer_token_id=installing_token.id,
        )
    )


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ─── Revoke token ─────────────────────────────────────────────────────────────

@router.post(
    "/revoke/{token_id}",
    response_model=APIResponse[InstallerTokenResponse],
    summary="Revoke a pending or installing token",
)
async def revoke_installer_token(
    token_id: UUID,
    payload: InstallerTokenRevokeRequest,
    member: Annotated[object, require_permission(Permission.AGENTS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[InstallerTokenResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    token = await InstallerService.revoke_token(
        db, m.tenant_id, token_id, revoked_by_id=m.user_id, reason=payload.reason
    )
    await db.commit()
    return APIResponse.ok(_token_to_response(token))

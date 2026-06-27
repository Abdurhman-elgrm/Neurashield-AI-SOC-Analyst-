from __future__ import annotations

from typing import Annotated
from uuid import UUID

import structlog
from fastapi import Depends, Header, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.logging import user_id_ctx
from app.core.redis import get_redis
from app.core.security import decode_access_token
from app.rbac.permissions import Permission
from app.rbac.roles import get_effective_permissions

logger = structlog.get_logger(__name__)

_bearer = HTTPBearer(auto_error=False)


# ─── Token extraction ─────────────────────────────────────────────────────────


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:  # type: ignore[name-defined]
    """
    Decodes the Bearer JWT and returns the authenticated User.
    Raises UnauthorizedError if the token is missing, invalid, or the user is inactive.
    """
    from app.services.user_service import UserService

    if credentials is None:
        raise UnauthorizedError("Authentication required")

    payload = decode_access_token(credentials.credentials)

    try:
        user_id = UUID(payload.sub)
    except ValueError:
        raise UnauthorizedError("Malformed token subject") from None

    user = await UserService.get_by_id(db, user_id)
    if user is None or not user.is_active or user.is_deleted:
        raise UnauthorizedError("User account not found or inactive")

    # Enforce email verification — the JWT carries the claim set at issue time.
    # We check *both* the JWT claim (fast, no DB hit) and the DB state (catches
    # tokens issued before a verification was rolled back or expired).
    # Endpoints under /auth/ are exempt because verify-email and resend-verification
    # must be reachable before the address is confirmed.
    jwt_verified: bool = getattr(payload, "email_verified", True)
    if not jwt_verified and not user.email_verified:
        raise ForbiddenError(
            "Email address not verified. Please check your inbox for the verification link.",
            details={"code": "EMAIL_NOT_VERIFIED"},
        )

    # Inject user_id into log context for all downstream logging in this request
    user_id_ctx.set(str(user_id))

    return user


# ─── Tenant context ───────────────────────────────────────────────────────────


async def get_current_tenant_member(
    x_tenant_id: Annotated[str | None, Header(alias="X-Tenant-ID")] = None,
    current_user: Annotated[User, Depends(get_current_user)] = None,  # type: ignore
    db: Annotated[AsyncSession, Depends(get_db)] = None,  # type: ignore
) -> TenantMember:  # type: ignore[name-defined]
    """
    Resolves the tenant context from the X-Tenant-ID header and validates
    that the current user is an active member of that tenant.

    Returns the TenantMember record (which includes the user's role).
    """
    from app.services.tenant_service import TenantService

    if not x_tenant_id:
        raise ForbiddenError("X-Tenant-ID header is required")

    try:
        tenant_id = UUID(x_tenant_id)
    except ValueError:
        raise ForbiddenError("Invalid tenant ID format") from None

    member = await TenantService.get_active_member(db, tenant_id, current_user.id)
    if member is None:
        raise ForbiddenError("Not a member of this tenant")

    return member


# ─── Permission-based authorization ──────────────────────────────────────────


def require_permission(permission: Permission) -> Depends:
    """
    Returns a FastAPI dependency that validates the current member holds
    the specified permission (including any custom grant/revoke overrides).

    Usage in routes:
        member: TenantMember = require_permission(Permission.ALERTS_UPDATE)
    """

    async def _check(
        member: Annotated[TenantMember, Depends(get_current_tenant_member)],  # type: ignore
    ) -> TenantMember:  # type: ignore[name-defined]
        custom = getattr(member, "custom_permissions", None)
        effective = get_effective_permissions(member.role, custom)
        if permission not in effective:
            logger.info(
                "permission_denied",
                required_permission=permission.value,
                member_role=member.role,
            )
            raise ForbiddenError(
                f"Required permission: {permission.value}",
                details={"required": permission.value, "role": member.role},
            )
        return member

    return Depends(_check)


# ─── Re-exports for route convenience ────────────────────────────────────────

CurrentUser = Annotated["User", Depends(get_current_user)]  # type: ignore
CurrentMember = Annotated["TenantMember", Depends(get_current_tenant_member)]  # type: ignore
DBSession = Annotated[AsyncSession, Depends(get_db)]
RedisClient = Annotated["Redis[str]", Depends(get_redis)]  # type: ignore

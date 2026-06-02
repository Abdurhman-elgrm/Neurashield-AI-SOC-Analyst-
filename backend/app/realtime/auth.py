from __future__ import annotations

from uuid import UUID

from fastapi import WebSocket
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.security import decode_access_token
from app.services.tenant_service import TenantService
from app.services.user_service import UserService


async def authenticate_websocket(
    websocket: WebSocket,
    token: str | None,
    tenant_id_str: str | None,
    db: AsyncSession,
) -> tuple["User", "TenantMember"]:  # type: ignore[name-defined]
    """
    Validates a WebSocket upgrade request.
    token and tenant_id are expected as query parameters:
      /ws?token=<jwt>&tenant_id=<uuid>

    Raises UnauthorizedError / ForbiddenError on failure.
    """
    from app.models.user import User
    from app.models.tenant_member import TenantMember

    if not token:
        raise UnauthorizedError("Missing token query parameter")

    payload = decode_access_token(token)

    try:
        user_id = UUID(payload.sub)
    except (ValueError, AttributeError):
        raise UnauthorizedError("Malformed token subject")

    user = await UserService.get_by_id(db, user_id)
    if user is None or not user.is_active or user.is_deleted:
        raise UnauthorizedError("User account not found or inactive")

    if not tenant_id_str:
        raise ForbiddenError("Missing tenant_id query parameter")

    try:
        tenant_id = UUID(tenant_id_str)
    except ValueError:
        raise ForbiddenError("Invalid tenant_id format")

    member = await TenantService.get_active_member(db, tenant_id, user_id)
    if member is None:
        raise ForbiddenError("Not a member of this tenant")

    return user, member

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models.api_key import ApiKey
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


# ─── Schemas ──────────────────────────────────────────────────────────────────


class ApiKeyCreate(BaseModel):
    name: str
    expires_in_days: int | None = None


class ApiKeyResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    name: str
    key_prefix: str
    created_at: str
    last_used_at: str | None
    expires_at: str | None
    revoked_at: str | None


class ApiKeyCreateResponse(ApiKeyResponse):
    raw_key: str


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.get("", response_model=APIResponse[list[ApiKeyResponse]])
async def list_api_keys(
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[ApiKeyResponse]]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.tenant_id == m.tenant_id, ApiKey.revoked_at.is_(None))
        .order_by(ApiKey.created_at.desc())
    )
    keys = result.scalars().all()
    return APIResponse.ok(
        [
            ApiKeyResponse(
                id=str(k.id),
                name=k.name,
                key_prefix=k.key_prefix,
                created_at=k.created_at.isoformat(),
                last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
                expires_at=k.expires_at.isoformat() if k.expires_at else None,
                revoked_at=None,
            )
            for k in keys
        ]
    )


@router.post(
    "", response_model=APIResponse[ApiKeyCreateResponse], status_code=status.HTTP_201_CREATED
)
async def create_api_key(
    body: ApiKeyCreate,
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[ApiKeyCreateResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    raw_key = f"ns_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:8]

    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.now(UTC) + timedelta(days=body.expires_in_days)

    key = ApiKey(
        tenant_id=m.tenant_id,
        user_id=m.user_id,
        name=body.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        expires_at=expires_at,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)

    return APIResponse.ok(
        ApiKeyCreateResponse(
            id=str(key.id),
            name=key.name,
            key_prefix=key.key_prefix,
            created_at=key.created_at.isoformat(),
            last_used_at=None,
            expires_at=key.expires_at.isoformat() if key.expires_at else None,
            revoked_at=None,
            raw_key=raw_key,
        )
    )


@router.delete("/{key_id}", response_model=APIResponse[dict])
async def revoke_api_key(
    key_id: UUID,
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    result = await db.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == m.tenant_id)
    )
    key = result.scalar_one_or_none()
    if key:
        key.revoked_at = datetime.now(UTC)
        await db.commit()
    return APIResponse.ok({"revoked": True})

from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.rbac.roles import Role

# ─── Tenant ───────────────────────────────────────────────────────────────────


class TenantCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    slug: str | None = Field(default=None, min_length=2, max_length=100)

    @field_validator("name")
    @classmethod
    def strip_name(cls, v: str) -> str:
        return v.strip()

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.lower().strip()
        if not re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$", v):
            raise ValueError(
                "Slug must contain only lowercase letters, numbers, and hyphens, "
                "and cannot start or end with a hyphen"
            )
        return v


class TenantUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)
    timezone: str | None = Field(default=None, max_length=64)
    logo_url: str | None = Field(default=None, max_length=65535)
    event_retention_days: int | None = Field(default=None, ge=7, le=3650)
    alert_retention_days: int | None = Field(default=None, ge=7, le=3650)

    @field_validator("name")
    @classmethod
    def strip_name(cls, v: str | None) -> str | None:
        return v.strip() if v else v


class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    is_active: bool
    created_at: datetime
    member_role: str | None = None
    timezone: str = "UTC"
    logo_url: str | None = None
    event_retention_days: int = 90
    alert_retention_days: int = 365


# ─── Tenant Member ────────────────────────────────────────────────────────────


class MemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    user_id: UUID
    role: str
    joined_at: datetime | None
    created_at: datetime
    # Flattened user fields — populated via join
    email: str | None = None
    full_name: str | None = None
    custom_permissions: dict = Field(default_factory=lambda: {"grant": [], "revoke": []})


class MemberRoleUpdateRequest(BaseModel):
    role: Role


# ─── Invitation ───────────────────────────────────────────────────────────────


class InvitationCreateRequest(BaseModel):
    email: EmailStr
    role: Role = Role.ANALYST


class InvitationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    email: str
    role: str
    expires_at: datetime
    created_at: datetime

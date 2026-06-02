from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Characters that must not appear in machine names or organization names
# to prevent log injection and path traversal attacks.
_SAFE_TEXT_RE = re.compile(r'^[^\x00-\x1f\x7f<>&|;`${}\\]+$')
# Token format: inst_ prefix followed by URL-safe base64 characters
_TOKEN_FORMAT_RE = re.compile(r'^inst_[A-Za-z0-9_-]{20,}$')


class InstallerTokenGenerateRequest(BaseModel):
    organization: str = Field(..., min_length=1, max_length=255)
    machine_name: str = Field(..., min_length=1, max_length=255)
    token_metadata: dict[str, Any] = Field(default_factory=dict, alias="metadata")

    model_config = ConfigDict(populate_by_name=True)

    @field_validator("machine_name", "organization")
    @classmethod
    def no_control_chars(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Field must not be blank after stripping whitespace")
        if not _SAFE_TEXT_RE.match(v):
            raise ValueError(
                "Field contains disallowed characters (control characters, < > & | ; ` $ { } \\)"
            )
        return v


class InstallerTokenGenerateResponse(BaseModel):
    """
    Returned ONCE on generation.
    raw_token is never stored and cannot be recovered.
    The caller must distribute it to the installer immediately.
    """

    id: UUID
    raw_token: str
    token_preview: str
    organization: str
    machine_name: str
    expires_at: datetime
    expires_in_seconds: int


class InstallerTokenResponse(BaseModel):
    """Safe read-only view — raw_token is NOT included."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    token_preview: str
    organization: str
    machine_name: str
    status: str
    expires_at: datetime
    used_at: datetime | None
    installed_at: datetime | None
    revoked_at: datetime | None
    device_id: str | None
    token_metadata: dict[str, Any] = Field(alias="metadata")
    created_by_id: UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class InstallerTokenRevokeRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=512)


class InstallerTokenListResponse(BaseModel):
    tokens: list[InstallerTokenResponse]
    total: int


# ─── Bootstrap enrollment (installer token → permanent agent credentials) ─────

class MachineInfo(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    os_type: str = Field(..., pattern="^(windows|linux|macos)$")
    ip_address: str | None = Field(default=None, max_length=64)
    agent_version: str | None = Field(default="2.0.0", max_length=64)

    @field_validator("hostname")
    @classmethod
    def sanitize_hostname(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Hostname must not be blank")
        if not _SAFE_TEXT_RE.match(v):
            raise ValueError(
                "Hostname contains disallowed characters (control characters, < > & | ; ` $ { } \\)"
            )
        # Prevent path traversal sequences
        if ".." in v or "/" in v:
            raise ValueError("Hostname must not contain '..' or '/'")
        return v


class BootstrapEnrollRequest(BaseModel):
    """
    Sent by the installer script to exchange a single-use installer token
    for permanent agent runtime credentials.  No JWT required — the raw
    installer token IS the authentication credential for this endpoint.
    """
    token: str = Field(..., min_length=25, max_length=128, description="Raw installer token (inst_…)")
    tenant_id: UUID
    machine_info: MachineInfo

    @field_validator("token")
    @classmethod
    def validate_token_format(cls, v: str) -> str:
        if not _TOKEN_FORMAT_RE.match(v):
            raise ValueError(
                "Installer token must match format 'inst_<alphanumeric>' with at least 25 characters"
            )
        return v


class BootstrapEnrollResponse(BaseModel):
    """
    Returned once on successful enrollment.
    agent_id and enrollment_token must be stored securely (DPAPI) by the
    installer — the raw enrollment_token is never stored on the server.
    """
    agent_id: UUID
    enrollment_token: str
    tenant_id: UUID
    installer_token_id: UUID

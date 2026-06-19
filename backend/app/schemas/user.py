from __future__ import annotations

import hashlib
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, computed_field, field_validator


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    full_name: str
    is_active: bool
    email_verified: bool = False
    created_at: datetime
    timezone: str = "UTC"
    avatar_url: str | None = None
    job_title: str | None = None
    bio: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def gravatar_url(self) -> str:
        hash_ = hashlib.md5(self.email.lower().strip().encode()).hexdigest()
        return f"https://www.gravatar.com/avatar/{hash_}?d=identicon&s=200"


class UserUpdateRequest(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=255)
    timezone: str | None = Field(default=None, max_length=64)
    avatar_url: str | None = Field(default=None, max_length=512)
    job_title: str | None = Field(default=None, max_length=128)
    bio: str | None = Field(default=None, max_length=2000)

    @field_validator("full_name")
    @classmethod
    def strip_name(cls, v: str | None) -> str | None:
        if v is not None:
            return v.strip()
        return v

    @field_validator("avatar_url")
    @classmethod
    def validate_avatar_url(cls, v: str | None) -> str | None:
        if v is not None and v.strip() == "":
            return None
        return v

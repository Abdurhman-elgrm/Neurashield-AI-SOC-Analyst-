from __future__ import annotations

import math

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

# ─── Password strength helpers ────────────────────────────────────────────────

_COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password",
        "password1",
        "password123",
        "123456789",
        "12345678",
        "qwerty123",
        "qwertyuiop",
        "iloveyou",
        "admin123",
        "letmein",
        "welcome1",
        "monkey123",
        "dragon123",
        "master123",
        "sunshine",
        "princess",
        "football",
        "baseball",
        "superman",
        "batman123",
        "trustno1",
        "abc123456",
        "pass1234",
        "test1234",
    }
)


def _shannon_entropy(s: str) -> float:
    """Return the Shannon entropy (bits) of the string."""
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _validate_password_strength(v: str) -> str:
    """
    Raise ValueError if the password fails strength requirements.
    Uses character class checks + Shannon entropy to catch weak passwords.
    Minimum entropy of 3.0 bits ≈ roughly equivalent to zxcvbn score ≥ 2.
    """
    if v.lower() in _COMMON_PASSWORDS:
        raise ValueError("Password is too common — choose a more unique password")
    if not any(c.isupper() for c in v):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in v):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in v):
        raise ValueError("Password must contain at least one digit")
    entropy = _shannon_entropy(v)
    if entropy < 3.0:
        raise ValueError(
            "Password is too predictable (low entropy) — use a mix of letters, digits, and symbols"
        )
    return v


# ─── Requests ─────────────────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=255)

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        return _validate_password_strength(v)

    @field_validator("full_name")
    @classmethod
    def strip_name(cls, v: str) -> str:
        return v.strip()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    mfa_code: str | None = Field(default=None, min_length=6, max_length=8)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(default="", max_length=512)


# ─── Responses ────────────────────────────────────────────────────────────────


class TokenPair(BaseModel):
    model_config = ConfigDict(frozen=True)

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # access token TTL in seconds


class TokenRefreshResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    access_token: str
    token_type: str = "bearer"
    expires_in: int

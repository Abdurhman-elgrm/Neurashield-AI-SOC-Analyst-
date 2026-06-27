from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "SOC SaaS"
    APP_VERSION: str = "2.0.0"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # ─── API ──────────────────────────────────────────────────────────────────
    API_PREFIX: str = "/api/v1"
    ALLOWED_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    # Derived from FRONTEND_URL by set_cors_from_frontend_url validator if not set explicitly.
    # Set to your exact frontend URL in production — do NOT use wildcards.
    CORS_ALLOW_ORIGIN_REGEX: str = ""

    # ─── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800

    # ─── Redis ────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    # 8 per service × 2 services (API + Worker) = 16 total — stays within
    # Railway managed-Redis connection limits (typically 20 on hobby plan).
    REDIS_MAX_CONNECTIONS: int = 8
    # Dedicated Redis DB for event stream workers (workers use this; API uses REDIS_URL).
    # Defaults to REDIS_URL with /1 appended (same server, different DB).
    # In production, use a separate Redis instance for stream isolation.
    REDIS_STREAM_URL: str = ""

    # ─── JWT ──────────────────────────────────────────────────────────────────
    JWT_SECRET: str
    JWT_REFRESH_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    # RS256 asymmetric keys (PEM format). Required when JWT_ALGORITHM=RS256.
    # Generate with: openssl genrsa -out private.pem 4096
    #                openssl rsa -in private.pem -pubout -out public.pem
    JWT_PRIVATE_KEY: str = ""
    JWT_PUBLIC_KEY: str = ""

    # ─── Rate Limiting ────────────────────────────────────────────────────────
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_AUTH_ATTEMPTS: int = 10
    RATE_LIMIT_API_REQUESTS: int = 300
    RATE_LIMIT_INGEST_EVENTS: int = 10000

    # ─── Workers ──────────────────────────────────────────────────────────────
    WORKER_STREAM_BLOCK_MS: int = 5000
    WORKER_CLAIM_IDLE_MS: int = 30000
    WORKER_MAX_RETRY: int = 3

    # ─── AI / LLM ─────────────────────────────────────────────────────────────
    GROQ_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    # ─── Threat Intelligence ──────────────────────────────────────────────────
    ABUSEIPDB_API_KEY: str = ""
    ALIENVAULT_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    # Optional: absolute path to a GeoLite2-City.mmdb file from MaxMind.
    # When set, GeoIP lookups use the local DB (no rate limit) instead of
    # ip-api.com.  Download: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    # Install the library:  pip install "soc-saas-backend[geoip]"
    MAXMIND_DB_PATH: str = ""

    # ─── Email / SMTP ─────────────────────────────────────────────────────────
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""

    # ─── Brevo (primary email provider — no domain verification needed) ────────
    BREVO_API_KEY: str = ""
    BREVO_FROM_EMAIL: str = ""  # e.g. "ai.soc.anlaylst.team@gmail.com"

    # ─── Resend (fallback — requires verified domain for non-owner recipients) ─
    RESEND_API_KEY: str = ""
    RESEND_FROM_EMAIL: str = ""

    # ─── Observability ────────────────────────────────────────────────────────
    # Bearer token required by Prometheus scraper to access /metrics.
    # Leave empty to disable token auth (metrics are still accessible in dev).
    METRICS_SECRET_TOKEN: str = ""

    # ─── Frontend ─────────────────────────────────────────────────────────────
    FRONTEND_URL: str = "http://localhost:5173"

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_allowed_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [origin.strip() for origin in v.split(",")]
        return v

    @field_validator("JWT_ALGORITHM", mode="after")
    @classmethod
    def validate_jwt_algorithm(cls, v: str) -> str:
        supported = {"HS256", "RS256"}
        if v.upper() not in supported:
            raise ValueError(
                f"JWT_ALGORITHM must be one of {supported}. "
                f"Got '{v}'. Use 'openssl genrsa' for RS256 setup."
            )
        return v.upper()

    @field_validator("JWT_SECRET", "JWT_REFRESH_SECRET", mode="after")
    @classmethod
    def validate_jwt_secrets(cls, v: str) -> str:
        # HS256 uses the secret as a raw HMAC key.  64 UTF-8 characters
        # (≈ 512 bits of entropy for random hex) provides an adequate
        # security margin.  32 characters is insufficient because printable
        # ASCII passwords have far less effective entropy than random bytes.
        # Generate a safe value with: openssl rand -hex 64
        if len(v) < 64:
            raise ValueError(
                "JWT secret must be at least 64 characters. Generate one with: openssl rand -hex 64"
            )
        return v

    @model_validator(mode="after")
    def validate_rs256_keys(self) -> Settings:
        if self.JWT_ALGORITHM == "RS256":
            if not self.JWT_PRIVATE_KEY or not self.JWT_PUBLIC_KEY:
                raise ValueError(
                    "JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required when JWT_ALGORITHM=RS256. "
                    "Generate with: openssl genrsa -out private.pem 4096 && "
                    "openssl rsa -in private.pem -pubout -out public.pem"
                )
        return self

    @model_validator(mode="after")
    def set_default_stream_url(self) -> Settings:
        """Default REDIS_STREAM_URL to REDIS_URL with DB index 1 if not set."""
        if not self.REDIS_STREAM_URL:
            base = self.REDIS_URL
            import re as _re

            if _re.search(r"/\d+$", base):
                stream_url = _re.sub(r"/\d+$", "/1", base)
            else:
                stream_url = base.rstrip("/") + "/1"
            object.__setattr__(self, "REDIS_STREAM_URL", stream_url)
        return self

    @model_validator(mode="after")
    def set_cors_from_frontend_url(self) -> Settings:
        """Build a precise CORS regex from FRONTEND_URL when not configured explicitly."""
        if not self.CORS_ALLOW_ORIGIN_REGEX and self.FRONTEND_URL:
            import re

            escaped = re.escape(self.FRONTEND_URL.rstrip("/"))
            object.__setattr__(self, "CORS_ALLOW_ORIGIN_REGEX", f"^{escaped}$")
        if self.is_production and not self.CORS_ALLOW_ORIGIN_REGEX:
            import structlog

            structlog.get_logger(__name__).warning(
                "cors_not_configured",
                note="Set CORS_ALLOW_ORIGIN_REGEX or FRONTEND_URL to restrict cross-origin access",
            )
        return self

    @model_validator(mode="after")
    def validate_llm_keys(self) -> Settings:
        if self.is_production and not self.GROQ_API_KEY and not self.GEMINI_API_KEY:
            import structlog

            structlog.get_logger(__name__).warning(
                "llm_api_keys_missing",
                detail="Neither GROQ_API_KEY nor GEMINI_API_KEY is set in production — AI analysis will be disabled",
            )
        return self

    @model_validator(mode="after")
    def validate_secrets_differ(self) -> Settings:
        if self.JWT_SECRET == self.JWT_REFRESH_SECRET:
            raise ValueError("JWT_SECRET and JWT_REFRESH_SECRET must be different values")
        return self

    @model_validator(mode="after")
    def validate_production_config(self) -> Settings:
        if not self.is_production:
            return self
        if "localhost" in self.REDIS_URL or "127.0.0.1" in self.REDIS_URL:
            raise ValueError(
                "REDIS_URL cannot point to localhost in production. "
                "Set REDIS_URL to your Redis instance URL (e.g. rediss://... on Railway)."
            )
        all_localhost = all("localhost" in o or "127.0.0.1" in o for o in self.ALLOWED_ORIGINS)
        if all_localhost and not self.CORS_ALLOW_ORIGIN_REGEX:
            raise ValueError(
                "In production ALLOWED_ORIGINS must include your frontend URL, "
                "or CORS_ALLOW_ORIGIN_REGEX must be set."
            )
        return self

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"

    @property
    def async_database_url(self) -> str:
        url = self.DATABASE_URL
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql+asyncpg://", 1)
        return url

    @property
    def sync_database_url(self) -> str:
        """Used by Alembic migrations (sync driver)."""
        url = self.DATABASE_URL
        if url.startswith("postgresql+asyncpg://"):
            return url.replace("postgresql+asyncpg://", "postgresql://", 1)
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql://", 1)
        return url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()

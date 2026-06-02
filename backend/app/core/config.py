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

    # ─── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800

    # ─── Redis ────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_MAX_CONNECTIONS: int = 20

    # ─── JWT ──────────────────────────────────────────────────────────────────
    JWT_SECRET: str
    JWT_REFRESH_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ─── Rate Limiting ────────────────────────────────────────────────────────
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_AUTH_ATTEMPTS: int = 10
    RATE_LIMIT_API_REQUESTS: int = 300
    RATE_LIMIT_INGEST_EVENTS: int = 10000

    # ─── Workers ──────────────────────────────────────────────────────────────
    WORKER_STREAM_BLOCK_MS: int = 5000
    WORKER_CLAIM_IDLE_MS: int = 30000
    WORKER_MAX_RETRY: int = 3

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_allowed_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [origin.strip() for origin in v.split(",")]
        return v

    @field_validator("JWT_SECRET", "JWT_REFRESH_SECRET", mode="after")
    @classmethod
    def validate_jwt_secrets(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT secret must be at least 32 characters")
        return v

    @model_validator(mode="after")
    def validate_secrets_differ(self) -> "Settings":
        if self.JWT_SECRET == self.JWT_REFRESH_SECRET:
            raise ValueError("JWT_SECRET and JWT_REFRESH_SECRET must be different values")
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

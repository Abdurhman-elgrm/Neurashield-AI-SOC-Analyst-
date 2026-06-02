"""
Top-level conftest for the unit_tests/ suite.

Sets the minimum required environment variables so that app.core.config
can be imported without a real .env file. Unit tests in this directory
do NOT use a real database or Redis instance.
"""
import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("JWT_SECRET", "unit-test-jwt-secret-placeholder")
os.environ.setdefault("JWT_REFRESH_SECRET", "unit-test-jwt-refresh-secret-placeholder")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")

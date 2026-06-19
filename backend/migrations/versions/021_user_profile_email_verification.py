"""021_user_profile_email_verification

Revision ID: 021
Revises: 020
Create Date: 2026-06-19

Adds email verification + extended profile fields to users table.
Existing users are pre-verified (email_verified = TRUE) so they are
not locked out. New registrations start with email_verified = FALSE
and must click the link in their verification email.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add all new columns — existing rows get email_verified=TRUE so no lockout
    op.execute(sa.text("""
        ALTER TABLE users
          ADD COLUMN IF NOT EXISTS email_verified        BOOLEAN      NOT NULL DEFAULT TRUE,
          ADD COLUMN IF NOT EXISTS email_verification_token VARCHAR(128),
          ADD COLUMN IF NOT EXISTS email_verification_sent_at TIMESTAMPTZ,
          ADD COLUMN IF NOT EXISTS avatar_url            VARCHAR(512),
          ADD COLUMN IF NOT EXISTS job_title             VARCHAR(128),
          ADD COLUMN IF NOT EXISTS bio                   TEXT
    """))
    # Switch column default to FALSE — new rows must verify before logging in again
    op.execute(sa.text(
        "ALTER TABLE users ALTER COLUMN email_verified SET DEFAULT FALSE"
    ))
    # Sparse unique index — fast token lookup, NULL values not indexed
    op.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_verification_token "
        "ON users (email_verification_token) "
        "WHERE email_verification_token IS NOT NULL"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP INDEX IF EXISTS idx_users_verification_token"))
    op.execute(sa.text("""
        ALTER TABLE users
          DROP COLUMN IF EXISTS email_verified,
          DROP COLUMN IF EXISTS email_verification_token,
          DROP COLUMN IF EXISTS email_verification_sent_at,
          DROP COLUMN IF EXISTS avatar_url,
          DROP COLUMN IF EXISTS job_title,
          DROP COLUMN IF EXISTS bio
    """))

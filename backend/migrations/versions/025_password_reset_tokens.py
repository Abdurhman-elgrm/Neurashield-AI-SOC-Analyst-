"""feat: password reset token columns on users table

Revision ID: 025
Revises: 024
Create Date: 2026-06-19
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "025"
down_revision = "024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("password_reset_token", sa.String(128), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("password_reset_sent_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_users_password_reset_token",
        "users",
        ["password_reset_token"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_users_password_reset_token", table_name="users")
    op.drop_column("users", "password_reset_sent_at")
    op.drop_column("users", "password_reset_token")

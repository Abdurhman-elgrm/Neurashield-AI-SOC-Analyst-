"""feat: add logo_url column to tenants table

Revision ID: 029
Revises: 028
Create Date: 2026-06-21
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "029"
down_revision = "028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("logo_url", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tenants", "logo_url")

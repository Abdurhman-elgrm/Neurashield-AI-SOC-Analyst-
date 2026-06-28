"""Add settings_json JSONB column to tenants

Revision ID: 037
Revises: 036
Create Date: 2026-06-28

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision = "037"
down_revision = "036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "settings_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("tenants", "settings_json")

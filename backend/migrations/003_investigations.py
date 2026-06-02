"""003 — Create investigations table

Revision ID: 003_investigations
Revises: (previous revision)
Create Date: 2026-05-23

Creates:
    investigations           — AI investigation groups with threat scoring
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Alembic revision metadata
revision = "003_investigations"
down_revision = None  # set to prior revision ID when chaining
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "investigation_group_id",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("threat_score",  sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confidence",    sa.String(16), nullable=False, server_default="'low'"),
        sa.Column("tp_probability", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("fp_probability", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column(
            "executive_summary",
            sa.Text(),
            nullable=False,
            server_default="''",
        ),
        sa.Column(
            "technical_summary",
            sa.Text(),
            nullable=False,
            server_default="''",
        ),
        sa.Column(
            "attack_progression",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="'[]'::jsonb",
        ),
        sa.Column(
            "recommended_actions",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="'[]'::jsonb",
        ),
        sa.Column(
            "status",
            sa.String(16),
            nullable=False,
            server_default="'new'",
            index=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )

    # Primary index on investigation_group_id (used for upserts)
    op.create_index(
        "idx_investigation_group",
        "investigations",
        ["investigation_group_id"],
        unique=False,
    )
    op.create_index(
        "idx_investigation_tenant_score",
        "investigations",
        ["tenant_id", "threat_score"],
    )
    op.create_index(
        "idx_investigation_tenant_created",
        "investigations",
        ["tenant_id", "created_at"],
    )
    op.create_index(
        "idx_investigation_tenant_status",
        "investigations",
        ["tenant_id", "status"],
    )
    op.create_index(
        "idx_investigation_tenant_id",
        "investigations",
        ["tenant_id"],
    )


def downgrade() -> None:
    op.drop_index("idx_investigation_tenant_id",      table_name="investigations")
    op.drop_index("idx_investigation_tenant_status",  table_name="investigations")
    op.drop_index("idx_investigation_tenant_created", table_name="investigations")
    op.drop_index("idx_investigation_tenant_score",   table_name="investigations")
    op.drop_index("idx_investigation_group",          table_name="investigations")
    op.drop_table("investigations")

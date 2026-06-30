"""Create tickets table for external ticketing integration

Revision ID: 038
Revises: 037
Create Date: 2026-06-30

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "038"
down_revision = "037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tickets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("investigation_id", sa.String(64), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("ticket_key", sa.String(128), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index("idx_ticket_tenant", "tickets", ["tenant_id"])
    op.create_index("idx_ticket_investigation", "tickets", ["investigation_id"])
    op.create_index("idx_ticket_tenant_inv", "tickets", ["tenant_id", "investigation_id"])


def downgrade() -> None:
    op.drop_index("idx_ticket_tenant_inv", table_name="tickets")
    op.drop_index("idx_ticket_investigation", table_name="tickets")
    op.drop_index("idx_ticket_tenant", table_name="tickets")
    op.drop_table("tickets")

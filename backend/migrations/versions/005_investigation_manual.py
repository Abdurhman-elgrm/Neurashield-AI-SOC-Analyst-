"""Add title, source, severity columns to investigations for manual creation

Revision ID: 005_investigation_manual
Revises: 004_events_explorer
Create Date: 2026-06-04
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "005_investigation_manual"
down_revision: Union[str, None] = "004_events_explorer"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("title", sa.String(500), nullable=True, server_default=""),
    )
    op.add_column(
        "investigations",
        sa.Column("source", sa.String(32), nullable=True, server_default="auto"),
    )
    op.add_column(
        "investigations",
        sa.Column(
            "created_by",
            sa.dialects.postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_index(
        "idx_investigation_tenant_source", "investigations", ["tenant_id", "source"]
    )


def downgrade() -> None:
    op.drop_index("idx_investigation_tenant_source", table_name="investigations")
    op.drop_column("investigations", "created_by")
    op.drop_column("investigations", "source")
    op.drop_column("investigations", "title")

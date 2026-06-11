"""Create chat_history table for Copilot conversation storage

Revision ID: 009_chat_history
Revises: 007_alert_metadata
Create Date: 2026-06-11
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "009_chat_history"
down_revision: Union[str, None] = "007_alert_metadata"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "chat_history",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "investigation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("investigations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint("role IN ('user', 'assistant', 'system')", name="chk_chat_role"),
    )
    op.create_index(
        "idx_chat_history_tenant_user",
        "chat_history",
        ["tenant_id", "user_id", "created_at"],
        postgresql_ops={"created_at": "DESC"},
    )
    op.execute(
        "CREATE INDEX idx_chat_history_investigation ON chat_history (investigation_id) "
        "WHERE investigation_id IS NOT NULL"
    )


def downgrade() -> None:
    op.drop_index("idx_chat_history_investigation", table_name="chat_history")
    op.drop_index("idx_chat_history_tenant_user",   table_name="chat_history")
    op.drop_table("chat_history")

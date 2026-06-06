"""Create api_keys table

Revision ID: 006_api_keys
Revises: 005_investigation_manual
Create Date: 2026-06-06
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "006_api_keys"
down_revision: Union[str, None] = "005_investigation_manual"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id",           postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id",    postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("user_id",      postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"),   nullable=False),
        sa.Column("name",         sa.String(100), nullable=False),
        sa.Column("key_hash",     sa.String(64),  nullable=False),
        sa.Column("key_prefix",   sa.String(8),   nullable=False),
        sa.Column("created_at",   sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at",   sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at",   sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_keys_tenant_id", "api_keys", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_api_keys_tenant_id", table_name="api_keys")
    op.drop_table("api_keys")

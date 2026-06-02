"""Forwarder Installer Hub — installer_tokens table

Revision ID: 003_installer_tokens
Revises: 002_phase2_ingestion
Create Date: 2025-05-22

Creates: installer_tokens
New enum: installer_token_status_enum
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "003_installer_tokens"
down_revision: Union[str, None] = "002_phase2_ingestion"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    # ─── Enum ─────────────────────────────────────────────────────────────────
    postgresql.ENUM(
        "pending", "installing", "active", "expired", "revoked", "failed",
        name="installer_token_status_enum",
        create_type=True,
    ).create(bind, checkfirst=True)

    # ─── Table ────────────────────────────────────────────────────────────────
    op.create_table(
        "installer_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(512), nullable=False),
        sa.Column("token_preview", sa.String(16), nullable=False),
        sa.Column("organization", sa.String(255), nullable=False),
        sa.Column("machine_name", sa.String(255), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(name="installer_token_status_enum", create_type=False),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("installed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("device_id", sa.String(255), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("revoked_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_installer_tokens"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_installer_tokens_tenant",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"], ["users.id"],
            name="fk_installer_tokens_created_by",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["revoked_by_id"], ["users.id"],
            name="fk_installer_tokens_revoked_by",
            ondelete="SET NULL",
        ),
    )

    # ─── Indexes ──────────────────────────────────────────────────────────────
    op.create_index("idx_installer_token_tenant_id", "installer_tokens", ["tenant_id"])
    op.create_index("idx_installer_token_status", "installer_tokens", ["status"])
    op.create_index("idx_installer_token_machine_name", "installer_tokens", ["machine_name"])
    op.create_index("idx_installer_token_device_id", "installer_tokens", ["device_id"])
    op.create_index("idx_installer_token_expires_at", "installer_tokens", ["expires_at"])
    op.create_index(
        "idx_installer_token_tenant_status",
        "installer_tokens",
        ["tenant_id", "status"],
    )
    op.create_index(
        "idx_installer_token_tenant_expires",
        "installer_tokens",
        ["tenant_id", "expires_at"],
    )
    # Partial index: expiry sweep only needs to scan PENDING rows
    op.create_index(
        "idx_installer_token_pending_expires",
        "installer_tokens",
        ["expires_at"],
        postgresql_where=sa.text("status = 'pending'"),
    )


def downgrade() -> None:
    op.drop_table("installer_tokens")
    postgresql.ENUM(
        name="installer_token_status_enum", create_type=False
    ).drop(op.get_bind(), checkfirst=True)

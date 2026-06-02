"""Initial schema — Phase 1 foundation tables

Revision ID: 001_initial_schema
Revises:
Create Date: 2025-05-22

Creates: users, tenants, tenant_members, invitations, refresh_tokens, audit_logs
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ─── member_role_enum ─────────────────────────────────────────────────────
    member_role_enum = postgresql.ENUM(
        "owner", "admin", "analyst", "viewer",
        name="member_role_enum",
        create_type=True,
    )
    member_role_enum.create(op.get_bind(), checkfirst=True)

    # ─── users ────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("idx_users_email", "users", ["email"])
    op.create_index("idx_users_deleted_at", "users", ["deleted_at"])

    # ─── tenants ──────────────────────────────────────────────────────────────
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_tenants"),
        sa.UniqueConstraint("slug", name="uq_tenants_slug"),
    )
    op.create_index("idx_tenants_slug", "tenants", ["slug"])
    op.create_index("idx_tenants_deleted_at", "tenants", ["deleted_at"])

    # ─── tenant_members ───────────────────────────────────────────────────────
    op.create_table(
        "tenant_members",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.Enum("owner", "admin", "analyst", "viewer", name="member_role_enum"), nullable=False),
        sa.Column("invited_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT", name="fk_tenant_members_tenant_id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT", name="fk_tenant_members_user_id"),
        sa.ForeignKeyConstraint(["invited_by"], ["users.id"], ondelete="SET NULL", name="fk_tenant_members_invited_by"),
        sa.PrimaryKeyConstraint("id", name="pk_tenant_members"),
    )
    op.create_index("idx_tenant_member_tenant_id", "tenant_members", ["tenant_id"])
    op.create_index("idx_tenant_member_user_id", "tenant_members", ["user_id"])
    # Partial unique index: one active membership per (tenant, user)
    op.create_index(
        "idx_tenant_member_tenant_user",
        "tenant_members",
        ["tenant_id", "user_id"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    # ─── invitations ──────────────────────────────────────────────────────────
    op.create_table(
        "invitations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("invited_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("role", sa.Enum("owner", "admin", "analyst", "viewer", name="member_role_enum"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE", name="fk_invitations_tenant_id"),
        sa.ForeignKeyConstraint(["invited_by"], ["users.id"], ondelete="SET NULL", name="fk_invitations_invited_by"),
        sa.PrimaryKeyConstraint("id", name="pk_invitations"),
        sa.UniqueConstraint("token_hash", name="uq_invitations_token_hash"),
    )
    op.create_index("idx_invitation_tenant_id", "invitations", ["tenant_id"])
    op.create_index("idx_invitation_email", "invitations", ["email"])

    # ─── refresh_tokens ───────────────────────────────────────────────────────
    op.create_table(
        "refresh_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("jti", sa.String(36), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE", name="fk_refresh_tokens_user_id"),
        sa.PrimaryKeyConstraint("id", name="pk_refresh_tokens"),
        sa.UniqueConstraint("jti", name="uq_refresh_tokens_jti"),
    )
    op.create_index("idx_refresh_token_jti", "refresh_tokens", ["jti"])
    op.create_index("idx_refresh_token_user_id", "refresh_tokens", ["user_id"])

    # ─── audit_logs ───────────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_role", sa.String(50), nullable=True),
        sa.Column("permission_used", sa.String(100), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(100), nullable=True),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("changes", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("request_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="SET NULL", name="fk_audit_logs_tenant_id"),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL", name="fk_audit_logs_actor_id"),
        sa.PrimaryKeyConstraint("id", name="pk_audit_logs"),
    )
    op.create_index("idx_audit_log_tenant_id", "audit_logs", ["tenant_id"])
    op.create_index("idx_audit_log_actor_id", "audit_logs", ["actor_id"])
    op.create_index("idx_audit_log_created_at", "audit_logs", ["created_at"])
    op.create_index("idx_audit_log_action", "audit_logs", ["action"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("refresh_tokens")
    op.drop_table("invitations")
    op.drop_table("tenant_members")
    op.drop_table("tenants")
    op.drop_table("users")

    # Drop the enum type last
    postgresql.ENUM(name="member_role_enum").drop(op.get_bind(), checkfirst=True)

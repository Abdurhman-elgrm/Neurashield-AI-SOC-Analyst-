"""004 — Analyst workspace tables + investigations column additions

Revision ID: 004_analyst_workspace
Revises: 003_investigations
Create Date: 2026-05-23

Adds to investigations:
    assigned_to, verdict, verdict_set_at, verdict_set_by,
    timeline_json, graph_json, behaviors_json, context_json

Creates:
    investigation_notes
    investigation_assignments
    investigation_activity
    investigation_evidence
    investigation_verdicts
    saved_hunts
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision      = "004_analyst_workspace"
down_revision = "003_investigations"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    # ── Extend investigations table ────────────────────────────────────────────
    op.add_column("investigations", sa.Column(
        "assigned_to", postgresql.UUID(as_uuid=True), nullable=True,
    ))
    op.add_column("investigations", sa.Column(
        "verdict", sa.String(32), nullable=True,
    ))
    op.add_column("investigations", sa.Column(
        "verdict_set_at", sa.DateTime(timezone=True), nullable=True,
    ))
    op.add_column("investigations", sa.Column(
        "verdict_set_by", postgresql.UUID(as_uuid=True), nullable=True,
    ))
    op.add_column("investigations", sa.Column(
        "timeline_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True,
    ))
    op.add_column("investigations", sa.Column(
        "graph_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True,
    ))
    op.add_column("investigations", sa.Column(
        "behaviors_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True,
    ))
    op.add_column("investigations", sa.Column(
        "context_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True,
    ))
    # Widen status column for new statuses (triaged, investigating, contained, etc.)
    op.alter_column("investigations", "status",
        type_=sa.String(20), existing_nullable=False,
    )
    op.create_index(
        "idx_investigation_tenant_assigned",
        "investigations", ["tenant_id", "assigned_to"],
    )

    # ── investigation_notes ────────────────────────────────────────────────────
    op.create_table(
        "investigation_notes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id",        postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("investigation_id", sa.String(64),                 nullable=False),
        sa.Column("analyst_id",       postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("content",          sa.Text(),                     nullable=False),
        sa.Column("pinned",           sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at",  sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at",  sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("deleted_at",  sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_note_tenant_inv", "investigation_notes",
                    ["tenant_id", "investigation_id"])

    # ── investigation_assignments ──────────────────────────────────────────────
    op.create_table(
        "investigation_assignments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id",         postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("investigation_id",  sa.String(64),                 nullable=False),
        sa.Column("assigned_to",       postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_by",       postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_at",       sa.DateTime(timezone=True),    nullable=False, server_default=sa.text("NOW()")),
        sa.Column("unassigned_at",     sa.DateTime(timezone=True),    nullable=True),
        sa.Column("escalated",         sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("escalation_reason", sa.Text(),    nullable=True),
        sa.Column("severity",          sa.String(32), nullable=True),
        sa.Column("is_active",         sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("idx_assign_tenant_inv_active", "investigation_assignments",
                    ["tenant_id", "investigation_id", "is_active"])

    # ── investigation_activity ────────────────────────────────────────────────
    op.create_table(
        "investigation_activity",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id",        postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("investigation_id", sa.String(64),                 nullable=False),
        sa.Column("analyst_id",       postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action",           sa.String(100),                nullable=False),
        sa.Column("target_id",        sa.String(64),                 nullable=True),
        sa.Column("metadata",         postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="'{}'::jsonb"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("idx_activity_tenant_inv", "investigation_activity",
                    ["tenant_id", "investigation_id"])
    op.create_index("idx_activity_tenant_ts",  "investigation_activity",
                    ["tenant_id", "created_at"])

    # ── investigation_evidence ────────────────────────────────────────────────
    op.create_table(
        "investigation_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id",        postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("investigation_id", sa.String(64),                 nullable=False),
        sa.Column("analyst_id",       postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_type",    sa.String(32),                 nullable=False),
        sa.Column("reference_id",     sa.String(255),                nullable=True),
        sa.Column("title",            sa.String(500),                nullable=False),
        sa.Column("description",      sa.Text(),                     nullable=True),
        sa.Column("metadata",         postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="'{}'::jsonb"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("idx_evidence_tenant_inv", "investigation_evidence",
                    ["tenant_id", "investigation_id"])

    # ── investigation_verdicts ────────────────────────────────────────────────
    op.create_table(
        "investigation_verdicts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id",         postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("investigation_id",  sa.String(64),                 nullable=False),
        sa.Column("analyst_id",        postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("previous_verdict",  sa.String(32),                 nullable=True),
        sa.Column("new_verdict",       sa.String(32),                 nullable=False),
        sa.Column("reasoning",         sa.Text(),                     nullable=True),
        sa.Column("containment_status", sa.String(64),                nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("idx_verdict_tenant_inv", "investigation_verdicts",
                    ["tenant_id", "investigation_id"])

    # ── saved_hunts ───────────────────────────────────────────────────────────
    op.create_table(
        "saved_hunts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id",    postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("analyst_id",   postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name",         sa.String(200),                nullable=False),
        sa.Column("description",  sa.Text(),                     nullable=True),
        sa.Column("query_params", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default="'{}'::jsonb"),
        sa.Column("run_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("idx_saved_hunt_tenant_analyst", "saved_hunts",
                    ["tenant_id", "analyst_id"])


def downgrade() -> None:
    op.drop_table("saved_hunts")
    op.drop_table("investigation_verdicts")
    op.drop_table("investigation_evidence")
    op.drop_table("investigation_activity")
    op.drop_table("investigation_assignments")
    op.drop_table("investigation_notes")

    op.drop_index("idx_investigation_tenant_assigned", table_name="investigations")
    op.drop_column("investigations", "context_json")
    op.drop_column("investigations", "behaviors_json")
    op.drop_column("investigations", "graph_json")
    op.drop_column("investigations", "timeline_json")
    op.drop_column("investigations", "verdict_set_by")
    op.drop_column("investigations", "verdict_set_at")
    op.drop_column("investigations", "verdict")
    op.drop_column("investigations", "assigned_to")

"""Phase 2 — Ingestion pipeline tables

Revision ID: 002_phase2_ingestion
Revises: 001_initial_schema
Create Date: 2025-05-22

Creates: agents, heartbeats, detection_rules, events, alerts
New enums: agent_os_type_enum, agent_status_enum, rule_type_enum,
           rule_severity_enum, event_category_enum, alert_status_enum,
           alert_severity_enum
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "002_phase2_ingestion"
down_revision: Union[str, None] = "001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    # ─── Enums ────────────────────────────────────────────────────────────────
    for name, values in [
        ("agent_os_type_enum", ["windows", "linux", "macos"]),
        ("agent_status_enum", ["online", "offline", "degraded"]),
        ("rule_type_enum", ["pattern", "threshold"]),
        ("rule_severity_enum", ["low", "medium", "high", "critical"]),
        ("event_category_enum", ["process", "network", "file", "auth", "registry", "dns", "other"]),
        ("alert_status_enum", ["open", "acknowledged", "closed", "false_positive"]),
        ("alert_severity_enum", ["low", "medium", "high", "critical"]),
    ]:
        postgresql.ENUM(*values, name=name, create_type=True).create(bind, checkfirst=True)

    # ─── agents ───────────────────────────────────────────────────────────────
    op.create_table(
        "agents",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("os_type", postgresql.ENUM(name="agent_os_type_enum", create_type=False), nullable=False),
        sa.Column("status", postgresql.ENUM(name="agent_status_enum", create_type=False), nullable=False, server_default="offline"),
        sa.Column("agent_version", sa.String(64), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("enrollment_token_hash", sa.String(512), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("tags", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_agents"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_agents_tenant", ondelete="CASCADE"),
    )
    op.create_index("idx_agent_tenant_id", "agents", ["tenant_id"])
    op.create_index("idx_agent_hostname", "agents", ["hostname"])
    op.create_index("idx_agent_status", "agents", ["status"])
    op.create_index("idx_agent_deleted_at", "agents", ["deleted_at"])
    op.create_index("idx_agent_tenant_hostname", "agents", ["tenant_id", "hostname"])

    # ─── heartbeats ───────────────────────────────────────────────────────────
    op.create_table(
        "heartbeats",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_version", sa.String(64), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("os_metrics", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.PrimaryKeyConstraint("id", name="pk_heartbeats"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_heartbeats_tenant", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], name="fk_heartbeats_agent", ondelete="CASCADE"),
    )
    op.create_index("idx_heartbeat_tenant_id", "heartbeats", ["tenant_id"])
    op.create_index("idx_heartbeat_agent_id", "heartbeats", ["agent_id"])
    op.create_index("idx_heartbeat_agent_received", "heartbeats", ["agent_id", "received_at"])

    # ─── detection_rules ──────────────────────────────────────────────────────
    op.create_table(
        "detection_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("rule_type", postgresql.ENUM(name="rule_type_enum", create_type=False), nullable=False),
        sa.Column("severity", postgresql.ENUM(name="rule_severity_enum", create_type=False), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("conditions", postgresql.JSONB(), nullable=False),
        sa.Column("mitre_tactics", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("mitre_techniques", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("suppression_window_secs", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_detection_rules"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_rules_tenant", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], name="fk_rules_created_by", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["updated_by_id"], ["users.id"], name="fk_rules_updated_by", ondelete="SET NULL"),
    )
    op.create_index("idx_rule_tenant_id", "detection_rules", ["tenant_id"])
    op.create_index("idx_rule_type", "detection_rules", ["rule_type"])
    op.create_index("idx_rule_severity", "detection_rules", ["severity"])
    op.create_index("idx_rule_enabled", "detection_rules", ["enabled"])
    op.create_index("idx_rule_tenant_enabled", "detection_rules", ["tenant_id", "enabled"])

    # ─── events ───────────────────────────────────────────────────────────────
    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("stream_id", sa.String(64), nullable=True),
        sa.Column("raw_id", sa.String(255), nullable=True),
        sa.Column("category", postgresql.ENUM(name="event_category_enum", create_type=False), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("host_name", sa.String(255), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("dest_ip", sa.String(45), nullable=True),
        sa.Column("process_name", sa.String(512), nullable=True),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("process", postgresql.JSONB(), nullable=True),
        sa.Column("user", postgresql.JSONB(), nullable=True),
        sa.Column("network", postgresql.JSONB(), nullable=True),
        sa.Column("file", postgresql.JSONB(), nullable=True),
        sa.Column("registry", postgresql.JSONB(), nullable=True),
        sa.Column("normalized", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("raw_payload", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("tags", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.PrimaryKeyConstraint("id", name="pk_events"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_events_tenant", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], name="fk_events_agent", ondelete="SET NULL"),
    )
    op.create_index("idx_event_tenant_id", "events", ["tenant_id"])
    op.create_index("idx_event_agent_id", "events", ["agent_id"])
    op.create_index("idx_event_raw_id", "events", ["raw_id"])
    op.create_index("idx_event_category", "events", ["category"])
    op.create_index("idx_event_severity", "events", ["severity"])
    op.create_index("idx_event_ingested_at", "events", ["ingested_at"])
    op.create_index("idx_event_host_name", "events", ["host_name"])
    op.create_index("idx_event_tenant_ts", "events", ["tenant_id", "event_timestamp"])
    op.create_index("idx_event_tenant_category", "events", ["tenant_id", "category"])
    op.create_index("idx_event_tenant_raw_id", "events", ["tenant_id", "raw_id"])

    # ─── alerts ───────────────────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("triggering_event_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", postgresql.ENUM(name="alert_status_enum", create_type=False), nullable=False, server_default="open"),
        sa.Column("severity", postgresql.ENUM(name="alert_severity_enum", create_type=False), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source_host", sa.String(255), nullable=True),
        sa.Column("assignee_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("mitre_tactics", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("mitre_techniques", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("suppression_key", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_alerts"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_alerts_tenant", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["rule_id"], ["detection_rules.id"], name="fk_alerts_rule", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["triggering_event_id"], ["events.id"], name="fk_alerts_event", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["assignee_id"], ["users.id"], name="fk_alerts_assignee", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["acknowledged_by_id"], ["users.id"], name="fk_alerts_acked_by", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["closed_by_id"], ["users.id"], name="fk_alerts_closed_by", ondelete="SET NULL"),
    )
    op.create_index("idx_alert_tenant_id", "alerts", ["tenant_id"])
    op.create_index("idx_alert_rule_id", "alerts", ["rule_id"])
    op.create_index("idx_alert_status", "alerts", ["status"])
    op.create_index("idx_alert_severity", "alerts", ["severity"])
    op.create_index("idx_alert_source_host", "alerts", ["source_host"])
    op.create_index("idx_alert_suppression_key", "alerts", ["suppression_key"])
    op.create_index("idx_alert_tenant_status", "alerts", ["tenant_id", "status"])
    op.create_index("idx_alert_tenant_severity", "alerts", ["tenant_id", "severity"])
    op.create_index("idx_alert_tenant_created", "alerts", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_table("alerts")
    op.drop_table("events")
    op.drop_table("detection_rules")
    op.drop_table("heartbeats")
    op.drop_table("agents")

    bind = op.get_bind()
    for name in [
        "alert_severity_enum", "alert_status_enum", "event_category_enum",
        "rule_severity_enum", "rule_type_enum", "agent_status_enum", "agent_os_type_enum",
    ]:
        postgresql.ENUM(name=name, create_type=False).drop(bind, checkfirst=True)

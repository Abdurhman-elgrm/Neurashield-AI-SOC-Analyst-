"""022_notification_channels_suppression_retention

Revision ID: 022
Revises: 021
Create Date: 2026-06-19

Adds:
  - notification_channels table (outbound Slack/Teams/webhook/PagerDuty/email)
  - suppression_rules table (user-defined alert suppression rules)
  - event_retention_days, alert_retention_days to tenants (data retention policies)
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Notification channels ─────────────────────────────────────────────────
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS notification_channels (
            id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            name            VARCHAR(255) NOT NULL,
            type            VARCHAR(32) NOT NULL,
            config          JSONB       NOT NULL DEFAULT '{}',
            enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
            min_severity    VARCHAR(16) NOT NULL DEFAULT 'high',
            created_by_id   UUID        REFERENCES users(id) ON DELETE SET NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            deleted_at      TIMESTAMPTZ
        )
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_notification_channels_tenant "
        "ON notification_channels (tenant_id) WHERE deleted_at IS NULL"
    ))

    # ── Suppression rules ─────────────────────────────────────────────────────
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS suppression_rules (
            id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            name                VARCHAR(255) NOT NULL,
            description         TEXT,
            detection_rule_id   UUID        REFERENCES detection_rules(id) ON DELETE CASCADE,
            hostname_pattern    VARCHAR(255),
            category            VARCHAR(32),
            min_severity        VARCHAR(16),
            reason              TEXT,
            enabled             BOOLEAN     NOT NULL DEFAULT TRUE,
            expires_at          TIMESTAMPTZ NOT NULL,
            created_by_id       UUID        REFERENCES users(id) ON DELETE SET NULL,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            deleted_at          TIMESTAMPTZ
        )
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_suppression_rules_tenant "
        "ON suppression_rules (tenant_id) WHERE deleted_at IS NULL AND enabled = TRUE"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_suppression_rules_expires "
        "ON suppression_rules (expires_at) WHERE deleted_at IS NULL"
    ))

    # ── Data retention on tenants ─────────────────────────────────────────────
    op.execute(sa.text("""
        ALTER TABLE tenants
          ADD COLUMN IF NOT EXISTS event_retention_days INT NOT NULL DEFAULT 90,
          ADD COLUMN IF NOT EXISTS alert_retention_days INT NOT NULL DEFAULT 365
    """))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS suppression_rules"))
    op.execute(sa.text("DROP TABLE IF EXISTS notification_channels"))
    op.execute(sa.text("""
        ALTER TABLE tenants
          DROP COLUMN IF EXISTS event_retention_days,
          DROP COLUMN IF EXISTS alert_retention_days
    """))

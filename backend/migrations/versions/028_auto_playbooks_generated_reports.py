"""feat: auto playbook config + generated reports

Revision ID: 028
Revises: 027
Create Date: 2026-06-20
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "028"
down_revision = "027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── 1. playbook_auto_config ───────────────────────────────────────────────
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS playbook_auto_config (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id       UUID NOT NULL UNIQUE
                            REFERENCES tenants(id) ON DELETE CASCADE,
            enabled         BOOLEAN NOT NULL DEFAULT FALSE,
            min_severity    VARCHAR(32) NOT NULL DEFAULT 'critical',
            updated_by_id   UUID REFERENCES users(id) ON DELETE SET NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_playbook_auto_config_tenant "
        "ON playbook_auto_config (tenant_id)"
    ))

    # ── 2. generated_reports ─────────────────────────────────────────────────
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS generated_reports (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id       UUID NOT NULL
                            REFERENCES tenants(id) ON DELETE CASCADE,
            report_type     VARCHAR(64)  NOT NULL,
            title           VARCHAR(512) NOT NULL,
            status          VARCHAR(32)  NOT NULL DEFAULT 'generating',
            period_days     INTEGER      NOT NULL DEFAULT 30,
            period_start    TIMESTAMPTZ  NOT NULL,
            period_end      TIMESTAMPTZ  NOT NULL,
            sections        JSONB,
            metrics         JSONB,
            error_message   TEXT,
            created_by_id   UUID REFERENCES users(id) ON DELETE SET NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_generated_reports_tenant "
        "ON generated_reports (tenant_id, created_at DESC)"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS generated_reports"))
    op.execute(sa.text("DROP TABLE IF EXISTS playbook_auto_config"))

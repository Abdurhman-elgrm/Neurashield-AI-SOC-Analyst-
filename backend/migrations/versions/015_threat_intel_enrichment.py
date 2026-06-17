"""Add GeoIP and Threat Intel enrichment fields to events

Revision ID: 015_threat_intel_enrichment
Revises: 014_notification_preferences
Create Date: 2026-06-17
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "015_threat_intel_enrichment"
down_revision: Union[str, None] = "014_notification_preferences"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # GeoIP fields
    op.execute(sa.text("ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_country VARCHAR(100)"))
    op.execute(sa.text("ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_country_code VARCHAR(10)"))
    op.execute(sa.text("ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_city VARCHAR(100)"))
    op.execute(sa.text("ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_latitude FLOAT"))
    op.execute(sa.text("ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_longitude FLOAT"))
    op.execute(sa.text("ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_isp VARCHAR(255)"))

    # Threat Intel fields
    op.execute(sa.text(
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS abuse_confidence INTEGER NOT NULL DEFAULT 0"
    ))
    op.execute(sa.text(
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS is_threat_ip BOOLEAN NOT NULL DEFAULT FALSE"
    ))
    op.execute(sa.text(
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS threat_intel_flags JSONB NOT NULL DEFAULT '[]'"
    ))

    # Indexes for common queries (geo filtering + threat IP filtering)
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_event_tenant_geo_country"
        " ON events (tenant_id, geo_country)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_event_is_threat_ip"
        " ON events (tenant_id, is_threat_ip)"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP INDEX IF EXISTS idx_event_is_threat_ip"))
    op.execute(sa.text("DROP INDEX IF EXISTS idx_event_tenant_geo_country"))
    op.drop_column("events", "threat_intel_flags")
    op.drop_column("events", "is_threat_ip")
    op.drop_column("events", "abuse_confidence")
    op.drop_column("events", "geo_isp")
    op.drop_column("events", "geo_longitude")
    op.drop_column("events", "geo_latitude")
    op.drop_column("events", "geo_city")
    op.drop_column("events", "geo_country_code")
    op.drop_column("events", "geo_country")

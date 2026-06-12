"""Add notification_preferences to tenant_members

Revision ID: 014_notification_preferences
Revises: 013_custom_permissions
Create Date: 2026-06-12
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "014_notification_preferences"
down_revision: Union[str, None] = "013_custom_permissions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        sa.text(
            "ALTER TABLE tenant_members"
            " ADD COLUMN IF NOT EXISTS notification_preferences JSONB NOT NULL"
            " DEFAULT jsonb_build_object("
            "   'email_high_critical_alerts', true::boolean,"
            "   'email_agent_offline', true::boolean,"
            "   'email_new_investigation', false::boolean"
            " )"
        )
    )


def downgrade() -> None:
    op.drop_column("tenant_members", "notification_preferences")

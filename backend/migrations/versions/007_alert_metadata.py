"""Add metadata JSONB column to alerts for AI analysis storage

Revision ID: 007_alert_metadata
Revises: 006_api_keys
Create Date: 2026-06-11
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "007_alert_metadata"
down_revision: Union[str, None] = "006_api_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "alerts",
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("alerts", "metadata")

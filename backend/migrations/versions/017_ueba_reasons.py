"""Add ueba_reasons column for human-readable anomaly explanations

Revision ID: 017_ueba_reasons
Revises: 016_ueba_anomaly_detection
Create Date: 2026-06-18
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "017_ueba_reasons"
down_revision: Union[str, None] = "016_ueba_anomaly_detection"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(sa.text(
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS"
        " ueba_reasons JSONB NOT NULL DEFAULT '{}'"
    ))


def downgrade() -> None:
    op.drop_column("events", "ueba_reasons")

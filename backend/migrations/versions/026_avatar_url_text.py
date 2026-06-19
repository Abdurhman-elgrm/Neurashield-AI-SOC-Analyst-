"""avatar_url column: VARCHAR(512) → TEXT to support base64 data URIs

Revision ID: 026
Revises: 025
Create Date: 2026-06-19
"""

from alembic import op
import sqlalchemy as sa

revision = "026"
down_revision = "025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "users",
        "avatar_url",
        type_=sa.Text(),
        existing_type=sa.String(512),
        existing_nullable=True,
    )


def downgrade() -> None:
    # Truncate any data URIs before shrinking the column
    op.execute(
        sa.text(
            "UPDATE users SET avatar_url = NULL WHERE avatar_url LIKE 'data:image/%'"
        )
    )
    op.alter_column(
        "users",
        "avatar_url",
        type_=sa.String(512),
        existing_type=sa.Text(),
        existing_nullable=True,
    )

"""threat_intel_feeds: threat_feeds and threat_iocs tables

Revision ID: 034
Revises: 033
Create Date: 2026-06-24
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "034"
down_revision = "033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_feeds",
        sa.Column("id",                   postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id",            postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name",                 sa.String(255), nullable=False),
        sa.Column("type",                 sa.Enum("stix_taxii", "csv", "opencti", "misp", "manual", name="threat_feed_type_enum"), nullable=False),
        sa.Column("endpoint_url",         sa.String(2048), nullable=True),
        sa.Column("api_key_encrypted",    sa.Text, nullable=True),
        sa.Column("last_synced_at",       sa.DateTime(timezone=True), nullable=True),
        sa.Column("ioc_count",            sa.Integer, nullable=False, server_default="0"),
        sa.Column("status",               sa.Enum("active", "error", "syncing", name="threat_feed_status_enum"), nullable=False, server_default="active"),
        sa.Column("error_message",        sa.Text, nullable=True),
        sa.Column("sync_interval_minutes",sa.Integer, nullable=False, server_default="1440"),
        sa.Column("created_at",           sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at",           sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("deleted_at",           sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_threat_feed_tenant", "threat_feeds", ["tenant_id"])

    op.create_table(
        "threat_iocs",
        sa.Column("id",         postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id",  postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("feed_id",    postgresql.UUID(as_uuid=True), sa.ForeignKey("threat_feeds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("indicator",  sa.String(2048), nullable=False),
        sa.Column("type",       sa.Enum("ip", "domain", "hash", "url", "email", name="threat_ioc_type_enum"), nullable=False),
        sa.Column("confidence", sa.Integer, nullable=False, server_default="50"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen",  sa.DateTime(timezone=True), nullable=False),
        sa.Column("hit_count",  sa.Integer, nullable=False, server_default="0"),
        sa.Column("tags",       postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("idx_threat_ioc_tenant_type",      "threat_iocs", ["tenant_id", "type"])
    op.create_index("idx_threat_ioc_tenant_indicator",  "threat_iocs", ["tenant_id", "indicator"])
    op.create_index("idx_threat_ioc_feed",              "threat_iocs", ["feed_id"])


def downgrade() -> None:
    op.drop_index("idx_threat_ioc_feed",             table_name="threat_iocs")
    op.drop_index("idx_threat_ioc_tenant_indicator", table_name="threat_iocs")
    op.drop_index("idx_threat_ioc_tenant_type",      table_name="threat_iocs")
    op.drop_table("threat_iocs")
    op.drop_index("idx_threat_feed_tenant",          table_name="threat_feeds")
    op.drop_table("threat_feeds")
    op.execute("DROP TYPE IF EXISTS threat_feed_type_enum")
    op.execute("DROP TYPE IF EXISTS threat_feed_status_enum")
    op.execute("DROP TYPE IF EXISTS threat_ioc_type_enum")

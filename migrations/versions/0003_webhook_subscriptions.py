"""add webhook_subscriptions table

Revision ID: 0003
Revises: 0002
Create Date: 2025-01-01
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "webhook_subscriptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("secret", sa.String(512), nullable=True),
        sa.Column("events", sa.JSON, nullable=False, server_default='["scan.completed", "scan.failed"]'),
        sa.Column("headers", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("last_delivery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_delivery_status", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_webhook_org_active", "webhook_subscriptions", ["organization_id", "is_active"])


def downgrade() -> None:
    op.drop_index("ix_webhook_org_active", "webhook_subscriptions")
    op.drop_table("webhook_subscriptions")

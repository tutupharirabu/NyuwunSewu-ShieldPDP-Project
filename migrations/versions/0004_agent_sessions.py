"""add agent_sessions table

Revision ID: 0004
Revises: 0003
Create Date: 2025-01-01
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=True, index=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id"), nullable=True, index=True),
        sa.Column("agent_name", sa.String(120), nullable=False, server_default="'phantom'"),
        sa.Column("target_url", sa.String(2048), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="'idle'"),
        sa.Column("current_action", sa.String(512), nullable=True),
        sa.Column("logs", sa.JSON, nullable=False, server_default="'[]'"),
        sa.Column("pending_action", sa.JSON, nullable=True),
        sa.Column("findings_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agent_session_org_status", "agent_sessions", ["organization_id", "status"])
    op.create_index("ix_agent_session_scan", "agent_sessions", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_agent_session_scan", "agent_sessions")
    op.drop_index("ix_agent_session_org_status", "agent_sessions")
    op.drop_table("agent_sessions")

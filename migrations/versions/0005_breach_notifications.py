"""add breach_notifications table for Pasal 46 UU PDP compliance

Revision ID: 0005
Revises: 0004
Create Date: 2025-06-01
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "breach_notifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "finding_ids",
            sa.JSON,
            nullable=False,
            server_default="'[]'",
            comment="List of Finding IDs",
        ),
        sa.Column("breach_title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("breach_type", sa.String(80), nullable=False),
        sa.Column("severity", sa.String(24), nullable=False),
        sa.Column(
            "status",
            sa.String(32),
            nullable=False,
            server_default="'detected'",
            comment="detected, assessing, notified, overdue, dismissed",
        ),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "sla_deadline",
            sa.DateTime(timezone=True),
            nullable=False,
            comment="3x24 hours from detected_at",
        ),
        sa.Column(
            "notified_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="When notification was sent",
        ),
        sa.Column(
            "notification_channels",
            sa.JSON,
            nullable=False,
            server_default="'[]'",
            comment="Channels used: telegram, email, dashboard",
        ),
        sa.Column(
            "pii_types_affected",
            sa.JSON,
            nullable=False,
            server_default="'[]'",
            comment="Types of PII affected",
        ),
        sa.Column(
            "data_subjects_estimate",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Estimated affected data subjects",
        ),
        sa.Column(
            "notification_text",
            sa.Text,
            nullable=True,
            comment="Generated notification text",
        ),
        sa.Column(
            "actions_taken",
            sa.JSON,
            nullable=False,
            server_default="'[]'",
            comment="Remediation actions",
        ),
        sa.Column(
            "contact_info", sa.Text, nullable=True, comment="Data controller contact"
        ),
        sa.Column(
            "dismissed_reason", sa.Text, nullable=True, comment="Reason if dismissed"
        ),
        sa.Column(
            "compliance_evidence",
            sa.JSON,
            nullable=False,
            server_default="'{}'",
            comment="Compliance evidence",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_breach_org_status", "breach_notifications", ["organization_id", "status"]
    )
    op.create_index(
        "ix_breach_org_deadline",
        "breach_notifications",
        ["organization_id", "sla_deadline"],
    )


def downgrade() -> None:
    op.drop_index("ix_breach_org_deadline", table_name="breach_notifications")
    op.drop_index("ix_breach_org_status", table_name="breach_notifications")
    op.drop_table("breach_notifications")

"""add roe_documents table and scan engagement columns

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "roe_documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("filename", sa.String(512), nullable=False),
        sa.Column("extracted_text", sa.Text, nullable=False, server_default=""),
        sa.Column("char_count", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column(
            "extraction_warning",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.add_column(
        "scans",
        sa.Column(
            "engagement_mode",
            sa.String(16),
            nullable=False,
            server_default="internal",
        ),
    )
    op.add_column(
        "scans",
        sa.Column(
            "roe_document_id",
            sa.String(36),
            sa.ForeignKey("roe_documents.id"),
            nullable=True,
        ),
    )
    op.add_column("scans", sa.Column("roe_basis", sa.String(32), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "roe_basis")
    op.drop_column("scans", "roe_document_id")
    op.drop_column("scans", "engagement_mode")
    op.drop_table("roe_documents")

"""Add raw_request_full and raw_response_full to evidence

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-30
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "evidence",
        op.Column("raw_request_full", op.JSON(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "evidence",
        op.Column("raw_response_full", op.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("evidence", "raw_response_full")
    op.drop_column("evidence", "raw_request_full")

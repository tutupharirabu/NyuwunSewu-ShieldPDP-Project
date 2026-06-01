"""Add raw_request_full and raw_response_full to evidence

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-30
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "evidence",
        sa.Column(
            "raw_request_full",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )
    op.add_column(
        "evidence",
        sa.Column(
            "raw_response_full",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )


def downgrade() -> None:
    op.drop_column("evidence", "raw_response_full")
    op.drop_column("evidence", "raw_request_full")

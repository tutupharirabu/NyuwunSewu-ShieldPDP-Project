"""add breach SLA tracking + data-subject notification columns

Revision ID: 0007
Revises: 0006
Create Date: 2026-06-13
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("breach_notifications") as batch:
        batch.add_column(
            sa.Column(
                "sla_alerts_sent", sa.JSON(), nullable=False, server_default="[]"
            )
        )
        batch.add_column(
            sa.Column("notification_text_subject", sa.Text(), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("breach_notifications") as batch:
        batch.drop_column("notification_text_subject")
        batch.drop_column("sla_alerts_sent")

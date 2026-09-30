"""anchor governance events to lifecycle transitions

Revision ID: d6f9b2c7a104
Revises: c4e8a1f6b203
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d6f9b2c7a104"
down_revision: str | Sequence[str] | None = "c4e8a1f6b203"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "source_finding_governance_events",
        sa.Column("lifecycle_transition_version", sa.Integer(), nullable=True),
    )
    op.add_column(
        "source_finding_suppression_events",
        sa.Column("lifecycle_transition_version", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column(
        "source_finding_suppression_events",
        "lifecycle_transition_version",
    )
    op.drop_column(
        "source_finding_governance_events",
        "lifecycle_transition_version",
    )

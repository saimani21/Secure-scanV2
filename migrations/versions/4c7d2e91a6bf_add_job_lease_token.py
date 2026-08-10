"""add job lease token

Revision ID: 4c7d2e91a6bf
Revises: 9eba1941b4ac

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "4c7d2e91a6bf"
down_revision: str | Sequence[str] | None = "9eba1941b4ac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.add_column(
            sa.Column(
                "lease_token",
                sa.String(length=36),
                nullable=True,
            )
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.drop_column("lease_token")

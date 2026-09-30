"""add expiring Source finding suppressions

Revision ID: c4e8a1f6b203
Revises: a2b7c4d9e105
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4e8a1f6b203"
down_revision: str | Sequence[str] | None = "a2b7c4d9e105"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_finding_suppressions",
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("suppression_id", sa.String(36), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(reason) >= 1 AND length(reason) <= 1000",
            name="ck_source_finding_suppressions_reason",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_source_finding_suppressions_expiry",
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR "
            "(revoked_at >= created_at AND revoked_at <= updated_at)",
            name="ck_source_finding_suppressions_revocation",
        ),
        sa.CheckConstraint(
            "revision >= 1",
            name="ck_source_finding_suppressions_revision",
        ),
        sa.CheckConstraint(
            "actor_type = 'LOCAL_OPERATOR'",
            name="ck_source_finding_suppressions_actor",
        ),
        sa.CheckConstraint(
            "created_at <= updated_at",
            name="ck_source_finding_suppressions_time_order",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id", "finding_id"],
            ["source_finding_lifecycles.lineage_id", "source_finding_lifecycles.finding_id"],
            name="fk_source_finding_suppressions_lifecycle",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("lineage_id", "finding_id"),
        sa.UniqueConstraint(
            "suppression_id",
            name="uq_source_finding_suppressions_id",
        ),
    )
    op.create_index(
        "ix_source_finding_suppressions_lineage_expiry",
        "source_finding_suppressions",
        ["lineage_id", "expires_at"],
    )
    op.create_table(
        "source_finding_suppression_events",
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("suppression_id", sa.String(36), nullable=False),
        sa.Column("operation", sa.String(16), nullable=False),
        sa.Column("previous_reason", sa.Text()),
        sa.Column("new_reason", sa.Text(), nullable=False),
        sa.Column("previous_expires_at", sa.DateTime(timezone=True)),
        sa.Column("new_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("previous_revoked_at", sa.DateTime(timezone=True)),
        sa.Column("new_revoked_at", sa.DateTime(timezone=True)),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resulting_revision", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "operation IN ('CREATE', 'UPDATE', 'REVOKE')",
            name="ck_source_finding_suppression_events_operation",
        ),
        sa.CheckConstraint(
            "previous_reason IS NULL OR "
            "(length(previous_reason) >= 1 AND length(previous_reason) <= 1000)",
            name="ck_source_finding_suppression_events_previous_reason",
        ),
        sa.CheckConstraint(
            "length(new_reason) >= 1 AND length(new_reason) <= 1000",
            name="ck_source_finding_suppression_events_new_reason",
        ),
        sa.CheckConstraint(
            "new_expires_at IS NOT NULL",
            name="ck_source_finding_suppression_events_new_expiry",
        ),
        sa.CheckConstraint(
            "(operation = 'REVOKE' AND previous_reason IS NOT NULL "
            "AND previous_expires_at IS NOT NULL AND previous_revoked_at IS NULL "
            "AND new_revoked_at IS NOT NULL) OR "
            "(operation IN ('CREATE', 'UPDATE') AND new_revoked_at IS NULL)",
            name="ck_source_finding_suppression_events_material",
        ),
        sa.CheckConstraint(
            "resulting_revision >= 1",
            name="ck_source_finding_suppression_events_revision",
        ),
        sa.CheckConstraint(
            "actor_type = 'LOCAL_OPERATOR'",
            name="ck_source_finding_suppression_events_actor",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id", "finding_id"],
            ["source_finding_lifecycles.lineage_id", "source_finding_lifecycles.finding_id"],
            name="fk_source_finding_suppression_events_lifecycle",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("event_id"),
        sa.UniqueConstraint(
            "lineage_id",
            "finding_id",
            "resulting_revision",
            name="uq_source_finding_suppression_events_revision",
        ),
    )
    op.create_index(
        "ix_source_finding_suppression_events_history",
        "source_finding_suppression_events",
        ["lineage_id", "finding_id", "resulting_revision"],
    )
    op.create_index(
        "ix_source_finding_suppression_events_suppression",
        "source_finding_suppression_events",
        ["suppression_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_source_finding_suppression_events_suppression",
        table_name="source_finding_suppression_events",
    )
    op.drop_index(
        "ix_source_finding_suppression_events_history",
        table_name="source_finding_suppression_events",
    )
    op.drop_table("source_finding_suppression_events")
    op.drop_index(
        "ix_source_finding_suppressions_lineage_expiry",
        table_name="source_finding_suppressions",
    )
    op.drop_table("source_finding_suppressions")

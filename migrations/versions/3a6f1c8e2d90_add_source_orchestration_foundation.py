"""add Source orchestration foundation

Revision ID: 3a6f1c8e2d90
Revises: f4a8c2d17b65

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "3a6f1c8e2d90"
down_revision: str | Sequence[str] | None = "f4a8c2d17b65"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_orchestrations",
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("creation_request_digest", sa.String(length=64), nullable=False),
        sa.Column("repository_digest", sa.String(length=64), nullable=False),
        sa.Column("profile_digest", sa.String(length=64), nullable=False),
        sa.Column("plan_digest", sa.String(length=64), nullable=False),
        sa.Column("roster_digest", sa.String(length=64), nullable=False),
        sa.Column("planning_snapshot_sha256", sa.String(length=64), nullable=False),
        sa.Column("snapshot_size_bytes", sa.Integer(), nullable=False),
        sa.Column("snapshot_media_type", sa.String(length=128), nullable=False),
        sa.Column("snapshot_schema_version", sa.String(length=128), nullable=False),
        sa.Column("snapshot_storage_path", sa.Text(), nullable=False),
        sa.Column("lifecycle_state", sa.String(length=32), nullable=False),
        sa.Column("terminal_outcome", sa.String(length=32), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("state_version >= 1", name="ck_source_orchestrations_version"),
        sa.CheckConstraint(
            "snapshot_size_bytes >= 1", name="ck_source_orchestrations_snapshot_size"
        ),
        sa.CheckConstraint(
            "lifecycle_state IN ('PREPARED', 'ACTIVE', 'CANCELLATION_REQUESTED', "
            "'ASSEMBLY_READY', 'ASSEMBLING', 'COMMITTING', 'TERMINAL')",
            name="ck_source_orchestrations_lifecycle",
        ),
        sa.CheckConstraint(
            "terminal_outcome IS NULL OR terminal_outcome IN "
            "('COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED')",
            name="ck_source_orchestrations_terminal_outcome",
        ),
        sa.CheckConstraint(
            "(lifecycle_state = 'TERMINAL') = (terminal_outcome IS NOT NULL)",
            name="ck_source_orchestrations_terminal_pair",
        ),
        sa.CheckConstraint(
            "cancel_requested_at IS NULL OR cancel_requested = true",
            name="ck_source_orchestrations_cancel_timestamp",
        ),
        sa.ForeignKeyConstraint(["run_id"], ["analysis_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("run_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_source_orchestrations_idempotency"),
    )
    op.create_table(
        "source_orchestration_authorities",
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("authority", sa.String(length=64), nullable=False),
        sa.Column("capability", sa.String(length=64), nullable=False),
        sa.Column("analyzer_id", sa.String(length=128), nullable=False),
        sa.Column("contract_kind", sa.String(length=64), nullable=False),
        sa.Column("contract_digest", sa.String(length=64), nullable=False),
        sa.Column("implementation_version", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["source_orchestrations.run_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("run_id", "authority"),
        sa.UniqueConstraint(
            "run_id",
            "authority",
            "capability",
            name="uq_source_orchestration_authority_contract",
        ),
        sa.UniqueConstraint(
            "run_id",
            "capability",
            name="uq_source_orchestration_authority_capability",
        ),
    )
    op.create_table(
        "source_orchestration_nodes",
        sa.Column("node_id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("authority", sa.String(length=64), nullable=False),
        sa.Column("capability", sa.String(length=64), nullable=False),
        sa.Column("component_id", sa.String(length=128), nullable=True),
        sa.Column("component_key", sa.String(length=128), nullable=False),
        sa.Column("analyzer_id", sa.String(length=128), nullable=False),
        sa.Column("contract_digest", sa.String(length=64), nullable=False),
        sa.Column("plan_entry_keys_json", sa.JSON(), nullable=False),
        sa.Column("selected_paths_json", sa.JSON(), nullable=False),
        sa.Column("scope_digest", sa.String(length=64), nullable=False),
        sa.Column("lifecycle_state", sa.String(length=32), nullable=False),
        sa.Column("terminal_disposition", sa.String(length=32), nullable=True),
        sa.Column("containment_state", sa.String(length=32), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["source_orchestrations.run_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["run_id", "authority", "capability"],
            [
                "source_orchestration_authorities.run_id",
                "source_orchestration_authorities.authority",
                "source_orchestration_authorities.capability",
            ],
            name="fk_source_node_authority_contract",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("node_id"),
        sa.UniqueConstraint("node_id", "run_id", name="uq_source_node_id_run"),
        sa.UniqueConstraint(
            "run_id",
            "authority",
            "capability",
            "component_key",
            name="uq_source_node_logical_identity",
        ),
        sa.CheckConstraint(
            "component_key = COALESCE(component_id, '')", name="ck_source_node_component_key"
        ),
        sa.CheckConstraint("state_version >= 1", name="ck_source_node_version"),
        sa.CheckConstraint(
            "lifecycle_state IN ('PLANNED', 'WAITING_DEPENDENCY', 'READY', "
            "'NOT_APPLICABLE', 'QUEUED', 'RUNNING', 'RETRY_PENDING', "
            "'RECONCILIATION_REQUIRED', 'TERMINAL')",
            name="ck_source_node_lifecycle",
        ),
        sa.CheckConstraint(
            "terminal_disposition IS NULL OR terminal_disposition IN "
            "('COMPLETE', 'PARTIAL', 'NOT_APPLICABLE', 'FAILED', "
            "'BLOCKED_BY_DEPENDENCY', 'CANCELLED')",
            name="ck_source_node_disposition",
        ),
        sa.CheckConstraint(
            "(lifecycle_state = 'TERMINAL') = (terminal_disposition IS NOT NULL)",
            name="ck_source_node_terminal_pair",
        ),
        sa.CheckConstraint(
            "containment_state IN ('NOT_STARTED', 'ACTIVE', 'RECONCILIATION_REQUIRED', 'CLEAN')",
            name="ck_source_node_containment",
        ),
    )
    op.create_index(
        "ix_source_orchestration_nodes_run_id",
        "source_orchestration_nodes",
        ["run_id"],
        unique=False,
    )
    op.create_table(
        "source_orchestration_dependencies",
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("node_id", sa.String(length=64), nullable=False),
        sa.Column("prerequisite_node_id", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["source_orchestrations.run_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["node_id", "run_id"],
            ["source_orchestration_nodes.node_id", "source_orchestration_nodes.run_id"],
            name="fk_source_dependency_node",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["prerequisite_node_id", "run_id"],
            ["source_orchestration_nodes.node_id", "source_orchestration_nodes.run_id"],
            name="fk_source_dependency_prerequisite",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("run_id", "node_id", "prerequisite_node_id"),
        sa.CheckConstraint("node_id <> prerequisite_node_id", name="ck_source_dependency_not_self"),
    )


def downgrade() -> None:
    op.drop_table("source_orchestration_dependencies")
    op.drop_index(
        "ix_source_orchestration_nodes_run_id",
        table_name="source_orchestration_nodes",
    )
    op.drop_table("source_orchestration_nodes")
    op.drop_table("source_orchestration_authorities")
    op.drop_table("source_orchestrations")

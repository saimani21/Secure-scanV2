"""add Source Engine Closure state

Revision ID: b6c3d9e8f120
Revises: a8d4e6f2c1b7

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b6c3d9e8f120"
down_revision: str | Sequence[str] | None = "a8d4e6f2c1b7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "source_orchestrations",
        sa.Column(
            "max_active_jobs",
            sa.Integer(),
            nullable=False,
            server_default="2",
        ),
    )
    for column in (
        sa.Column("deadline_exceeded_at", sa.DateTime(timezone=True)),
        sa.Column("assembly_artifact_sha256", sa.String(64)),
        sa.Column("assembly_artifact_size_bytes", sa.Integer()),
        sa.Column("assembly_artifact_media_type", sa.String(128)),
        sa.Column("assembly_schema_version", sa.String(128)),
        sa.Column("assembly_artifact_storage_path", sa.Text()),
        sa.Column("assembled_at", sa.DateTime(timezone=True)),
        sa.Column("published_at", sa.DateTime(timezone=True)),
    ):
        op.add_column("source_orchestrations", column)
    with op.batch_alter_table("source_orchestrations") as batch_op:
        batch_op.create_check_constraint(
            "ck_source_orchestrations_max_active_jobs",
            "max_active_jobs BETWEEN 1 AND 4",
        )
        batch_op.create_check_constraint(
            "ck_source_orchestrations_assembly_reference",
            "(assembly_artifact_sha256 IS NULL AND assembly_artifact_size_bytes IS NULL "
            "AND assembly_artifact_media_type IS NULL AND assembly_schema_version IS NULL "
            "AND assembly_artifact_storage_path IS NULL AND assembled_at IS NULL) OR "
            "(assembly_artifact_sha256 IS NOT NULL AND assembly_artifact_size_bytes IS NOT NULL "
            "AND assembly_artifact_media_type IS NOT NULL AND assembly_schema_version IS NOT NULL "
            "AND assembly_artifact_storage_path IS NOT NULL AND assembled_at IS NOT NULL)",
        )
        batch_op.create_check_constraint(
            "ck_source_orchestrations_publication_requires_assembly",
            "published_at IS NULL OR assembled_at IS NOT NULL",
        )
        batch_op.alter_column("max_active_jobs", server_default=None)

    with op.batch_alter_table("source_orchestration_scanner_jobs") as batch_op:
        batch_op.add_column(
            sa.Column(
                "input_kind",
                sa.String(32),
                nullable=False,
                server_default="SOURCE_PROJECTION",
            )
        )
        batch_op.add_column(sa.Column("dependency_evaluation_sha256", sa.String(64)))
        batch_op.add_column(sa.Column("dependency_evaluation_size_bytes", sa.Integer()))
        batch_op.add_column(sa.Column("dependency_evaluation_schema_version", sa.String(128)))
        batch_op.add_column(sa.Column("syft_native_result_sha256", sa.String(64)))
        batch_op.add_column(sa.Column("osv_scope_digest", sa.String(64)))
        batch_op.add_column(sa.Column("execution_input_sha256", sa.String(64)))
        batch_op.add_column(sa.Column("execution_input_size_bytes", sa.Integer()))
        batch_op.add_column(sa.Column("execution_input_schema_version", sa.String(128)))
        for column in (
            "context_digest",
            "context_artifact_sha256",
            "context_artifact_size_bytes",
            "context_artifact_storage_path",
            "projection_id",
            "projection_digest",
        ):
            batch_op.alter_column(column, nullable=True)
        batch_op.create_check_constraint(
            "ck_source_scanner_job_input_kind",
            "(input_kind = 'SOURCE_PROJECTION' AND context_digest IS NOT NULL "
            "AND context_artifact_sha256 IS NOT NULL AND context_artifact_size_bytes IS NOT NULL "
            "AND context_artifact_storage_path IS NOT NULL AND projection_id IS NOT NULL "
            "AND projection_digest IS NOT NULL AND dependency_evaluation_sha256 IS NULL "
            "AND dependency_evaluation_size_bytes IS NULL "
            "AND dependency_evaluation_schema_version IS NULL "
            "AND syft_native_result_sha256 IS NULL AND osv_scope_digest IS NULL "
            "AND execution_input_sha256 IS NULL AND execution_input_size_bytes IS NULL "
            "AND execution_input_schema_version IS NULL) OR "
            "(input_kind = 'OSV_DEPENDENCY_INPUT' AND context_digest IS NULL "
            "AND context_artifact_sha256 IS NULL AND context_artifact_size_bytes IS NULL "
            "AND context_artifact_storage_path IS NULL AND projection_id IS NULL "
            "AND projection_digest IS NULL AND dependency_evaluation_sha256 IS NOT NULL "
            "AND dependency_evaluation_size_bytes IS NOT NULL "
            "AND dependency_evaluation_schema_version IS NOT NULL "
            "AND syft_native_result_sha256 IS NOT NULL AND osv_scope_digest IS NOT NULL "
            "AND execution_input_sha256 IS NOT NULL AND execution_input_size_bytes IS NOT NULL "
            "AND execution_input_schema_version IS NOT NULL)",
        )
        batch_op.alter_column("input_kind", server_default=None)

    with op.batch_alter_table("source_orchestration_attempts") as batch_op:
        batch_op.add_column(sa.Column("dependency_input_revalidated", sa.Boolean()))
        batch_op.drop_constraint("ck_source_attempt_acceptance_proof", type_="check")
        batch_op.create_check_constraint(
            "ck_source_attempt_acceptance_proof",
            "acceptance_state <> 'ACCEPTED' OR "
            "(containment_state = 'CLEAN' AND "
            "((projection_revalidated = true AND dependency_input_revalidated IS NULL) OR "
            "(projection_revalidated IS NULL AND dependency_input_revalidated = true)) "
            "AND tool_execution_id IS NOT NULL)",
        )

    op.create_table(
        "source_osv_request_permits",
        sa.Column("job_id", sa.String(36), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("request_sequence", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("node_id", sa.String(64), nullable=False),
        sa.Column("operation_kind", sa.String(32), nullable=False),
        sa.Column("logical_request_digest", sa.String(64), nullable=False),
        sa.Column("transport_attempt_number", sa.Integer(), nullable=False),
        sa.Column("helper_identity", sa.String(64), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("request_sequence >= 1", name="ck_source_osv_permit_sequence"),
        sa.CheckConstraint(
            "transport_attempt_number >= 1",
            name="ck_source_osv_permit_transport_attempt",
        ),
        sa.CheckConstraint(
            "operation_kind IN ('QUERY_BATCH', 'ADVISORY_GET')",
            name="ck_source_osv_permit_operation_kind",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "run_id", "node_id"],
            [
                "source_orchestration_scanner_jobs.job_id",
                "source_orchestration_scanner_jobs.run_id",
                "source_orchestration_scanner_jobs.node_id",
            ],
            name="fk_source_osv_permit_job",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "attempt_number"],
            [
                "source_orchestration_attempts.job_id",
                "source_orchestration_attempts.attempt_number",
            ],
            name="fk_source_osv_permit_attempt",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("job_id", "attempt_number", "request_sequence"),
        sa.UniqueConstraint(
            "job_id",
            "attempt_number",
            "logical_request_digest",
            "transport_attempt_number",
            name="uq_source_osv_permit_logical_attempt",
        ),
    )


def downgrade() -> None:
    op.drop_table("source_osv_request_permits")
    with op.batch_alter_table("source_orchestration_attempts") as batch_op:
        batch_op.drop_constraint("ck_source_attempt_acceptance_proof", type_="check")
        batch_op.drop_column("dependency_input_revalidated")
        batch_op.create_check_constraint(
            "ck_source_attempt_acceptance_proof",
            "acceptance_state <> 'ACCEPTED' OR "
            "(containment_state = 'CLEAN' AND projection_revalidated = true "
            "AND tool_execution_id IS NOT NULL)",
        )
    with op.batch_alter_table("source_orchestration_scanner_jobs") as batch_op:
        batch_op.drop_constraint("ck_source_scanner_job_input_kind", type_="check")
        for column in (
            "execution_input_schema_version",
            "execution_input_size_bytes",
            "execution_input_sha256",
            "osv_scope_digest",
            "syft_native_result_sha256",
            "dependency_evaluation_schema_version",
            "dependency_evaluation_size_bytes",
            "dependency_evaluation_sha256",
            "input_kind",
        ):
            batch_op.drop_column(column)
        for column in (
            "context_digest",
            "context_artifact_sha256",
            "context_artifact_size_bytes",
            "context_artifact_storage_path",
            "projection_id",
            "projection_digest",
        ):
            batch_op.alter_column(column, nullable=False)
    with op.batch_alter_table("source_orchestrations") as batch_op:
        batch_op.drop_constraint(
            "ck_source_orchestrations_max_active_jobs", type_="check"
        )
        batch_op.drop_constraint(
            "ck_source_orchestrations_publication_requires_assembly", type_="check"
        )
        batch_op.drop_constraint("ck_source_orchestrations_assembly_reference", type_="check")
        for column in (
            "published_at",
            "assembled_at",
            "assembly_artifact_storage_path",
            "assembly_schema_version",
            "assembly_artifact_media_type",
            "assembly_artifact_size_bytes",
            "assembly_artifact_sha256",
            "deadline_exceeded_at",
        ):
            batch_op.drop_column(column)
        batch_op.drop_column("max_active_jobs")

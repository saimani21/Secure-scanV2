from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    text,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)

from securescan.config import Settings
from securescan.domain.enums import JobFailureCategory, JobStatus


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(UTC)


JOB_STATUS_SQL = ", ".join(
    f"'{status.value}'"
    for status in JobStatus
)
JOB_FAILURE_CATEGORY_SQL = ", ".join(
    f"'{category.value}'"
    for category in JobFailureCategory
)


class Base(DeclarativeBase):
    pass


class ProjectRow(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    targets: Mapped[list[TargetRow]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
    )


class TargetRow(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    project_id: Mapped[str] = mapped_column(
        ForeignKey(
            "projects.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )
    target_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    content_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    source_path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    metadata_json: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    project: Mapped[ProjectRow] = relationship(
        back_populates="targets",
    )
    runs: Mapped[list[AnalysisRunRow]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
    )


class AnalysisRunRow(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    target_id: Mapped[str] = mapped_column(
        ForeignKey(
            "targets.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    report_json: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    target: Mapped[TargetRow] = relationship(
        back_populates="runs",
    )
    jobs: Mapped[list[JobRow]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
    )
    executions: Mapped[list[ToolExecutionRow]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
    )


class JobRow(Base):
    __tablename__ = "jobs"

    __table_args__ = (
        CheckConstraint(
            "priority >= 0",
            name="ck_jobs_priority_nonnegative",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_jobs_attempt_count_nonnegative",
        ),
        CheckConstraint(
            "max_attempts >= 1",
            name="ck_jobs_max_attempts_positive",
        ),
        CheckConstraint(
            "attempt_count <= max_attempts",
            name="ck_jobs_attempt_count_within_limit",
        ),
        CheckConstraint(
            f"status IN ({JOB_STATUS_SQL})",
            name="ck_jobs_status",
        ),
        CheckConstraint(
            "cancel_requested_at IS NULL OR cancel_requested = true",
            name="ck_jobs_cancel_timestamp_requires_flag",
        ),
        UniqueConstraint(
            "idempotency_key",
            name="uq_jobs_idempotency_key",
        ),
        Index(
            "ix_jobs_claim",
            "status",
            "available_at",
            "priority",
            "created_at",
        ),
        Index(
            "ix_jobs_cancel_reap",
            "cancel_requested",
            "status",
            "lease_expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    run_id: Mapped[str] = mapped_column(
        ForeignKey(
            "analysis_runs.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )
    adapter_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=JobStatus.SUBMITTED.value,
    )
    priority: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=100,
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    max_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3,
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    leased_by: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )
    lease_token: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    cancel_requested: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    idempotency_key: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    payload_json: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    last_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    run: Mapped[AnalysisRunRow] = relationship(
        back_populates="jobs",
    )


class ToolExecutionRow(Base):
    __tablename__ = "tool_executions"

    __table_args__ = (
        CheckConstraint(
            "attempt_number IS NULL OR attempt_number >= 1",
            name="ck_tool_executions_attempt_positive",
        ),
        CheckConstraint(
            "failure_category IS NULL "
            f"OR failure_category IN ({JOB_FAILURE_CATEGORY_SQL})",
            name="ck_tool_executions_failure_category",
        ),
        UniqueConstraint(
            "job_id",
            "attempt_number",
            name="uq_tool_executions_job_attempt",
        ),
        Index(
            "ix_tool_executions_job_id",
            "job_id",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    run_id: Mapped[str] = mapped_column(
        ForeignKey(
            "analysis_runs.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )
    job_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey(
            "jobs.id",
            name="fk_tool_executions_job_id_jobs",
            ondelete="CASCADE",
        ),
        nullable=True,
    )
    attempt_number: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    adapter_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    tool_version: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    adapter_version: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    outcome: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    exit_code: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    duration_ms: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    warning_json: Mapped[list] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    failure_category: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    retryable: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    run: Mapped[AnalysisRunRow] = relationship(
        back_populates="executions",
    )


class SourceOrchestrationRow(Base):
    __tablename__ = "source_orchestrations"

    __table_args__ = (
        CheckConstraint("state_version >= 1", name="ck_source_orchestrations_version"),
        CheckConstraint(
            "max_active_jobs BETWEEN 1 AND 4",
            name="ck_source_orchestrations_max_active_jobs",
        ),
        CheckConstraint("snapshot_size_bytes >= 1", name="ck_source_orchestrations_snapshot_size"),
        CheckConstraint(
            "lifecycle_state IN ('PREPARED', 'ACTIVE', 'CANCELLATION_REQUESTED', "
            "'ASSEMBLY_READY', 'ASSEMBLING', 'COMMITTING', 'TERMINAL')",
            name="ck_source_orchestrations_lifecycle",
        ),
        CheckConstraint(
            "terminal_outcome IS NULL OR terminal_outcome IN "
            "('COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED')",
            name="ck_source_orchestrations_terminal_outcome",
        ),
        CheckConstraint(
            "(lifecycle_state = 'TERMINAL') = (terminal_outcome IS NOT NULL)",
            name="ck_source_orchestrations_terminal_pair",
        ),
        CheckConstraint(
            "cancel_requested_at IS NULL OR cancel_requested = true",
            name="ck_source_orchestrations_cancel_timestamp",
        ),
        CheckConstraint(
            "(assembly_artifact_sha256 IS NULL AND assembly_artifact_size_bytes IS NULL "
            "AND assembly_artifact_media_type IS NULL AND assembly_schema_version IS NULL "
            "AND assembly_artifact_storage_path IS NULL AND assembled_at IS NULL) OR "
            "(assembly_artifact_sha256 IS NOT NULL AND assembly_artifact_size_bytes IS NOT NULL "
            "AND assembly_artifact_media_type IS NOT NULL AND assembly_schema_version IS NOT NULL "
            "AND assembly_artifact_storage_path IS NOT NULL AND assembled_at IS NOT NULL)",
            name="ck_source_orchestrations_assembly_reference",
        ),
        CheckConstraint(
            "published_at IS NULL OR assembled_at IS NOT NULL",
            name="ck_source_orchestrations_publication_requires_assembly",
        ),
        UniqueConstraint("idempotency_key", name="uq_source_orchestrations_idempotency"),
    )

    run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        primary_key=True,
    )
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    creation_request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    repository_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    profile_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    roster_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    planning_snapshot_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot_media_type: Mapped[str] = mapped_column(String(128), nullable=False)
    snapshot_schema_version: Mapped[str] = mapped_column(String(128), nullable=False)
    snapshot_storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False)
    terminal_outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    max_active_jobs: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deadline_exceeded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    assembly_artifact_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    assembly_artifact_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    assembly_artifact_media_type: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    assembly_schema_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    assembly_artifact_storage_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    assembled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class SourceOrchestrationAuthorityRow(Base):
    __tablename__ = "source_orchestration_authorities"

    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "authority",
            "capability",
            name="uq_source_orchestration_authority_contract",
        ),
        UniqueConstraint(
            "run_id",
            "capability",
            name="uq_source_orchestration_authority_capability",
        ),
    )

    run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("source_orchestrations.run_id", ondelete="CASCADE"),
        primary_key=True,
    )
    authority: Mapped[str] = mapped_column(String(64), primary_key=True)
    capability: Mapped[str] = mapped_column(String(64), nullable=False)
    analyzer_id: Mapped[str] = mapped_column(String(128), nullable=False)
    contract_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    contract_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    implementation_version: Mapped[str] = mapped_column(String(64), nullable=False)


class SourceOrchestrationNodeRow(Base):
    __tablename__ = "source_orchestration_nodes"

    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "authority", "capability"],
            [
                "source_orchestration_authorities.run_id",
                "source_orchestration_authorities.authority",
                "source_orchestration_authorities.capability",
            ],
            name="fk_source_node_authority_contract",
            ondelete="CASCADE",
        ),
        UniqueConstraint("node_id", "run_id", name="uq_source_node_id_run"),
        UniqueConstraint(
            "run_id",
            "authority",
            "capability",
            "component_key",
            name="uq_source_node_logical_identity",
        ),
        CheckConstraint(
            "component_key = COALESCE(component_id, '')", name="ck_source_node_component_key"
        ),
        CheckConstraint("state_version >= 1", name="ck_source_node_version"),
        CheckConstraint(
            "lifecycle_state IN ('PLANNED', 'WAITING_DEPENDENCY', 'READY', "
            "'NOT_APPLICABLE', 'QUEUED', 'RUNNING', 'RETRY_PENDING', "
            "'RECONCILIATION_REQUIRED', 'TERMINAL')",
            name="ck_source_node_lifecycle",
        ),
        CheckConstraint(
            "terminal_disposition IS NULL OR terminal_disposition IN "
            "('COMPLETE', 'PARTIAL', 'NOT_APPLICABLE', 'FAILED', "
            "'BLOCKED_BY_DEPENDENCY', 'CANCELLED')",
            name="ck_source_node_disposition",
        ),
        CheckConstraint(
            "(lifecycle_state = 'TERMINAL') = (terminal_disposition IS NOT NULL)",
            name="ck_source_node_terminal_pair",
        ),
        CheckConstraint(
            "lifecycle_state = 'TERMINAL' OR terminal_reason_code IS NULL",
            name="ck_source_node_terminal_reason",
        ),
        CheckConstraint(
            "containment_state IN ('NOT_STARTED', 'ACTIVE', 'RECONCILIATION_REQUIRED', 'CLEAN')",
            name="ck_source_node_containment",
        ),
    )

    node_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("source_orchestrations.run_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    authority: Mapped[str] = mapped_column(String(64), nullable=False)
    capability: Mapped[str] = mapped_column(String(64), nullable=False)
    component_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    component_key: Mapped[str] = mapped_column(String(128), nullable=False)
    analyzer_id: Mapped[str] = mapped_column(String(128), nullable=False)
    contract_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    plan_entry_keys_json: Mapped[list] = mapped_column(JSON, nullable=False)
    selected_paths_json: Mapped[list] = mapped_column(JSON, nullable=False)
    scope_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False)
    terminal_disposition: Mapped[str | None] = mapped_column(String(32), nullable=True)
    terminal_reason_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    containment_state: Mapped[str] = mapped_column(String(32), nullable=False)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class SourceOrchestrationDependencyEvaluationRow(Base):
    __tablename__ = "source_orchestration_dependency_evaluations"

    __table_args__ = (
        ForeignKeyConstraint(
            ["osv_node_id", "run_id"],
            ["source_orchestration_nodes.node_id", "source_orchestration_nodes.run_id"],
            name="fk_source_dependency_evaluation_osv_node",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["syft_node_id", "run_id"],
            ["source_orchestration_nodes.node_id", "source_orchestration_nodes.run_id"],
            name="fk_source_dependency_evaluation_syft_node",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["syft_job_id", "run_id", "syft_node_id"],
            [
                "source_orchestration_scanner_jobs.job_id",
                "source_orchestration_scanner_jobs.run_id",
                "source_orchestration_scanner_jobs.node_id",
            ],
            name="fk_source_dependency_evaluation_syft_job",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["syft_job_id", "syft_selected_attempt_number"],
            [
                "source_orchestration_attempts.job_id",
                "source_orchestration_attempts.attempt_number",
            ],
            name="fk_source_dependency_evaluation_syft_attempt",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "syft_selected_attempt_number >= 1",
            name="ck_source_dependency_evaluation_attempt",
        ),
        CheckConstraint(
            "evaluation_artifact_size_bytes >= 1",
            name="ck_source_dependency_evaluation_size",
        ),
    )

    run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("source_orchestrations.run_id", ondelete="CASCADE"),
        primary_key=True,
    )
    osv_node_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    syft_node_id: Mapped[str] = mapped_column(String(64), nullable=False)
    syft_job_id: Mapped[str] = mapped_column(String(36), nullable=False)
    syft_selected_attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    syft_native_result_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    evaluation_artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    evaluation_artifact_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    evaluation_artifact_media_type: Mapped[str] = mapped_column(String(128), nullable=False)
    evaluation_schema_version: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SourceOrchestrationDependencyRow(Base):
    __tablename__ = "source_orchestration_dependencies"

    __table_args__ = (
        ForeignKeyConstraint(
            ["node_id", "run_id"],
            ["source_orchestration_nodes.node_id", "source_orchestration_nodes.run_id"],
            name="fk_source_dependency_node",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["prerequisite_node_id", "run_id"],
            ["source_orchestration_nodes.node_id", "source_orchestration_nodes.run_id"],
            name="fk_source_dependency_prerequisite",
            ondelete="CASCADE",
        ),
        CheckConstraint("node_id <> prerequisite_node_id", name="ck_source_dependency_not_self"),
    )

    run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("source_orchestrations.run_id", ondelete="CASCADE"),
        primary_key=True,
    )
    node_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    prerequisite_node_id: Mapped[str] = mapped_column(String(64), primary_key=True)


class SourceOrchestrationScannerJobRow(Base):
    __tablename__ = "source_orchestration_scanner_jobs"

    __table_args__ = (
        ForeignKeyConstraint(
            ["node_id", "run_id"],
            ["source_orchestration_nodes.node_id", "source_orchestration_nodes.run_id"],
            name="fk_source_scanner_job_node_run",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["run_id", "authority", "capability"],
            [
                "source_orchestration_authorities.run_id",
                "source_orchestration_authorities.authority",
                "source_orchestration_authorities.capability",
            ],
            name="fk_source_scanner_job_authority",
            ondelete="CASCADE",
        ),
        UniqueConstraint("node_id", name="uq_source_scanner_job_node"),
        UniqueConstraint(
            "job_id",
            "run_id",
            "node_id",
            name="uq_source_scanner_job_dependency_identity",
        ),
        CheckConstraint(
            "selected_attempt_number IS NULL OR selected_attempt_number >= 1",
            name="ck_source_scanner_job_selected_attempt",
        ),
        CheckConstraint(
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
            name="ck_source_scanner_job_input_kind",
        ),
    )

    job_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("jobs.id", ondelete="CASCADE"),
        primary_key=True,
    )
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    node_id: Mapped[str] = mapped_column(String(64), nullable=False)
    authority: Mapped[str] = mapped_column(String(64), nullable=False)
    capability: Mapped[str] = mapped_column(String(64), nullable=False)
    analyzer_id: Mapped[str] = mapped_column(String(128), nullable=False)
    contract_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    input_kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default="SOURCE_PROJECTION"
    )
    context_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    context_artifact_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    context_artifact_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    context_artifact_storage_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    projection_id: Mapped[str | None] = mapped_column(String(96), nullable=True)
    projection_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dependency_evaluation_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dependency_evaluation_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dependency_evaluation_schema_version: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    syft_native_result_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    osv_scope_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    execution_input_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    execution_input_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    execution_input_schema_version: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    selected_attempt_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SourceOrchestrationAttemptRow(Base):
    __tablename__ = "source_orchestration_attempts"

    __table_args__ = (
        ForeignKeyConstraint(
            ["node_id", "run_id"],
            ["source_orchestration_nodes.node_id", "source_orchestration_nodes.run_id"],
            name="fk_source_attempt_node_run",
            ondelete="CASCADE",
        ),
        CheckConstraint("attempt_number >= 1", name="ck_source_attempt_number"),
        CheckConstraint(
            "containment_state IN ('ACTIVE', 'RECONCILIATION_REQUIRED', 'CLEAN')",
            name="ck_source_attempt_containment",
        ),
        CheckConstraint(
            "acceptance_state IN ('PENDING', 'ACCEPTED', 'REJECTED')",
            name="ck_source_attempt_acceptance",
        ),
        CheckConstraint(
            "(acceptance_state = 'ACCEPTED') = (native_result_sha256 IS NOT NULL)",
            name="ck_source_attempt_accepted_result",
        ),
        CheckConstraint(
            "(native_result_sha256 IS NULL AND native_result_size_bytes IS NULL "
            "AND native_result_media_type IS NULL AND native_result_schema_version IS NULL "
            "AND native_result_storage_path IS NULL AND accepted_at IS NULL) OR "
            "(native_result_sha256 IS NOT NULL AND native_result_size_bytes IS NOT NULL "
            "AND native_result_media_type IS NOT NULL "
            "AND native_result_schema_version IS NOT NULL "
            "AND native_result_storage_path IS NOT NULL AND accepted_at IS NOT NULL)",
            name="ck_source_attempt_result_reference",
        ),
        CheckConstraint(
            "acceptance_state <> 'ACCEPTED' OR "
            "(containment_state = 'CLEAN' AND "
            "((projection_revalidated = true AND dependency_input_revalidated IS NULL) OR "
            "(projection_revalidated IS NULL AND dependency_input_revalidated = true)) "
            "AND tool_execution_id IS NOT NULL)",
            name="ck_source_attempt_acceptance_proof",
        ),
        CheckConstraint(
            "cleanup_receipt_sha256 IS NULL OR cleanup_receipt_json IS NOT NULL",
            name="ck_source_attempt_receipt_pair",
        ),
        UniqueConstraint("attempt_token", name="uq_source_attempt_token"),
        UniqueConstraint("tool_execution_id", name="uq_source_attempt_tool_execution"),
        Index(
            "uq_source_attempt_selected_node",
            "node_id",
            unique=True,
            sqlite_where=text("acceptance_state = 'ACCEPTED'"),
            postgresql_where=text("acceptance_state = 'ACCEPTED'"),
        ),
    )

    job_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("source_orchestration_scanner_jobs.job_id", ondelete="CASCADE"),
        primary_key=True,
    )
    attempt_number: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    node_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_token: Mapped[str] = mapped_column(String(36), nullable=False)
    worker_id: Mapped[str] = mapped_column(String(200), nullable=False)
    lease_token: Mapped[str] = mapped_column(String(36), nullable=False)
    containment_state: Mapped[str] = mapped_column(String(32), nullable=False)
    acceptance_state: Mapped[str] = mapped_column(String(16), nullable=False)
    supervisor_identity: Mapped[str | None] = mapped_column(String(64), nullable=True)
    supervisor_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    supervisor_start_ticks: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scanner_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scanner_pgid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scanner_start_ticks: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cleanup_receipt_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cleanup_receipt_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    tool_execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("tool_executions.id", ondelete="RESTRICT"), nullable=True
    )
    native_result_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    native_result_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    native_result_media_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    native_result_schema_version: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    native_result_storage_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    projection_revalidated: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    dependency_input_revalidated: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SourceOsvRequestPermitRow(Base):
    __tablename__ = "source_osv_request_permits"

    __table_args__ = (
        ForeignKeyConstraint(
            ["job_id", "run_id", "node_id"],
            [
                "source_orchestration_scanner_jobs.job_id",
                "source_orchestration_scanner_jobs.run_id",
                "source_orchestration_scanner_jobs.node_id",
            ],
            name="fk_source_osv_permit_job",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["job_id", "attempt_number"],
            [
                "source_orchestration_attempts.job_id",
                "source_orchestration_attempts.attempt_number",
            ],
            name="fk_source_osv_permit_attempt",
            ondelete="CASCADE",
        ),
        CheckConstraint("request_sequence >= 1", name="ck_source_osv_permit_sequence"),
        CheckConstraint(
            "transport_attempt_number >= 1",
            name="ck_source_osv_permit_transport_attempt",
        ),
        CheckConstraint(
            "operation_kind IN ('QUERY_BATCH', 'ADVISORY_GET')",
            name="ck_source_osv_permit_operation_kind",
        ),
        UniqueConstraint(
            "job_id",
            "attempt_number",
            "logical_request_digest",
            "transport_attempt_number",
            name="uq_source_osv_permit_logical_attempt",
        ),
    )

    job_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    attempt_number: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    node_id: Mapped[str] = mapped_column(String(64), nullable=False)
    operation_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    logical_request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    transport_attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    helper_identity: Mapped[str] = mapped_column(String(64), nullable=False)
    authorized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def create_session_factory(settings: Settings):
    is_sqlite = settings.database_url.startswith("sqlite")

    connect_args = (
        {"check_same_thread": False}
        if is_sqlite
        else {}
    )

    engine = create_engine(
        settings.database_url,
        connect_args=connect_args,
    )

    if is_sqlite:

        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(
            dbapi_connection,
            _connection_record,
        ) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    session_factory = sessionmaker(
        bind=engine,
        expire_on_commit=False,
    )

    return engine, session_factory


def initialize_database(settings: Settings) -> None:
    engine, _ = create_session_factory(settings)
    Base.metadata.create_all(engine)

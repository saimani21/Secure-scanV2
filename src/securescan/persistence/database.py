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
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
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
    containment_state: Mapped[str] = mapped_column(String(32), nullable=False)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


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

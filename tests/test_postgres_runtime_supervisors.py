from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import get_settings
from securescan.domain.enums import (
    ExecutionOutcome,
    JobStatus,
    RunStatus,
    TargetType,
)
from securescan.domain.models import ScanReport, TargetProfile
from securescan.jobs import (
    JobCancellationService,
    JobExecutionService,
    JobFailureCommitService,
    JobHeartbeatService,
    JobLeaseRecoveryService,
    JobLeasingService,
    JobRepository,
    JobResultCommitService,
    JobRetryPromotionService,
    JobSubmissionRequest,
    JobSubmissionResult,
    JobSubmissionService,
    ToolExecutionCommit,
)
from securescan.maintenance import (
    CancellationReaperOperation,
    LeaseRecoveryOperation,
    MaintenanceCoordinator,
    MaintenanceOperationName,
    MaintenanceTask,
    MaintenanceTaskConfiguration,
    RetryPromotionOperation,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
    create_session_factory,
)
from securescan.worker import (
    SingleJobWorkerCycle,
    WorkerDaemon,
    WorkerDaemonExitReason,
    WorkerSuccessfulExecution,
)

pytestmark = pytest.mark.postgres

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"
BASE_TIME = datetime(2046, 2, 3, 4, 5, 6, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _PostgresRuntimeContext:
    engine: Engine
    session_factory: sessionmaker[Session]
    target_id: str


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL runtime-supervisor integration test"
        )
    try:
        parsed_url = make_url(database_url)
    except ArgumentError as exc:
        pytest.fail(f"Unsafe SECURESCAN_TEST_POSTGRES_URL: URL could not be parsed: {exc}")
    if not parsed_url.get_backend_name().startswith("postgresql"):
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: backend must be PostgreSQL")
    if not parsed_url.database:
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: database name is required")
    if not parsed_url.database.endswith("_test"):
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: database name must end with _test")
    return database_url


def _reset_public_schema(database_url: str) -> None:
    engine = create_engine(database_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


@pytest.fixture
def postgres_runtime_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresRuntimeContext]:
    database_url = _validated_test_database_url()
    alembic_config = Config(str(ALEMBIC_INI_PATH))
    alembic_config.set_main_option("script_location", str(MIGRATIONS_PATH))
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()
    engine: Engine | None = None

    try:
        _reset_public_schema(database_url)
        command.upgrade(alembic_config, "head")
        engine, session_factory = create_session_factory(get_settings())
        with session_factory.begin() as session:
            project = ProjectRow(name="PostgreSQL runtime supervisor test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="d" * 64,
                source_path="/tmp/postgres-runtime-supervisor",
            )
            session.add(target)
            session.flush()
            target_id = target.id
        yield _PostgresRuntimeContext(engine, session_factory, target_id)
    finally:
        if engine is not None:
            engine.dispose()
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def _submit(
    context: _PostgresRuntimeContext,
    idempotency_key: str,
    *,
    max_attempts: int = 3,
) -> JobSubmissionResult:
    return JobSubmissionService(context.session_factory).submit(
        JobSubmissionRequest(
            target_id=context.target_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
            max_attempts=max_attempts,
        )
    )


def _report_json(run_id: str, marker: str) -> dict[str, Any]:
    return ScanReport(
        run_id=UUID(run_id),
        target=TargetProfile(
            target_type=TargetType.SOURCE_REPOSITORY,
            path=Path("/tmp/postgres-runtime-supervisor"),
            content_digest="d" * 64,
            metadata={"runtime_marker": marker},
        ),
        status=RunStatus.COMPLETED,
        executions=[],
        observations=[],
        generated_at=BASE_TIME + timedelta(seconds=2),
    ).model_dump(mode="json")


class _SuccessfulAdapter:
    adapter_id = "fake-scanner"
    adapter_version = "runtime-test-1"
    tool_version = "scanner-test-1"

    def execute(self, job):
        return WorkerSuccessfulExecution(
            final_status=JobStatus.SUCCEEDED,
            report_json=_report_json(job.run_id, "daemon-success"),
            tool_execution=ToolExecutionCommit(
                tool_version=self.tool_version,
                adapter_version=self.adapter_version,
                outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
                exit_code=0,
                duration_ms=20,
                warning_json=[],
            ),
        )


class _Resolver:
    def __init__(self, adapter: _SuccessfulAdapter) -> None:
        self.adapter = adapter

    def resolve(self, _adapter_id: str) -> _SuccessfulAdapter:
        return self.adapter


def _maintenance_tasks(
    session_factory: sessionmaker[Session],
    operation_time: datetime,
) -> list[MaintenanceTask]:
    configurations = {
        name: MaintenanceTaskConfiguration(name, 60, 100) for name in MaintenanceOperationName
    }
    return [
        MaintenanceTask(
            configurations[MaintenanceOperationName.RETRY_PROMOTION],
            RetryPromotionOperation(
                JobRetryPromotionService(
                    session_factory,
                    clock=lambda: operation_time,
                )
            ),
        ),
        MaintenanceTask(
            configurations[MaintenanceOperationName.LEASE_RECOVERY],
            LeaseRecoveryOperation(
                JobLeaseRecoveryService(
                    session_factory,
                    clock=lambda: operation_time,
                    retry_delay_seconds=lambda _attempt: 5,
                )
            ),
        ),
        MaintenanceTask(
            configurations[MaintenanceOperationName.CANCELLATION_REAPER],
            CancellationReaperOperation(
                JobCancellationService(
                    session_factory,
                    clock=lambda: operation_time,
                )
            ),
        ),
    ]


def test_postgres_worker_daemon_processes_one_job_end_to_end(
    postgres_runtime_context: _PostgresRuntimeContext,
) -> None:
    submitted = _submit(postgres_runtime_context, "a" * 64)
    cancellation = JobCancellationService(
        postgres_runtime_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=2),
    )
    cycle = SingleJobWorkerCycle(
        JobLeasingService(
            postgres_runtime_context.session_factory,
            clock=lambda: BASE_TIME,
        ),
        JobExecutionService(
            postgres_runtime_context.session_factory,
            clock=lambda: BASE_TIME + timedelta(seconds=1),
        ),
        JobResultCommitService(
            postgres_runtime_context.session_factory,
            clock=lambda: BASE_TIME + timedelta(seconds=2),
        ),
        JobFailureCommitService(
            postgres_runtime_context.session_factory,
            clock=lambda: BASE_TIME + timedelta(seconds=2),
        ),
        _Resolver(_SuccessfulAdapter()),
        JobRepository(postgres_runtime_context.session_factory),
        cancellation,
        JobHeartbeatService(
            postgres_runtime_context.session_factory,
            clock=lambda: BASE_TIME + timedelta(seconds=2),
        ),
        "daemon-postgres-worker",
    )

    result = WorkerDaemon(
        cycle,
        threading.Event(),
        max_cycles=1,
    ).run()

    with postgres_runtime_context.session_factory() as session:
        job = session.get(JobRow, submitted.job_id)
        run = session.get(AnalysisRunRow, submitted.run_id)
        executions = list(
            session.scalars(
                select(ToolExecutionRow).where(ToolExecutionRow.job_id == submitted.job_id)
            )
        )
        assert job is not None
        assert run is not None
        assert result.exit_reason is WorkerDaemonExitReason.MAX_CYCLES_REACHED
        assert result.processed_cycles == 1
        assert result.errors == 0
        assert job.status == JobStatus.SUCCEEDED.value
        assert job.leased_by is None
        assert job.lease_token is None
        assert job.lease_expires_at is None
        assert run.status == RunStatus.COMPLETED.value
        assert run.report_json == _report_json(submitted.run_id, "daemon-success")
        assert len(executions) == 1


def test_postgres_two_maintenance_coordinators_promote_due_retries_once(
    postgres_runtime_context: _PostgresRuntimeContext,
) -> None:
    due_jobs = [_submit(postgres_runtime_context, str(index) * 64) for index in range(1, 5)]
    future_job = _submit(postgres_runtime_context, "f" * 64)
    with postgres_runtime_context.session_factory.begin() as session:
        for submitted in due_jobs:
            row = session.get(JobRow, submitted.job_id)
            assert row is not None
            row.status = JobStatus.RETRY_PENDING.value
            row.attempt_count = 1
            row.available_at = BASE_TIME
        future_row = session.get(JobRow, future_job.job_id)
        assert future_row is not None
        future_row.status = JobStatus.RETRY_PENDING.value
        future_row.attempt_count = 1
        future_row.available_at = BASE_TIME + timedelta(seconds=1)

    factory_a = sessionmaker(bind=postgres_runtime_context.engine, expire_on_commit=False)
    factory_b = sessionmaker(bind=postgres_runtime_context.engine, expire_on_commit=False)
    coordinator_a = MaintenanceCoordinator(
        _maintenance_tasks(factory_a, BASE_TIME),
        threading.Event(),
    )
    coordinator_b = MaintenanceCoordinator(
        _maintenance_tasks(factory_b, BASE_TIME),
        threading.Event(),
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_a = executor.submit(coordinator_a.run_due_operations)
        future_b = executor.submit(coordinator_b.run_due_operations)
        results = [future_a.result(timeout=5), future_b.result(timeout=5)]

    promotion_index = list(MaintenanceOperationName).index(MaintenanceOperationName.RETRY_PROMOTION)
    affected = sum(result.operations[promotion_index].affected_jobs for result in results)
    with postgres_runtime_context.session_factory() as session:
        rows = {
            row.id: row
            for row in session.scalars(
                select(JobRow).where(
                    JobRow.id.in_(
                        [submitted.job_id for submitted in due_jobs] + [future_job.job_id]
                    )
                )
            )
        }
        execution_rows = list(session.scalars(select(ToolExecutionRow)))
        assert affected == len(due_jobs)
        assert all(
            rows[submitted.job_id].status == JobStatus.QUEUED.value for submitted in due_jobs
        )
        assert all(rows[submitted.job_id].attempt_count == 1 for submitted in due_jobs)
        assert rows[future_job.job_id].status == JobStatus.RETRY_PENDING.value
        assert rows[future_job.job_id].attempt_count == 1
        assert execution_rows == []


def test_postgres_maintenance_pass_recovers_and_reaps_without_fabricated_evidence(
    postgres_runtime_context: _PostgresRuntimeContext,
) -> None:
    ordinary = _submit(postgres_runtime_context, "b" * 64)
    ordinary_lease = JobLeasingService(
        postgres_runtime_context.session_factory,
        clock=lambda: BASE_TIME,
    ).lease_next_job("ordinary-expired-worker", lease_seconds=30)
    assert ordinary_lease is not None
    assert ordinary_lease.lease_token is not None
    JobExecutionService(
        postgres_runtime_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=1),
    ).start_job(
        ordinary.job_id,
        "ordinary-expired-worker",
        ordinary_lease.lease_token,
    )

    cancelling = _submit(postgres_runtime_context, "c" * 64)
    cancelling_lease = JobLeasingService(
        postgres_runtime_context.session_factory,
        clock=lambda: BASE_TIME,
    ).lease_next_job("cancelling-expired-worker", lease_seconds=30)
    assert cancelling_lease is not None
    JobCancellationService(
        postgres_runtime_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=2),
    ).request_cancellation(cancelling.job_id)

    healthy = _submit(postgres_runtime_context, "d" * 64)
    healthy_lease = JobLeasingService(
        postgres_runtime_context.session_factory,
        clock=lambda: BASE_TIME,
    ).lease_next_job("healthy-worker", lease_seconds=100)
    assert healthy_lease is not None
    assert healthy_lease.lease_token is not None
    JobExecutionService(
        postgres_runtime_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=1),
    ).start_job(
        healthy.job_id,
        "healthy-worker",
        healthy_lease.lease_token,
    )

    operation_time = BASE_TIME + timedelta(seconds=31)
    pass_result = MaintenanceCoordinator(
        _maintenance_tasks(
            postgres_runtime_context.session_factory,
            operation_time,
        ),
        threading.Event(),
    ).run_due_operations()

    with postgres_runtime_context.session_factory() as session:
        ordinary_row = session.get(JobRow, ordinary.job_id)
        cancelling_row = session.get(JobRow, cancelling.job_id)
        healthy_row = session.get(JobRow, healthy.job_id)
        ordinary_run = session.get(AnalysisRunRow, ordinary.run_id)
        cancelling_run = session.get(AnalysisRunRow, cancelling.run_id)
        healthy_run = session.get(AnalysisRunRow, healthy.run_id)
        executions = list(session.scalars(select(ToolExecutionRow)))
        assert ordinary_row is not None
        assert cancelling_row is not None
        assert healthy_row is not None
        assert ordinary_run is not None
        assert cancelling_run is not None
        assert healthy_run is not None
        assert [operation.affected_jobs for operation in pass_result.operations] == [0, 1, 1]
        assert ordinary_row.status == JobStatus.RETRY_PENDING.value
        assert ordinary_row.leased_by is None
        assert ordinary_row.lease_token is None
        assert cancelling_row.status == JobStatus.CANCELLED.value
        assert cancelling_row.leased_by is None
        assert cancelling_row.lease_token is None
        assert healthy_row.status == JobStatus.RUNNING.value
        assert healthy_row.leased_by == "healthy-worker"
        assert healthy_row.lease_token == healthy_lease.lease_token
        assert ordinary_run.status == RunStatus.QUEUED.value
        assert cancelling_run.status == RunStatus.CANCELLED.value
        assert healthy_run.status == RunStatus.RUNNING.value
        assert executions == []

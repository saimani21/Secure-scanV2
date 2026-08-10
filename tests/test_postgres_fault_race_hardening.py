from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import get_settings
from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    RunStatus,
    TargetType,
)
from securescan.domain.models import ScanReport, TargetProfile
from securescan.jobs import (
    FailedToolExecutionCommit,
    JobCancellationConflictError,
    JobCancellationRequestedError,
    JobCancellationService,
    JobExecutionService,
    JobFailureCommitRequest,
    JobFailureCommitService,
    JobHeartbeatService,
    JobLeaseExpiredError,
    JobLeaseOwnershipError,
    JobLeaseRecoveryService,
    JobLeaseTokenMismatchError,
    JobLeasingService,
    JobRepository,
    JobResultCommitRequest,
    JobResultCommitService,
    JobRetryPromotionService,
    JobStateConflictError,
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
    WorkerCommitError,
    WorkerDaemon,
    WorkerSuccessfulExecution,
)

pytestmark = pytest.mark.postgres

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"
BASE_TIME = datetime(2055, 2, 3, 4, 5, 6, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _PostgresRaceContext:
    engine: Engine
    session_factory: sessionmaker[Session]
    target_id: str


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL fault-race hardening test"
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
def postgres_race_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresRaceContext]:
    database_url = _validated_test_database_url()
    config = Config(str(ALEMBIC_INI_PATH))
    config.set_main_option("script_location", str(MIGRATIONS_PATH))
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()
    engine: Engine | None = None
    try:
        _reset_public_schema(database_url)
        command.upgrade(config, "head")
        engine, factory = create_session_factory(get_settings())
        with factory.begin() as session:
            project = ProjectRow(name="PostgreSQL fault race hardening")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="e" * 64,
                source_path="/tmp/postgres-fault-race",
            )
            session.add(target)
            session.flush()
            target_id = target.id
        yield _PostgresRaceContext(engine, factory, target_id)
    finally:
        if engine is not None:
            engine.dispose()
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def _submit(
    context: _PostgresRaceContext,
    key_character: str,
    *,
    max_attempts: int = 3,
) -> JobSubmissionResult:
    return JobSubmissionService(context.session_factory).submit(
        JobSubmissionRequest(
            target_id=context.target_id,
            adapter_id="fake-scanner",
            idempotency_key=key_character * 64,
            max_attempts=max_attempts,
        )
    )


def _prepare_running(
    context: _PostgresRaceContext,
    key_character: str,
    worker_id: str,
    *,
    max_attempts: int = 3,
    lease_seconds: int = 30,
) -> tuple[JobSubmissionResult, str]:
    submitted = _submit(context, key_character, max_attempts=max_attempts)
    leased = JobLeasingService(
        context.session_factory,
        clock=lambda: BASE_TIME,
    ).lease_next_job(worker_id, lease_seconds)
    assert leased is not None
    assert leased.id == submitted.job_id
    assert leased.lease_token is not None
    JobExecutionService(
        context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=1),
    ).start_job(
        submitted.job_id,
        worker_id,
        leased.lease_token,
    )
    return submitted, leased.lease_token


def _report(run_id: str, marker: str, generated_at: datetime) -> dict[str, Any]:
    return ScanReport(
        run_id=UUID(run_id),
        target=TargetProfile(
            target_type=TargetType.SOURCE_REPOSITORY,
            path=Path("/tmp/postgres-fault-race"),
            content_digest="e" * 64,
            metadata={"race_marker": marker},
        ),
        status=RunStatus.COMPLETED,
        executions=[],
        observations=[],
        generated_at=generated_at,
    ).model_dump(mode="json")


def _result_request(
    submitted: JobSubmissionResult,
    worker_id: str,
    lease_token: str,
    marker: str,
) -> JobResultCommitRequest:
    return JobResultCommitRequest(
        job_id=submitted.job_id,
        worker_id=worker_id,
        lease_token=lease_token,
        final_status=JobStatus.SUCCEEDED,
        report_json=_report(
            submitted.run_id,
            marker,
            BASE_TIME + timedelta(seconds=2),
        ),
        tool_execution=ToolExecutionCommit(
            tool_version="1",
            adapter_version="1",
            outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
            exit_code=0,
            duration_ms=10,
            warning_json=[],
        ),
    )


def _failure_request(
    submitted: JobSubmissionResult,
    worker_id: str,
    lease_token: str,
    *,
    retryable: bool,
) -> JobFailureCommitRequest:
    return JobFailureCommitRequest(
        job_id=submitted.job_id,
        worker_id=worker_id,
        lease_token=lease_token,
        tool_execution=FailedToolExecutionCommit(
            tool_version="1",
            adapter_version="1",
            outcome=ExecutionOutcome.INTERNAL_ERROR.value,
            exit_code=1,
            duration_ms=10,
            warning_json=[],
            error="Controlled scanner failure.",
            failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
            retryable=retryable,
        ),
    )


def _race_call(barrier: threading.Barrier, operation: Callable[[], object]) -> object:
    barrier.wait(timeout=5)
    try:
        return operation()
    except Exception as exc:
        return exc


def _persisted_state(
    context: _PostgresRaceContext,
    submitted: JobSubmissionResult,
) -> tuple[JobRow, AnalysisRunRow, list[ToolExecutionRow]]:
    with context.session_factory() as session:
        job = session.get(JobRow, submitted.job_id)
        run = session.get(AnalysisRunRow, submitted.run_id)
        assert job is not None
        assert run is not None
        executions = list(
            session.scalars(
                select(ToolExecutionRow)
                .where(ToolExecutionRow.job_id == submitted.job_id)
                .order_by(ToolExecutionRow.attempt_number.asc())
            )
        )
        session.expunge(job)
        session.expunge(run)
        for execution in executions:
            session.expunge(execution)
        return job, run, executions


class _SuccessfulAdapter:
    adapter_id = "fake-scanner"
    adapter_version = "race-test-1"
    tool_version = "scanner-test-1"

    def __init__(self, marker: str, generated_at: datetime) -> None:
        self.marker = marker
        self.generated_at = generated_at

    def execute(self, job) -> WorkerSuccessfulExecution:
        return WorkerSuccessfulExecution(
            final_status=JobStatus.SUCCEEDED,
            report_json=_report(job.run_id, self.marker, self.generated_at),
            tool_execution=ToolExecutionCommit(
                tool_version=self.tool_version,
                adapter_version=self.adapter_version,
                outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
                exit_code=0,
                duration_ms=10,
                warning_json=[],
            ),
        )


class _Resolver:
    def __init__(self, adapter: _SuccessfulAdapter) -> None:
        self.adapter = adapter

    def resolve(self, adapter_id: str) -> _SuccessfulAdapter:
        assert adapter_id == self.adapter.adapter_id
        return self.adapter


class _BarrierLeasingService:
    def __init__(
        self,
        service: JobLeasingService,
        barrier: threading.Barrier,
    ) -> None:
        self.service = service
        self.barrier = barrier

    def lease_next_job(self, worker_id: str, lease_seconds: int = 30):
        self.barrier.wait(timeout=5)
        return self.service.lease_next_job(worker_id, lease_seconds)


class _FailingResultCommitService:
    def __init__(self, service: JobResultCommitService) -> None:
        self.service = service
        self.calls = 0

    def commit_result(self, request: JobResultCommitRequest):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("postgresql://admin:secret@database SQL")
        return self.service.commit_result(request)


def _worker_cycle(
    context: _PostgresRaceContext,
    worker_id: str,
    adapter: _SuccessfulAdapter,
    *,
    lease_time: datetime,
    start_time: datetime,
    commit_time: datetime,
    leasing_service: object | None = None,
    result_commit_service: object | None = None,
) -> SingleJobWorkerCycle:
    cancellation = JobCancellationService(
        context.session_factory,
        clock=lambda: commit_time,
    )
    return SingleJobWorkerCycle(
        leasing_service
        or JobLeasingService(
            context.session_factory,
            clock=lambda: lease_time,
        ),
        JobExecutionService(
            context.session_factory,
            clock=lambda: start_time,
        ),
        result_commit_service
        or JobResultCommitService(
            context.session_factory,
            clock=lambda: commit_time,
        ),
        JobFailureCommitService(
            context.session_factory,
            clock=lambda: commit_time,
            retry_delay_seconds=lambda _attempt: 5,
        ),
        _Resolver(adapter),
        JobRepository(context.session_factory),
        cancellation,
        JobHeartbeatService(
            context.session_factory,
            clock=lambda: commit_time,
        ),
        worker_id,
    )


def _maintenance_tasks(
    factory: sessionmaker[Session],
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
                    factory,
                    clock=lambda: operation_time,
                )
            ),
        ),
        MaintenanceTask(
            configurations[MaintenanceOperationName.LEASE_RECOVERY],
            LeaseRecoveryOperation(
                JobLeaseRecoveryService(
                    factory,
                    clock=lambda: operation_time,
                    retry_delay_seconds=lambda _attempt: 5,
                )
            ),
        ),
        MaintenanceTask(
            configurations[MaintenanceOperationName.CANCELLATION_REAPER],
            CancellationReaperOperation(
                JobCancellationService(
                    factory,
                    clock=lambda: operation_time,
                )
            ),
        ),
    ]


def test_postgres_cancellation_racing_success_commit_has_one_terminal_winner(
    postgres_race_context: _PostgresRaceContext,
) -> None:
    worker_id = "success-race-worker"
    submitted, lease_token = _prepare_running(
        postgres_race_context,
        "1",
        worker_id,
        lease_seconds=60,
    )
    result_service = JobResultCommitService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=2),
    )
    cancellation = JobCancellationService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=2),
    )
    barrier = threading.Barrier(3)
    with ThreadPoolExecutor(max_workers=2) as executor:
        commit_future = executor.submit(
            _race_call,
            barrier,
            lambda: result_service.commit_result(
                _result_request(submitted, worker_id, lease_token, "success-race")
            ),
        )
        cancel_future = executor.submit(
            _race_call,
            barrier,
            lambda: cancellation.request_cancellation(submitted.job_id),
        )
        barrier.wait(timeout=5)
        commit_outcome = commit_future.result(timeout=5)
        cancel_outcome = cancel_future.result(timeout=5)

    if isinstance(commit_outcome, JobCancellationRequestedError):
        assert not isinstance(cancel_outcome, Exception)
        cancellation.acknowledge_cancellation(
            submitted.job_id,
            worker_id,
            lease_token,
        )
    else:
        assert not isinstance(commit_outcome, Exception)
        assert isinstance(cancel_outcome, JobCancellationConflictError)

    job, run, executions = _persisted_state(postgres_race_context, submitted)
    if job.status == JobStatus.SUCCEEDED.value:
        assert len(executions) == 1
        assert run.status == RunStatus.COMPLETED.value
    else:
        assert job.status == JobStatus.CANCELLED.value
        assert run.status == RunStatus.CANCELLED.value
        assert executions == []


def test_postgres_cancellation_racing_failure_commit_has_one_terminal_winner(
    postgres_race_context: _PostgresRaceContext,
) -> None:
    worker_id = "failure-race-worker"
    submitted, lease_token = _prepare_running(
        postgres_race_context,
        "2",
        worker_id,
        lease_seconds=60,
    )
    failure_service = JobFailureCommitService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=2),
    )
    cancellation = JobCancellationService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=2),
    )
    barrier = threading.Barrier(3)
    with ThreadPoolExecutor(max_workers=2) as executor:
        failure_future = executor.submit(
            _race_call,
            barrier,
            lambda: failure_service.commit_failure(
                _failure_request(
                    submitted,
                    worker_id,
                    lease_token,
                    retryable=False,
                )
            ),
        )
        cancel_future = executor.submit(
            _race_call,
            barrier,
            lambda: cancellation.request_cancellation(submitted.job_id),
        )
        barrier.wait(timeout=5)
        failure_outcome = failure_future.result(timeout=5)
        cancel_outcome = cancel_future.result(timeout=5)

    if isinstance(failure_outcome, JobCancellationRequestedError):
        assert not isinstance(cancel_outcome, Exception)
        cancellation.acknowledge_cancellation(
            submitted.job_id,
            worker_id,
            lease_token,
        )
    else:
        assert not isinstance(failure_outcome, Exception)
        assert isinstance(cancel_outcome, JobCancellationConflictError)

    job, run, executions = _persisted_state(postgres_race_context, submitted)
    if job.status == JobStatus.FAILED.value:
        assert len(executions) == 1
        assert executions[0].retryable is False
        assert run.status == RunStatus.FAILED.value
    else:
        assert job.status == JobStatus.CANCELLED.value
        assert run.status == RunStatus.CANCELLED.value
        assert executions == []


def test_postgres_heartbeat_racing_expired_lease_recovery_is_coherent(
    postgres_race_context: _PostgresRaceContext,
) -> None:
    worker_id = "heartbeat-race-worker"
    submitted, lease_token = _prepare_running(
        postgres_race_context,
        "3",
        worker_id,
    )
    heartbeat = JobHeartbeatService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=29),
    )
    recovery = JobLeaseRecoveryService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=31),
        retry_delay_seconds=lambda _attempt: 5,
    )
    barrier = threading.Barrier(3)
    with ThreadPoolExecutor(max_workers=2) as executor:
        heartbeat_future = executor.submit(
            _race_call,
            barrier,
            lambda: heartbeat.renew_lease(
                submitted.job_id,
                worker_id,
                lease_token,
                30,
            ),
        )
        recovery_future = executor.submit(
            _race_call,
            barrier,
            lambda: recovery.recover_expired_jobs(limit=1),
        )
        barrier.wait(timeout=5)
        heartbeat_outcome = heartbeat_future.result(timeout=5)
        recovery_outcome = recovery_future.result(timeout=5)

    job, run, executions = _persisted_state(postgres_race_context, submitted)
    if job.status == JobStatus.RUNNING.value:
        assert not isinstance(heartbeat_outcome, Exception)
        assert recovery_outcome == []
        assert job.lease_expires_at == BASE_TIME + timedelta(seconds=59)
        assert run.status == RunStatus.RUNNING.value
    else:
        assert job.status == JobStatus.RETRY_PENDING.value
        assert isinstance(
            heartbeat_outcome,
            (
                JobStateConflictError,
                JobLeaseOwnershipError,
                JobLeaseTokenMismatchError,
                JobLeaseExpiredError,
            ),
        )
        assert len(recovery_outcome) == 1
        assert job.leased_by is None
        assert job.lease_token is None
        assert job.lease_expires_at is None
        assert run.status == RunStatus.QUEUED.value
    assert job.attempt_count == 1
    assert executions == []


def test_postgres_success_commit_racing_recovery_cannot_be_overwritten(
    postgres_race_context: _PostgresRaceContext,
) -> None:
    worker_id = "success-recovery-worker"
    submitted, lease_token = _prepare_running(
        postgres_race_context,
        "4",
        worker_id,
    )
    commit = JobResultCommitService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=29),
    )
    recovery = JobLeaseRecoveryService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=31),
        retry_delay_seconds=lambda _attempt: 5,
    )
    barrier = threading.Barrier(3)
    with ThreadPoolExecutor(max_workers=2) as executor:
        commit_future = executor.submit(
            _race_call,
            barrier,
            lambda: commit.commit_result(
                _result_request(submitted, worker_id, lease_token, "recovery-race")
            ),
        )
        recovery_future = executor.submit(
            _race_call,
            barrier,
            lambda: recovery.recover_expired_jobs(limit=1),
        )
        barrier.wait(timeout=5)
        commit_outcome = commit_future.result(timeout=5)
        recovery_outcome = recovery_future.result(timeout=5)

    job, run, executions = _persisted_state(postgres_race_context, submitted)
    if job.status == JobStatus.SUCCEEDED.value:
        assert not isinstance(commit_outcome, Exception)
        assert recovery_outcome == []
        assert len(executions) == 1
        assert run.status == RunStatus.COMPLETED.value
    else:
        assert job.status == JobStatus.RETRY_PENDING.value
        assert isinstance(commit_outcome, JobStateConflictError)
        assert len(recovery_outcome) == 1
        assert executions == []
        assert run.status == RunStatus.QUEUED.value


def test_postgres_failure_commit_racing_recovery_cannot_duplicate_attempt_evidence(
    postgres_race_context: _PostgresRaceContext,
) -> None:
    worker_id = "failure-recovery-worker"
    submitted, lease_token = _prepare_running(
        postgres_race_context,
        "5",
        worker_id,
    )
    failure = JobFailureCommitService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=29),
        retry_delay_seconds=lambda _attempt: 5,
    )
    recovery = JobLeaseRecoveryService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=31),
        retry_delay_seconds=lambda _attempt: 5,
    )
    barrier = threading.Barrier(3)
    with ThreadPoolExecutor(max_workers=2) as executor:
        failure_future = executor.submit(
            _race_call,
            barrier,
            lambda: failure.commit_failure(
                _failure_request(
                    submitted,
                    worker_id,
                    lease_token,
                    retryable=True,
                )
            ),
        )
        recovery_future = executor.submit(
            _race_call,
            barrier,
            lambda: recovery.recover_expired_jobs(limit=1),
        )
        barrier.wait(timeout=5)
        failure_outcome = failure_future.result(timeout=5)
        recovery_outcome = recovery_future.result(timeout=5)

    job, run, executions = _persisted_state(postgres_race_context, submitted)
    assert job.status == JobStatus.RETRY_PENDING.value
    assert job.attempt_count == 1
    assert run.status == RunStatus.QUEUED.value
    assert len(executions) <= 1
    assert len({(row.job_id, row.attempt_number) for row in executions}) == len(executions)
    if executions:
        assert not isinstance(failure_outcome, Exception)
        assert recovery_outcome == []
    else:
        assert isinstance(failure_outcome, JobStateConflictError)
        assert len(recovery_outcome) == 1


def test_postgres_two_worker_daemons_process_single_job_once(
    postgres_race_context: _PostgresRaceContext,
) -> None:
    submitted = _submit(postgres_race_context, "6")
    barrier = threading.Barrier(2)
    cycles = [
        _worker_cycle(
            postgres_race_context,
            worker_id,
            _SuccessfulAdapter(worker_id, BASE_TIME + timedelta(seconds=2)),
            lease_time=BASE_TIME,
            start_time=BASE_TIME + timedelta(seconds=1),
            commit_time=BASE_TIME + timedelta(seconds=2),
            leasing_service=_BarrierLeasingService(
                JobLeasingService(
                    postgres_race_context.session_factory,
                    clock=lambda: BASE_TIME,
                ),
                barrier,
            ),
        )
        for worker_id in ("daemon-race-a", "daemon-race-b")
    ]
    daemons = [WorkerDaemon(cycle, threading.Event(), max_cycles=1) for cycle in cycles]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(daemon.run) for daemon in daemons]
        results = [future.result(timeout=5) for future in futures]

    job, run, executions = _persisted_state(postgres_race_context, submitted)
    assert sorted(result.processed_cycles for result in results) == [0, 1]
    assert sorted(result.idle_cycles for result in results) == [0, 1]
    assert sum(result.errors for result in results) == 0
    assert job.status == JobStatus.SUCCEEDED.value
    assert job.attempt_count == 1
    assert len(executions) == 1
    assert executions[0].attempt_number == 1
    assert run.status == RunStatus.COMPLETED.value
    assert run.report_json is not None
    assert run.report_json["target"]["metadata"]["race_marker"] in {
        "daemon-race-a",
        "daemon-race-b",
    }


def test_postgres_transient_commit_failure_recovers_retries_and_succeeds(
    postgres_race_context: _PostgresRaceContext,
) -> None:
    submitted = _submit(postgres_race_context, "7", max_attempts=2)
    real_commit = JobResultCommitService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=2),
    )
    failing_commit = _FailingResultCommitService(real_commit)
    first_cycle = _worker_cycle(
        postgres_race_context,
        "first-attempt-worker",
        _SuccessfulAdapter("first-attempt", BASE_TIME + timedelta(seconds=2)),
        lease_time=BASE_TIME,
        start_time=BASE_TIME + timedelta(seconds=1),
        commit_time=BASE_TIME + timedelta(seconds=2),
        result_commit_service=failing_commit,
    )

    with pytest.raises(WorkerCommitError) as error:
        first_cycle.run_one_job()

    assert error.value.__cause__ is not None
    assert "postgresql://" not in str(error.value)
    assert failing_commit.calls == 1
    job, _, executions = _persisted_state(postgres_race_context, submitted)
    assert job.status == JobStatus.RUNNING.value
    assert job.attempt_count == 1
    assert executions == []

    recovered = JobLeaseRecoveryService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=31),
        retry_delay_seconds=lambda _attempt: 5,
    ).recover_expired_jobs(limit=1)
    assert len(recovered) == 1
    promoted = JobRetryPromotionService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=36),
    ).promote_due_retries(limit=1)
    assert len(promoted) == 1

    result = _worker_cycle(
        postgres_race_context,
        "second-attempt-worker",
        _SuccessfulAdapter("second-attempt", BASE_TIME + timedelta(seconds=38)),
        lease_time=BASE_TIME + timedelta(seconds=36),
        start_time=BASE_TIME + timedelta(seconds=37),
        commit_time=BASE_TIME + timedelta(seconds=38),
    ).run_one_job()

    job, run, executions = _persisted_state(postgres_race_context, submitted)
    assert result.attempt_number == 2
    assert job.status == JobStatus.SUCCEEDED.value
    assert job.attempt_count == 2
    assert [(row.attempt_number, row.outcome) for row in executions] == [
        (2, ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value)
    ]
    assert run.status == RunStatus.COMPLETED.value


def test_postgres_concurrent_maintenance_passes_affect_each_job_once(
    postgres_race_context: _PostgresRaceContext,
) -> None:
    due_retries = [_submit(postgres_race_context, key) for key in ("8", "9")]
    future_retry = _submit(postgres_race_context, "a")
    with postgres_race_context.session_factory.begin() as session:
        for submitted in due_retries:
            row = session.get(JobRow, submitted.job_id)
            assert row is not None
            row.status = JobStatus.RETRY_PENDING.value
            row.attempt_count = 1
            row.available_at = BASE_TIME
        future_row = session.get(JobRow, future_retry.job_id)
        assert future_row is not None
        future_row.status = JobStatus.RETRY_PENDING.value
        future_row.attempt_count = 1
        future_row.available_at = BASE_TIME + timedelta(minutes=5)

    ordinary, _ = _prepare_running(
        postgres_race_context,
        "b",
        "ordinary-expired-worker",
    )
    cancelling, _ = _prepare_running(
        postgres_race_context,
        "c",
        "cancelling-expired-worker",
    )
    JobCancellationService(
        postgres_race_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=2),
    ).request_cancellation(cancelling.job_id)
    healthy, _ = _prepare_running(
        postgres_race_context,
        "d",
        "healthy-worker",
        lease_seconds=100,
    )

    operation_time = BASE_TIME + timedelta(seconds=31)
    factory_a = sessionmaker(
        bind=postgres_race_context.engine,
        expire_on_commit=False,
    )
    factory_b = sessionmaker(
        bind=postgres_race_context.engine,
        expire_on_commit=False,
    )
    coordinators = [
        MaintenanceCoordinator(
            _maintenance_tasks(factory, operation_time),
            threading.Event(),
        )
        for factory in (factory_a, factory_b)
    ]
    barrier = threading.Barrier(3)

    def run_pass(coordinator: MaintenanceCoordinator):
        barrier.wait(timeout=5)
        return coordinator.run_due_operations()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run_pass, coordinator) for coordinator in coordinators]
        barrier.wait(timeout=5)
        results = [future.result(timeout=5) for future in futures]

    affected = sum(result.total_affected_jobs for result in results)
    all_job_ids = [
        *(submitted.job_id for submitted in due_retries),
        future_retry.job_id,
        ordinary.job_id,
        cancelling.job_id,
        healthy.job_id,
    ]
    with postgres_race_context.session_factory() as session:
        rows = {
            row.id: row for row in session.scalars(select(JobRow).where(JobRow.id.in_(all_job_ids)))
        }
        execution_count = session.scalar(select(func.count()).select_from(ToolExecutionRow))

    assert affected == len(due_retries) + 2
    assert all(rows[submitted.job_id].status == JobStatus.QUEUED.value for submitted in due_retries)
    assert rows[future_retry.job_id].status == JobStatus.RETRY_PENDING.value
    assert rows[ordinary.job_id].status == JobStatus.RETRY_PENDING.value
    assert rows[cancelling.job_id].status == JobStatus.CANCELLED.value
    assert rows[healthy.job_id].status == JobStatus.RUNNING.value
    assert rows[future_retry.job_id].available_at == BASE_TIME + timedelta(minutes=5)
    assert rows[healthy.job_id].leased_by == "healthy-worker"
    assert rows[healthy.job_id].lease_token is not None
    assert all(rows[job_id].attempt_count == 1 for job_id in all_job_ids)
    assert execution_count == 0

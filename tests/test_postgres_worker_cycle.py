from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock
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
    JobFailureCategory,
    JobStatus,
    RunStatus,
    TargetType,
)
from securescan.domain.models import ScanReport, TargetProfile
from securescan.jobs import (
    FailedToolExecutionCommit,
    JobCancellationService,
    JobExecutionService,
    JobFailureCommitService,
    JobHeartbeatService,
    JobLeaseRecoveryService,
    JobLeasingService,
    JobRecord,
    JobRepository,
    JobResultCommitService,
    JobRetryPromotionService,
    JobSubmissionRequest,
    JobSubmissionResult,
    JobSubmissionService,
    ToolExecutionCommit,
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
    WorkerCycleDisposition,
    WorkerExecutionHandle,
    WorkerFailedExecution,
    WorkerSuccessfulExecution,
)

pytestmark = pytest.mark.postgres

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"
BASE_TIME = datetime(2045, 2, 3, 4, 5, 6, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _PostgresWorkerContext:
    session_factory: sessionmaker[Session]
    target_id: str


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL worker-cycle integration test"
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
def postgres_worker_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresWorkerContext]:
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
            project = ProjectRow(name="PostgreSQL worker cycle test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="c" * 64,
                source_path="/tmp/postgres-worker-cycle",
            )
            session.add(target)
            session.flush()
            target_id = target.id
        yield _PostgresWorkerContext(session_factory, target_id)
    finally:
        if engine is not None:
            engine.dispose()
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def _submit(
    context: _PostgresWorkerContext,
    idempotency_key: str,
    *,
    max_attempts: int = 3,
) -> JobSubmissionResult:
    return JobSubmissionService(context.session_factory).submit(
        JobSubmissionRequest(
            target_id=context.target_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
            payload_json={"test": idempotency_key},
            max_attempts=max_attempts,
        )
    )


def _report_json(run_id: str, marker: str, generated_at: datetime) -> dict[str, Any]:
    return ScanReport(
        run_id=UUID(run_id),
        target=TargetProfile(
            target_type=TargetType.SOURCE_REPOSITORY,
            path=Path("/tmp/postgres-worker-cycle"),
            content_digest="c" * 64,
            metadata={"worker_marker": marker},
        ),
        status=RunStatus.COMPLETED,
        executions=[],
        observations=[],
        generated_at=generated_at,
    ).model_dump(mode="json")


class _SuccessfulAdapter:
    adapter_id = "fake-scanner"
    adapter_version = "worker-test-1"
    tool_version = "scanner-test-1"

    def __init__(self, marker: str, clock: datetime) -> None:
        self.marker = marker
        self.clock = clock
        self.jobs: list[JobRecord] = []

    def execute(self, job: JobRecord) -> WorkerSuccessfulExecution:
        self.jobs.append(job)
        return WorkerSuccessfulExecution(
            final_status=JobStatus.SUCCEEDED,
            report_json=_report_json(job.run_id, self.marker, self.clock),
            tool_execution=ToolExecutionCommit(
                tool_version=self.tool_version,
                adapter_version=self.adapter_version,
                outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
                exit_code=0,
                duration_ms=20,
                warning_json=[],
            ),
        )


class _FailedAdapter:
    adapter_id = "fake-scanner"
    adapter_version = "worker-test-1"
    tool_version = "scanner-test-1"

    def __init__(self) -> None:
        self.jobs: list[JobRecord] = []

    def execute(self, job: JobRecord) -> WorkerFailedExecution:
        self.jobs.append(job)
        return WorkerFailedExecution(
            tool_execution=FailedToolExecutionCommit(
                tool_version=self.tool_version,
                adapter_version=self.adapter_version,
                outcome=ExecutionOutcome.INTERNAL_ERROR.value,
                exit_code=1,
                duration_ms=20,
                warning_json=[{"code": "temporary"}],
                error="Temporary scanner infrastructure failure.",
                failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
                retryable=True,
            )
        )


class _Resolver:
    def __init__(
        self,
        adapter: _SuccessfulAdapter | _FailedAdapter | _ManagedAdapter,
    ) -> None:
        self.adapter = adapter
        self.adapter_ids: list[str] = []

    def resolve(
        self,
        adapter_id: str,
    ) -> _SuccessfulAdapter | _FailedAdapter | _ManagedAdapter:
        self.adapter_ids.append(adapter_id)
        return self.adapter


class _CancellingAdapter(_SuccessfulAdapter):
    def __init__(
        self,
        marker: str,
        clock: datetime,
        cancellation_service: JobCancellationService,
    ) -> None:
        super().__init__(marker, clock)
        self.cancellation_service = cancellation_service

    def execute(self, job: JobRecord) -> WorkerSuccessfulExecution:
        outcome = super().execute(job)
        self.cancellation_service.request_cancellation(job.id)
        return outcome


class _BlockingAdapter(_SuccessfulAdapter):
    def __init__(
        self,
        marker: str,
        clock: datetime,
        entered: Event,
        release: Event,
    ) -> None:
        super().__init__(marker, clock)
        self.entered = entered
        self.release = release

    def execute(self, job: JobRecord) -> WorkerSuccessfulExecution:
        self.jobs.append(job)
        self.entered.set()
        if not self.release.wait(timeout=5):
            raise RuntimeError("Blocking test adapter was not released")
        return WorkerSuccessfulExecution(
            final_status=JobStatus.SUCCEEDED,
            report_json=_report_json(job.run_id, self.marker, self.clock),
            tool_execution=ToolExecutionCommit(
                tool_version=self.tool_version,
                adapter_version=self.adapter_version,
                outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
                exit_code=0,
                duration_ms=20,
                warning_json=[],
            ),
        )


class _CancellingLeasingService:
    def __init__(
        self,
        leasing_service: JobLeasingService,
        cancellation_service: JobCancellationService,
    ) -> None:
        self.leasing_service = leasing_service
        self.cancellation_service = cancellation_service

    def lease_next_job(
        self,
        worker_id: str,
        lease_seconds: int = 30,
    ) -> JobRecord | None:
        leased = self.leasing_service.lease_next_job(worker_id, lease_seconds)
        if leased is not None:
            self.cancellation_service.request_cancellation(leased.id)
        return leased


class _MutableTime:
    def __init__(
        self,
        wall_start: datetime,
        gate: Event | None = None,
        gate_at: float = 0.5,
    ) -> None:
        self.wall_start = wall_start
        self.gate = gate
        self.gate_at = gate_at
        self.value = 0.0
        self.lock = Lock()

    def monotonic(self) -> float:
        with self.lock:
            return self.value

    def wall_clock(self) -> datetime:
        return self.wall_start + timedelta(seconds=self.monotonic())

    def sleep(self, seconds: float) -> None:
        with self.lock:
            self.value += seconds
            should_wait = self.gate is not None and self.value >= self.gate_at
        if should_wait:
            assert self.gate is not None
            if not self.gate.wait(timeout=5):
                raise RuntimeError("PostgreSQL worker test gate was not released")


class _ManagedHandle:
    def __init__(
        self,
        outcome: WorkerSuccessfulExecution,
        completion: Event,
        *,
        stop_on_terminate: bool = True,
    ) -> None:
        self.outcome = outcome
        self.completion = completion
        self.stop_on_terminate = stop_on_terminate
        self.terminated = False
        self.killed = False
        self.closed = False

    def poll(self):
        return self.outcome if self.completion.is_set() else None

    def terminate(self) -> None:
        self.terminated = True
        if self.stop_on_terminate:
            self.completion.set()

    def kill(self) -> None:
        self.killed = True
        self.completion.set()

    def close(self) -> None:
        self.closed = True


class _ManagedAdapter:
    adapter_id = "fake-scanner"
    adapter_version = "worker-test-1"
    tool_version = "scanner-test-1"

    def __init__(
        self,
        marker: str,
        generated_at: datetime,
        completion: Event,
        entered: Event,
        *,
        stop_on_terminate: bool = True,
    ) -> None:
        self.marker = marker
        self.generated_at = generated_at
        self.entered = entered
        self.jobs: list[JobRecord] = []
        self.handle = _ManagedHandle(
            WorkerSuccessfulExecution(
                final_status=JobStatus.SUCCEEDED,
                report_json={},
                tool_execution=ToolExecutionCommit(
                    tool_version=self.tool_version,
                    adapter_version=self.adapter_version,
                    outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
                    exit_code=0,
                    duration_ms=20,
                    warning_json=[],
                ),
            ),
            completion,
            stop_on_terminate=stop_on_terminate,
        )

    def start(self, job: JobRecord) -> WorkerExecutionHandle:
        self.jobs.append(job)
        self.handle.outcome = WorkerSuccessfulExecution(
            final_status=JobStatus.SUCCEEDED,
            report_json=_report_json(job.run_id, self.marker, self.generated_at),
            tool_execution=self.handle.outcome.tool_execution,
        )
        self.entered.set()
        return self.handle


class _RecordingHeartbeat:
    def __init__(
        self,
        service: JobHeartbeatService,
        renewed: Event,
    ) -> None:
        self.service = service
        self.renewed = renewed
        self.records: list[JobRecord] = []

    def renew_lease(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        lease_seconds: int = 30,
    ) -> JobRecord:
        record = self.service.renew_lease(
            job_id,
            worker_id,
            lease_token,
            lease_seconds,
        )
        self.records.append(record)
        self.renewed.set()
        return record


class _RecordingCancellationAcknowledger:
    def __init__(
        self,
        service: JobCancellationService,
        handle: _ManagedHandle,
    ) -> None:
        self.service = service
        self.handle = handle
        self.stopped_before_acknowledgement: list[bool] = []

    def acknowledge_cancellation(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> JobRecord:
        self.stopped_before_acknowledgement.append(self.handle.completion.is_set())
        return self.service.acknowledge_cancellation(
            job_id,
            worker_id,
            lease_token,
        )


def _cycle(
    context: _PostgresWorkerContext,
    adapter: _SuccessfulAdapter | _FailedAdapter | _ManagedAdapter,
    worker_id: str,
    *,
    lease_time: datetime = BASE_TIME,
    start_time: datetime = BASE_TIME + timedelta(seconds=1),
    commit_time: datetime = BASE_TIME + timedelta(seconds=2),
    cancellation_service: JobCancellationService | None = None,
    cancellation_acknowledger: object | None = None,
    leasing_service: JobLeasingService | _CancellingLeasingService | None = None,
    heartbeat_renewer: object | None = None,
    monotonic_clock: Any = None,
    sleeper: Any = None,
    heartbeat_interval_seconds: float = 10,
    execution_poll_interval_seconds: float = 0.25,
    termination_grace_seconds: float = 5,
    force_kill_grace_seconds: float = 2,
) -> SingleJobWorkerCycle:
    cancellation = cancellation_service or JobCancellationService(
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
        JobResultCommitService(
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
        cancellation_acknowledger or cancellation,
        heartbeat_renewer
        or JobHeartbeatService(
            context.session_factory,
            clock=lambda: commit_time,
        ),
        worker_id,
        lease_seconds=30,
        heartbeat_interval_seconds=heartbeat_interval_seconds,
        execution_poll_interval_seconds=execution_poll_interval_seconds,
        termination_grace_seconds=termination_grace_seconds,
        force_kill_grace_seconds=force_kill_grace_seconds,
        **(
            {
                "monotonic_clock": monotonic_clock,
                "sleeper": sleeper,
            }
            if monotonic_clock is not None and sleeper is not None
            else {}
        ),
    )


def _persisted_rows(
    context: _PostgresWorkerContext,
    job_id: str,
) -> tuple[JobRow, AnalysisRunRow, list[ToolExecutionRow]]:
    with context.session_factory() as session:
        job = session.get(JobRow, job_id)
        assert job is not None
        run = session.get(AnalysisRunRow, job.run_id)
        assert run is not None
        executions = list(
            session.scalars(select(ToolExecutionRow).where(ToolExecutionRow.job_id == job_id))
        )
        session.expunge(job)
        session.expunge(run)
        for execution in executions:
            session.expunge(execution)
        return job, run, executions


def test_postgres_worker_cycle_commits_success_end_to_end(
    postgres_worker_context: _PostgresWorkerContext,
) -> None:
    submitted = _submit(postgres_worker_context, "1" * 64)
    adapter = _SuccessfulAdapter("single-success", BASE_TIME + timedelta(seconds=2))

    result = _cycle(
        postgres_worker_context,
        adapter,
        "worker-success",
    ).run_one_job()

    job, run, executions = _persisted_rows(postgres_worker_context, submitted.job_id)
    assert result.disposition is WorkerCycleDisposition.SUCCEEDED
    assert result.job_id == submitted.job_id
    assert result.run_id == submitted.run_id
    assert result.attempt_number == job.attempt_count == 1
    assert result.tool_execution_id == executions[0].id
    assert not hasattr(result, "lease_token")
    assert job.status == JobStatus.SUCCEEDED.value
    assert job.leased_by is None
    assert job.lease_token is None
    assert job.lease_expires_at is None
    assert run.status == RunStatus.COMPLETED.value
    assert run.report_json == _report_json(
        submitted.run_id,
        "single-success",
        BASE_TIME + timedelta(seconds=2),
    )
    assert len(executions) == 1


def test_postgres_worker_cycle_schedules_retryable_failure(
    postgres_worker_context: _PostgresWorkerContext,
) -> None:
    submitted = _submit(postgres_worker_context, "2" * 64)
    adapter = _FailedAdapter()

    result = _cycle(
        postgres_worker_context,
        adapter,
        "worker-retry",
    ).run_one_job()

    job, run, executions = _persisted_rows(postgres_worker_context, submitted.job_id)
    assert result.disposition is WorkerCycleDisposition.RETRY_PENDING
    assert result.attempt_number == 1
    assert result.tool_execution_id == executions[0].id
    assert job.status == JobStatus.RETRY_PENDING.value
    assert job.leased_by is None
    assert job.lease_token is None
    assert job.lease_expires_at is None
    assert run.status == RunStatus.QUEUED.value
    assert len(executions) == 1
    assert executions[0].failure_category == (JobFailureCategory.RETRYABLE_INFRASTRUCTURE.value)
    assert executions[0].retryable is True


def test_postgres_cancellation_before_execution_prevents_adapter_call(
    postgres_worker_context: _PostgresWorkerContext,
) -> None:
    submitted = _submit(postgres_worker_context, "3" * 64)
    cancellation = JobCancellationService(
        postgres_worker_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=1),
    )
    leasing = _CancellingLeasingService(
        JobLeasingService(
            postgres_worker_context.session_factory,
            clock=lambda: BASE_TIME,
        ),
        cancellation,
    )
    adapter = _SuccessfulAdapter("must-not-run", BASE_TIME)

    result = _cycle(
        postgres_worker_context,
        adapter,
        "worker-cancel-before",
        cancellation_service=cancellation,
        leasing_service=leasing,
    ).run_one_job()

    job, run, executions = _persisted_rows(postgres_worker_context, submitted.job_id)
    assert result.disposition is WorkerCycleDisposition.CANCELLED
    assert result.tool_execution_id is None
    assert adapter.jobs == []
    assert job.status == JobStatus.CANCELLED.value
    assert run.status == RunStatus.CANCELLED.value
    assert executions == []


def test_postgres_cancellation_after_execution_discards_outcome(
    postgres_worker_context: _PostgresWorkerContext,
) -> None:
    submitted = _submit(postgres_worker_context, "4" * 64)
    cancellation = JobCancellationService(
        postgres_worker_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=2),
    )
    adapter = _CancellingAdapter(
        "discarded",
        BASE_TIME + timedelta(seconds=2),
        cancellation,
    )

    result = _cycle(
        postgres_worker_context,
        adapter,
        "worker-cancel-after",
        commit_time=BASE_TIME + timedelta(seconds=3),
        cancellation_service=cancellation,
    ).run_one_job()

    job, run, executions = _persisted_rows(postgres_worker_context, submitted.job_id)
    assert result.disposition is WorkerCycleDisposition.CANCELLED
    assert result.tool_execution_id is None
    assert len(adapter.jobs) == 1
    assert job.status == JobStatus.CANCELLED.value
    assert run.status == RunStatus.CANCELLED.value
    assert run.report_json is None
    assert executions == []


def test_postgres_competing_worker_cycles_process_job_exactly_once(
    postgres_worker_context: _PostgresWorkerContext,
) -> None:
    submitted = _submit(postgres_worker_context, "5" * 64)
    adapter_a = _SuccessfulAdapter("worker-a", BASE_TIME + timedelta(seconds=2))
    adapter_b = _SuccessfulAdapter("worker-b", BASE_TIME + timedelta(seconds=2))
    cycle_a = _cycle(postgres_worker_context, adapter_a, "worker-a")
    cycle_b = _cycle(postgres_worker_context, adapter_b, "worker-b")

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_a = executor.submit(cycle_a.run_one_job)
        future_b = executor.submit(cycle_b.run_one_job)
        results = [future_a.result(timeout=5), future_b.result(timeout=5)]

    job, run, executions = _persisted_rows(postgres_worker_context, submitted.job_id)
    assert sorted(result.disposition for result in results) == [
        WorkerCycleDisposition.IDLE,
        WorkerCycleDisposition.SUCCEEDED,
    ]
    assert sum(len(adapter.jobs) for adapter in (adapter_a, adapter_b)) == 1
    assert job.status == JobStatus.SUCCEEDED.value
    assert job.attempt_count == 1
    assert run.status == RunStatus.COMPLETED.value
    assert len(executions) == 1
    assert sum(result.tool_execution_id is not None for result in results) == 1


def test_postgres_recovery_and_new_lease_fence_old_worker_cycle(
    postgres_worker_context: _PostgresWorkerContext,
) -> None:
    submitted = _submit(postgres_worker_context, "6" * 64, max_attempts=3)
    token_a = UUID("00000000-0000-4000-8000-0000000000a1")
    token_b = UUID("00000000-0000-4000-8000-0000000000b2")
    entered = Event()
    release = Event()
    adapter_a = _BlockingAdapter(
        "stale-worker-a",
        BASE_TIME + timedelta(seconds=1),
        entered,
        release,
    )
    cycle_a = _cycle(
        postgres_worker_context,
        adapter_a,
        "stale-worker-a",
        leasing_service=JobLeasingService(
            postgres_worker_context.session_factory,
            clock=lambda: BASE_TIME,
            token_factory=lambda: token_a,
        ),
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future_a = executor.submit(cycle_a.run_one_job)
        try:
            assert entered.wait(timeout=5)
            recovered = JobLeaseRecoveryService(
                postgres_worker_context.session_factory,
                clock=lambda: BASE_TIME + timedelta(seconds=31),
                retry_delay_seconds=lambda _attempt: 1,
            ).recover_expired_jobs(limit=1)
            assert len(recovered) == 1
            assert recovered[0].job.status is JobStatus.RETRY_PENDING
            promoted = JobRetryPromotionService(
                postgres_worker_context.session_factory,
                clock=lambda: BASE_TIME + timedelta(seconds=32),
            ).promote_due_retries(limit=1)
            assert len(promoted) == 1

            adapter_b = _SuccessfulAdapter(
                "current-worker-b",
                BASE_TIME + timedelta(seconds=35),
            )
            result_b = _cycle(
                postgres_worker_context,
                adapter_b,
                "current-worker-b",
                lease_time=BASE_TIME + timedelta(seconds=33),
                start_time=BASE_TIME + timedelta(seconds=34),
                commit_time=BASE_TIME + timedelta(seconds=35),
                leasing_service=JobLeasingService(
                    postgres_worker_context.session_factory,
                    clock=lambda: BASE_TIME + timedelta(seconds=33),
                    token_factory=lambda: token_b,
                ),
            ).run_one_job()
            assert result_b.disposition is WorkerCycleDisposition.SUCCEEDED
            assert len(adapter_b.jobs) == 1
            assert adapter_b.jobs[0].attempt_count == 2
            assert adapter_a.jobs[0].lease_token == str(token_a)
            assert adapter_b.jobs[0].lease_token == str(token_b)
        finally:
            release.set()
        result_a = future_a.result(timeout=5)

    job, run, executions = _persisted_rows(postgres_worker_context, submitted.job_id)
    assert result_a.disposition is WorkerCycleDisposition.LEASE_LOST
    assert result_a.attempt_number == 1
    assert result_a.tool_execution_id is None
    assert not hasattr(result_a, "lease_token")
    assert job.status == JobStatus.SUCCEEDED.value
    assert job.attempt_count == 2
    assert run.status == RunStatus.COMPLETED.value
    assert run.report_json == _report_json(
        submitted.run_id,
        "current-worker-b",
        BASE_TIME + timedelta(seconds=35),
    )
    assert len(executions) == 1
    assert executions[0].attempt_number == 2


def test_postgres_long_running_cycle_renews_live_heartbeat(
    postgres_worker_context: _PostgresWorkerContext,
) -> None:
    submitted = _submit(postgres_worker_context, "7" * 64)
    completion = Event()
    entered = Event()
    heartbeat_observed = Event()
    fake_time = _MutableTime(
        BASE_TIME + timedelta(seconds=1),
        gate=completion,
        gate_at=1.5,
    )
    adapter = _ManagedAdapter(
        "heartbeat-worker",
        BASE_TIME + timedelta(seconds=5),
        completion,
        entered,
    )
    heartbeat = _RecordingHeartbeat(
        JobHeartbeatService(
            postgres_worker_context.session_factory,
            clock=fake_time.wall_clock,
        ),
        heartbeat_observed,
    )
    cycle = _cycle(
        postgres_worker_context,
        adapter,
        "heartbeat-worker",
        heartbeat_renewer=heartbeat,
        monotonic_clock=fake_time.monotonic,
        sleeper=fake_time.sleep,
        heartbeat_interval_seconds=1,
        execution_poll_interval_seconds=0.5,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(cycle.run_one_job)
        try:
            assert entered.wait(timeout=5)
            assert heartbeat_observed.wait(timeout=5)
        finally:
            completion.set()
        result = future.result(timeout=5)

    job, run, executions = _persisted_rows(postgres_worker_context, submitted.job_id)
    assert result.disposition is WorkerCycleDisposition.SUCCEEDED
    assert len(heartbeat.records) >= 1
    assert heartbeat.records[0].heartbeat_at is not None
    assert heartbeat.records[0].heartbeat_at > BASE_TIME + timedelta(seconds=1)
    assert heartbeat.records[0].lease_expires_at is not None
    assert heartbeat.records[0].lease_expires_at > BASE_TIME + timedelta(seconds=30)
    assert adapter.handle.closed is True
    assert job.status == JobStatus.SUCCEEDED.value
    assert run.status == RunStatus.COMPLETED.value
    assert len(executions) == 1


def test_postgres_live_cancellation_stops_handle_before_acknowledgement(
    postgres_worker_context: _PostgresWorkerContext,
) -> None:
    submitted = _submit(postgres_worker_context, "8" * 64)
    request_finished = Event()
    completion = Event()
    entered = Event()
    fake_time = _MutableTime(
        BASE_TIME + timedelta(seconds=1),
        gate=request_finished,
    )
    adapter = _ManagedAdapter(
        "cancelled-managed-worker",
        BASE_TIME + timedelta(seconds=2),
        completion,
        entered,
    )
    cancellation = JobCancellationService(
        postgres_worker_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=2),
    )
    acknowledger = _RecordingCancellationAcknowledger(
        cancellation,
        adapter.handle,
    )
    cycle = _cycle(
        postgres_worker_context,
        adapter,
        "cancelled-managed-worker",
        cancellation_service=cancellation,
        cancellation_acknowledger=acknowledger,
        monotonic_clock=fake_time.monotonic,
        sleeper=fake_time.sleep,
        heartbeat_interval_seconds=5,
        execution_poll_interval_seconds=0.5,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(cycle.run_one_job)
        try:
            assert entered.wait(timeout=5)
            cancellation.request_cancellation(submitted.job_id)
        finally:
            request_finished.set()
        result = future.result(timeout=5)

    job, run, executions = _persisted_rows(postgres_worker_context, submitted.job_id)
    assert result.disposition is WorkerCycleDisposition.CANCELLED
    assert result.tool_execution_id is None
    assert adapter.handle.terminated is True
    assert acknowledger.stopped_before_acknowledgement == [True]
    assert job.status == JobStatus.CANCELLED.value
    assert job.leased_by is None
    assert job.lease_token is None
    assert job.lease_expires_at is None
    assert run.status == RunStatus.CANCELLED.value
    assert executions == []


def test_postgres_heartbeat_lease_loss_stops_stale_execution(
    postgres_worker_context: _PostgresWorkerContext,
) -> None:
    submitted = _submit(postgres_worker_context, "9" * 64, max_attempts=3)
    recovery_finished = Event()
    completion = Event()
    entered = Event()
    fake_time = _MutableTime(
        BASE_TIME + timedelta(seconds=1),
        gate=recovery_finished,
    )
    adapter = _ManagedAdapter(
        "recovered-managed-worker",
        BASE_TIME + timedelta(seconds=2),
        completion,
        entered,
    )
    cycle = _cycle(
        postgres_worker_context,
        adapter,
        "recovered-managed-worker",
        monotonic_clock=fake_time.monotonic,
        sleeper=fake_time.sleep,
        heartbeat_interval_seconds=5,
        execution_poll_interval_seconds=0.5,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(cycle.run_one_job)
        try:
            assert entered.wait(timeout=5)
            recovered = JobLeaseRecoveryService(
                postgres_worker_context.session_factory,
                clock=lambda: BASE_TIME + timedelta(seconds=31),
                retry_delay_seconds=lambda _attempt: 5,
            ).recover_expired_jobs(limit=1)
            assert len(recovered) == 1
        finally:
            recovery_finished.set()
        result = future.result(timeout=5)

    job, run, executions = _persisted_rows(postgres_worker_context, submitted.job_id)
    assert result.disposition is WorkerCycleDisposition.LEASE_LOST
    assert result.tool_execution_id is None
    assert adapter.handle.terminated is True or adapter.handle.killed is True
    assert adapter.handle.closed is True
    assert job.status == JobStatus.RETRY_PENDING.value
    assert job.attempt_count == 1
    assert run.status == RunStatus.QUEUED.value
    assert executions == []

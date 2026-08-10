from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
from securescan.jobs import (
    FailedToolExecutionCommit,
    JobExecutionService,
    JobFailureCommitError,
    JobFailureCommitRequest,
    JobFailureCommitResult,
    JobFailureCommitService,
    JobLeasingService,
    JobRecord,
    JobStateConflictError,
    JobSubmissionRequest,
    JobSubmissionService,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
    create_session_factory,
)

pytestmark = pytest.mark.postgres

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"
LEASE_TIME = datetime(2038, 2, 3, 4, 5, 6, tzinfo=UTC)
EXECUTION_TIME = LEASE_TIME + timedelta(seconds=5)
COMMIT_TIME = LEASE_TIME + timedelta(seconds=10)


@dataclass(frozen=True, slots=True)
class _PostgresFailureContext:
    session_factory: sessionmaker[Session]
    target_id: str


@dataclass(frozen=True, slots=True)
class _RunningJob:
    job_id: str
    run_id: str
    worker_id: str
    lease_token: str
    record: JobRecord


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL failure-commit integration test"
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
def postgres_failure_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresFailureContext]:
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
            project = ProjectRow(name="PostgreSQL failure commit test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="c" * 64,
                source_path="/tmp/postgres-failure-target",
            )
            session.add(target)
            session.flush()
            target_id = target.id
        yield _PostgresFailureContext(session_factory, target_id)
    finally:
        if engine is not None:
            engine.dispose()
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def _prepare_running_job(
    context: _PostgresFailureContext,
    idempotency_key: str,
    worker_id: str,
) -> _RunningJob:
    submitted = JobSubmissionService(context.session_factory).submit(
        JobSubmissionRequest(
            target_id=context.target_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
        )
    )
    leased = JobLeasingService(
        context.session_factory,
        clock=lambda: LEASE_TIME,
    ).lease_next_job(worker_id, lease_seconds=60)
    assert leased is not None
    assert leased.id == submitted.job_id
    assert leased.lease_token is not None
    started = JobExecutionService(
        context.session_factory,
        clock=lambda: EXECUTION_TIME,
    ).start_job(submitted.job_id, worker_id, leased.lease_token)
    return _RunningJob(
        job_id=submitted.job_id,
        run_id=submitted.run_id,
        worker_id=worker_id,
        lease_token=leased.lease_token,
        record=started,
    )


def _request(
    running: _RunningJob,
    *,
    retryable: bool,
    failure_category: JobFailureCategory,
) -> JobFailureCommitRequest:
    return JobFailureCommitRequest(
        job_id=running.job_id,
        worker_id=running.worker_id,
        lease_token=running.lease_token,
        tool_execution=FailedToolExecutionCommit(
            tool_version="1.2.3",
            adapter_version="2.3.4",
            outcome=ExecutionOutcome.INTERNAL_ERROR.value,
            exit_code=2,
            duration_ms=250,
            warning_json=[{"code": "structured-warning"}],
            error="Structured failure",
            failure_category=failure_category,
            retryable=retryable,
        ),
    )


def _assert_committed_records(
    context: _PostgresFailureContext,
    result: JobFailureCommitResult,
) -> None:
    with context.session_factory() as session:
        job = session.get(JobRow, result.job.id)
        run = session.get(AnalysisRunRow, result.run_id)
        executions = session.scalars(
            select(ToolExecutionRow).where(ToolExecutionRow.job_id == result.job.id)
        ).all()
        assert job is not None
        assert job.status == result.job.status.value
        assert job.leased_by is None
        assert job.lease_token is None
        assert job.lease_expires_at is None
        assert job.attempt_count == result.attempt_number == 1
        assert len(executions) == 1
        assert executions[0].id == result.tool_execution_id
        assert executions[0].failure_category == result.failure_category.value
        assert executions[0].retryable is (
            result.failure_category is JobFailureCategory.RETRYABLE_INFRASTRUCTURE
        )
        assert run is not None
        expected_run_status = (
            RunStatus.QUEUED if result.retry_scheduled else RunStatus.FAILED
        )
        assert run.status == expected_run_status.value


def test_postgres_retryable_failure_schedules_retry(
    postgres_failure_context: _PostgresFailureContext,
) -> None:
    running = _prepare_running_job(
        postgres_failure_context,
        "1" * 64,
        "postgres-retry-worker",
    )
    result = JobFailureCommitService(
        postgres_failure_context.session_factory,
        clock=lambda: COMMIT_TIME,
    ).commit_failure(
        _request(
            running,
            retryable=True,
            failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
        )
    )

    assert result.retry_scheduled is True
    assert result.retry_delay_seconds == 5
    assert result.job.status is JobStatus.RETRY_PENDING
    assert result.job.available_at == COMMIT_TIME + timedelta(seconds=5)
    assert result.job.finished_at is None
    assert result.job.last_error == "Structured failure"
    _assert_committed_records(postgres_failure_context, result)


def test_postgres_permanent_failure_commits_failed_state(
    postgres_failure_context: _PostgresFailureContext,
) -> None:
    running = _prepare_running_job(
        postgres_failure_context,
        "2" * 64,
        "postgres-permanent-worker",
    )
    result = JobFailureCommitService(
        postgres_failure_context.session_factory,
        clock=lambda: COMMIT_TIME,
    ).commit_failure(
        _request(
            running,
            retryable=False,
            failure_category=JobFailureCategory.NON_RETRYABLE_INPUT,
        )
    )

    assert result.retry_scheduled is False
    assert result.retry_delay_seconds is None
    assert result.job.status is JobStatus.FAILED
    assert result.job.finished_at == COMMIT_TIME
    _assert_committed_records(postgres_failure_context, result)


def test_concurrent_failure_commits_commit_exactly_once(
    postgres_failure_context: _PostgresFailureContext,
) -> None:
    running = _prepare_running_job(
        postgres_failure_context,
        "3" * 64,
        "postgres-concurrent-failure-worker",
    )
    services = [
        JobFailureCommitService(
            postgres_failure_context.session_factory,
            clock=lambda: COMMIT_TIME,
        )
        for _ in range(2)
    ]
    requests = [
        _request(
            running,
            retryable=True,
            failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
        ),
        _request(
            running,
            retryable=False,
            failure_category=JobFailureCategory.NON_RETRYABLE_POLICY,
        ),
    ]
    outcomes: list[JobFailureCommitResult | JobStateConflictError] = []

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(service.commit_failure, request)
            for service, request in zip(services, requests, strict=True)
        ]
        for future in futures:
            try:
                outcomes.append(future.result(timeout=5))
            except JobStateConflictError as exc:
                outcomes.append(exc)

    successful = [
        outcome for outcome in outcomes if isinstance(outcome, JobFailureCommitResult)
    ]
    conflicts = [outcome for outcome in outcomes if isinstance(outcome, JobStateConflictError)]
    assert len(successful) == 1
    assert len(conflicts) == 1
    winner = successful[0]
    _assert_committed_records(postgres_failure_context, winner)
    assert winner.job.status is (
        JobStatus.RETRY_PENDING if winner.retry_scheduled else JobStatus.FAILED
    )


def test_postgres_constraint_failure_rolls_back_everything(
    postgres_failure_context: _PostgresFailureContext,
) -> None:
    running = _prepare_running_job(
        postgres_failure_context,
        "4" * 64,
        "postgres-rollback-failure-worker",
    )
    with postgres_failure_context.session_factory.begin() as session:
        conflicting = ToolExecutionRow(
            run_id=running.run_id,
            job_id=running.job_id,
            attempt_number=1,
            adapter_id="fake-scanner",
            tool_version="existing",
            adapter_version="existing",
            outcome=ExecutionOutcome.INTERNAL_ERROR.value,
            duration_ms=1,
            warning_json=[],
            error="Existing failure",
            failure_category=JobFailureCategory.WORKER_CRASH.value,
            retryable=True,
        )
        session.add(conflicting)
        session.flush()
        conflicting_id = conflicting.id

    service = JobFailureCommitService(
        postgres_failure_context.session_factory,
        clock=lambda: COMMIT_TIME,
    )
    with pytest.raises(JobFailureCommitError):
        service.commit_failure(
            _request(
                running,
                retryable=True,
                failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
            )
        )

    with postgres_failure_context.session_factory() as session:
        job = session.get(JobRow, running.job_id)
        run = session.get(AnalysisRunRow, running.run_id)
        executions = session.scalars(
            select(ToolExecutionRow).where(ToolExecutionRow.job_id == running.job_id)
        ).all()
        assert job is not None
        assert job.status == JobStatus.RUNNING.value
        assert job.leased_by == running.worker_id
        assert job.lease_token == running.lease_token
        assert job.finished_at is None
        assert run is not None
        assert run.status == RunStatus.RUNNING.value
        assert [execution.id for execution in executions] == [conflicting_id]

    with postgres_failure_context.session_factory.begin() as session:
        conflicting = session.get(ToolExecutionRow, conflicting_id)
        assert conflicting is not None
        session.delete(conflicting)

    result = service.commit_failure(
        _request(
            running,
            retryable=True,
            failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
        )
    )
    assert result.retry_scheduled is True

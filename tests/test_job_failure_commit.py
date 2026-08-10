from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import Settings
from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    RunStatus,
    TargetType,
)
from securescan.jobs import (
    FailedToolExecutionCommit,
    InvalidFailedToolExecutionCommitError,
    JobCancellationRequestedError,
    JobExecutionService,
    JobFailureCommitError,
    JobFailureCommitRequest,
    JobFailureCommitResult,
    JobFailureCommitService,
    JobLeaseExpiredError,
    JobLeaseOwnershipError,
    JobLeaseTokenMismatchError,
    JobNotFoundError,
    JobRepository,
    JobStateConflictError,
    JobSubmissionRequest,
    JobSubmissionService,
    default_retry_delay_seconds,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
    create_session_factory,
    initialize_database,
)

T0 = datetime(2038, 1, 2, 3, 4, 5, tzinfo=UTC)
COMMIT_TIME = T0 + timedelta(seconds=10)
WORKER_ID = "failure-commit-worker"
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000080"))
OTHER_LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000081"))


@dataclass(frozen=True, slots=True)
class _SqliteFailureContext:
    session_factory: sessionmaker[Session]
    repository: JobRepository
    job_id: str
    run_id: str


@pytest.fixture
def sqlite_failure_context(tmp_path: Path) -> Iterator[_SqliteFailureContext]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'job-failure-commit.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)

    with session_factory.begin() as session:
        project = ProjectRow(name="Job failure commit test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="b" * 64,
            source_path="/tmp/job-failure-target",
        )
        session.add(target)
        session.flush()
        target_id = target.id

    submitted = JobSubmissionService(session_factory).submit(
        JobSubmissionRequest(
            target_id=target_id,
            adapter_id="fake-scanner",
            idempotency_key="f" * 64,
        )
    )

    try:
        yield _SqliteFailureContext(
            session_factory=session_factory,
            repository=JobRepository(session_factory),
            job_id=submitted.job_id,
            run_id=submitted.run_id,
        )
    finally:
        engine.dispose()


def _prepare_leased_job(
    context: _SqliteFailureContext,
    *,
    attempt_count: int = 1,
    max_attempts: int = 3,
) -> None:
    context.repository.transition_job(
        context.job_id,
        JobStatus.QUEUED,
        JobStatus.LEASED,
    )
    with context.session_factory.begin() as session:
        job = session.get(JobRow, context.job_id)
        assert job is not None
        job.leased_by = WORKER_ID
        job.lease_token = LEASE_TOKEN
        job.heartbeat_at = T0
        job.lease_expires_at = T0 + timedelta(seconds=60)
        job.attempt_count = attempt_count
        job.max_attempts = max_attempts


def _prepare_running_job(
    context: _SqliteFailureContext,
    *,
    attempt_count: int = 1,
    max_attempts: int = 3,
) -> None:
    _prepare_leased_job(
        context,
        attempt_count=attempt_count,
        max_attempts=max_attempts,
    )
    JobExecutionService(
        context.session_factory,
        clock=lambda: T0 + timedelta(seconds=5),
    ).start_job(context.job_id, WORKER_ID, LEASE_TOKEN)


def _failed_execution(**overrides: Any) -> FailedToolExecutionCommit:
    values: dict[str, Any] = {
        "tool_version": " 1.2.3 ",
        "adapter_version": " 2.3.4 ",
        "outcome": ExecutionOutcome.INTERNAL_ERROR.value,
        "exit_code": 2,
        "duration_ms": 125,
        "warning_json": [{"code": "controlled-warning", "details": {"count": 1}}],
        "error": " Safe structured failure ",
        "failure_category": JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
        "retryable": True,
    }
    values.update(overrides)
    return FailedToolExecutionCommit(**values)


def _request(
    context: _SqliteFailureContext,
    *,
    tool_execution: FailedToolExecutionCommit | None = None,
    worker_id: str = WORKER_ID,
    lease_token: str = LEASE_TOKEN,
    job_id: str | None = None,
) -> JobFailureCommitRequest:
    return JobFailureCommitRequest(
        job_id=job_id or context.job_id,
        worker_id=worker_id,
        lease_token=lease_token,
        tool_execution=tool_execution or _failed_execution(),
    )


def _assert_no_failure_data(context: _SqliteFailureContext) -> None:
    with context.session_factory() as session:
        job = session.get(JobRow, context.job_id)
        run = session.get(AnalysisRunRow, context.run_id)
        execution_count = session.scalar(select(func.count()).select_from(ToolExecutionRow))
        assert job is not None
        assert job.status == JobStatus.RUNNING.value
        assert job.leased_by == WORKER_ID
        assert job.lease_token == LEASE_TOKEN
        assert job.finished_at is None
        assert run is not None
        assert run.status == RunStatus.RUNNING.value
        assert execution_count == 0


def _without_timezone(timestamp: datetime | None) -> datetime | None:
    if timestamp is None:
        return None
    return timestamp.replace(tzinfo=None)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@pytest.mark.parametrize(
    "tool_execution",
    [
        _failed_execution(tool_version=" "),
        _failed_execution(error="\t"),
        _failed_execution(duration_ms=-1),
    ],
)
def test_invalid_failed_execution_is_rejected(
    sqlite_failure_context: _SqliteFailureContext,
    tool_execution: FailedToolExecutionCommit,
) -> None:
    _prepare_running_job(sqlite_failure_context)

    with pytest.raises(InvalidFailedToolExecutionCommitError):
        JobFailureCommitService(sqlite_failure_context.session_factory).commit_failure(
            _request(sqlite_failure_context, tool_execution=tool_execution)
        )

    _assert_no_failure_data(sqlite_failure_context)


def test_unknown_job_raises_not_found(
    sqlite_failure_context: _SqliteFailureContext,
) -> None:
    unknown_job_id = str(uuid4())

    with pytest.raises(JobNotFoundError) as error:
        JobFailureCommitService(
            sqlite_failure_context.session_factory,
            clock=lambda: COMMIT_TIME,
        ).commit_failure(_request(sqlite_failure_context, job_id=unknown_job_id))

    assert error.value.job_id == unknown_job_id


def test_nonrunning_job_raises_state_conflict(
    sqlite_failure_context: _SqliteFailureContext,
) -> None:
    _prepare_leased_job(sqlite_failure_context)

    with pytest.raises(JobStateConflictError) as error:
        JobFailureCommitService(
            sqlite_failure_context.session_factory,
            clock=lambda: COMMIT_TIME,
        ).commit_failure(_request(sqlite_failure_context))

    assert error.value.actual_status is JobStatus.LEASED


@pytest.mark.parametrize(
    ("worker_id", "lease_token", "error_type"),
    [
        ("another-worker", LEASE_TOKEN, JobLeaseOwnershipError),
        (WORKER_ID, OTHER_LEASE_TOKEN, JobLeaseTokenMismatchError),
    ],
)
def test_wrong_worker_or_token_cannot_commit_failure(
    sqlite_failure_context: _SqliteFailureContext,
    worker_id: str,
    lease_token: str,
    error_type: type[Exception],
) -> None:
    _prepare_running_job(sqlite_failure_context)

    with pytest.raises(error_type):
        JobFailureCommitService(
            sqlite_failure_context.session_factory,
            clock=lambda: COMMIT_TIME,
        ).commit_failure(
            _request(
                sqlite_failure_context,
                worker_id=worker_id,
                lease_token=lease_token,
            )
        )

    _assert_no_failure_data(sqlite_failure_context)


@pytest.mark.parametrize(
    ("failure_mode", "error_type"),
    [
        ("expired", JobLeaseExpiredError),
        ("cancelled", JobCancellationRequestedError),
    ],
)
def test_expired_or_cancelled_job_cannot_commit_failure(
    sqlite_failure_context: _SqliteFailureContext,
    failure_mode: str,
    error_type: type[Exception],
) -> None:
    _prepare_running_job(sqlite_failure_context)
    with sqlite_failure_context.session_factory.begin() as session:
        job = session.get(JobRow, sqlite_failure_context.job_id)
        assert job is not None
        if failure_mode == "expired":
            job.lease_expires_at = COMMIT_TIME
        else:
            job.cancel_requested = True

    with pytest.raises(error_type):
        JobFailureCommitService(
            sqlite_failure_context.session_factory,
            clock=lambda: COMMIT_TIME,
        ).commit_failure(_request(sqlite_failure_context))

    _assert_no_failure_data(sqlite_failure_context)


def test_retryable_failure_schedules_retry(
    sqlite_failure_context: _SqliteFailureContext,
) -> None:
    _prepare_running_job(sqlite_failure_context, attempt_count=1, max_attempts=3)
    existing_report = {"evidence": {"preserved": True}}
    with sqlite_failure_context.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, sqlite_failure_context.run_id)
        assert run is not None
        run.report_json = existing_report

    failed_execution = _failed_execution()
    result = JobFailureCommitService(
        sqlite_failure_context.session_factory,
        clock=lambda: COMMIT_TIME,
    ).commit_failure(
        _request(sqlite_failure_context, tool_execution=failed_execution)
    )

    assert isinstance(result, JobFailureCommitResult)
    assert result.retry_scheduled is True
    assert result.retry_delay_seconds == 5
    assert result.failure_category is JobFailureCategory.RETRYABLE_INFRASTRUCTURE
    assert result.job.status is JobStatus.RETRY_PENDING
    assert result.job.attempt_count == result.attempt_number == 1
    assert result.job.finished_at is None
    assert result.job.leased_by is None
    assert result.job.lease_token is None
    assert result.job.lease_expires_at is None
    assert result.job.last_error == "Safe structured failure"
    assert _without_timezone(result.job.available_at) == _without_timezone(
        COMMIT_TIME + timedelta(seconds=5)
    )
    assert [default_retry_delay_seconds(attempt) for attempt in range(1, 7)] == [
        5,
        30,
        60,
        120,
        300,
        300,
    ]

    with sqlite_failure_context.session_factory() as session:
        executions = session.scalars(select(ToolExecutionRow)).all()
        run = session.get(AnalysisRunRow, sqlite_failure_context.run_id)
        assert len(executions) == 1
        execution = executions[0]
        assert execution.id == result.tool_execution_id
        assert execution.run_id == result.run_id
        assert execution.job_id == sqlite_failure_context.job_id
        assert execution.attempt_number == 1
        assert execution.adapter_id == "fake-scanner"
        assert execution.tool_version == "1.2.3"
        assert execution.adapter_version == "2.3.4"
        assert execution.outcome == ExecutionOutcome.INTERNAL_ERROR.value
        assert execution.exit_code == 2
        assert execution.duration_ms == 125
        assert execution.warning_json == failed_execution.warning_json
        assert execution.error == "Safe structured failure"
        assert execution.failure_category == JobFailureCategory.RETRYABLE_INFRASTRUCTURE.value
        assert execution.retryable is True
        assert run is not None
        assert run.status == RunStatus.QUEUED.value
        assert run.report_json == existing_report


def test_nonretryable_failure_becomes_failed(
    sqlite_failure_context: _SqliteFailureContext,
) -> None:
    _prepare_running_job(sqlite_failure_context)
    existing_report = {"partial_evidence": ["preserved"]}
    with sqlite_failure_context.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, sqlite_failure_context.run_id)
        assert run is not None
        run.report_json = existing_report

    failed_execution = _failed_execution(
        outcome=ExecutionOutcome.INVALID_OUTPUT.value,
        failure_category=JobFailureCategory.NON_RETRYABLE_PARSER,
        retryable=False,
        error=" Parser rejected sanitized output ",
    )
    result = JobFailureCommitService(
        sqlite_failure_context.session_factory,
        clock=lambda: COMMIT_TIME,
    ).commit_failure(
        _request(sqlite_failure_context, tool_execution=failed_execution)
    )

    assert result.retry_scheduled is False
    assert result.retry_delay_seconds is None
    assert result.job.status is JobStatus.FAILED
    assert _without_timezone(result.job.finished_at) == _without_timezone(COMMIT_TIME)
    assert result.job.leased_by is None
    assert result.job.lease_token is None
    assert result.job.lease_expires_at is None
    assert result.job.last_error == "Parser rejected sanitized output"
    with sqlite_failure_context.session_factory() as session:
        execution = session.get(ToolExecutionRow, result.tool_execution_id)
        run = session.get(AnalysisRunRow, result.run_id)
        assert execution is not None
        assert execution.failure_category == JobFailureCategory.NON_RETRYABLE_PARSER.value
        assert execution.retryable is False
        assert execution.error == "Parser rejected sanitized output"
        assert run is not None
        assert run.status == RunStatus.FAILED.value
        assert run.report_json == existing_report


def test_retryable_failure_at_attempt_limit_becomes_failed(
    sqlite_failure_context: _SqliteFailureContext,
) -> None:
    _prepare_running_job(sqlite_failure_context, attempt_count=3, max_attempts=3)

    def unexpected_retry_policy(_attempt_number: int) -> int:
        pytest.fail("retry policy must not be called at the attempt limit")

    result = JobFailureCommitService(
        sqlite_failure_context.session_factory,
        clock=lambda: COMMIT_TIME,
        retry_delay_seconds=unexpected_retry_policy,
    ).commit_failure(_request(sqlite_failure_context))

    assert result.retry_scheduled is False
    assert result.retry_delay_seconds is None
    assert result.job.status is JobStatus.FAILED
    assert result.attempt_number == 3


def test_duplicate_failure_commit_is_rejected(
    sqlite_failure_context: _SqliteFailureContext,
) -> None:
    _prepare_running_job(sqlite_failure_context)
    service = JobFailureCommitService(
        sqlite_failure_context.session_factory,
        clock=lambda: COMMIT_TIME,
    )
    first = service.commit_failure(_request(sqlite_failure_context))

    with pytest.raises(JobStateConflictError):
        service.commit_failure(_request(sqlite_failure_context))

    with sqlite_failure_context.session_factory() as session:
        job = session.get(JobRow, sqlite_failure_context.job_id)
        run = session.get(AnalysisRunRow, sqlite_failure_context.run_id)
        executions = session.scalars(select(ToolExecutionRow)).all()
        assert job is not None
        assert job.status == first.job.status.value
        assert first.job.available_at is not None
        assert first.job.available_at.utcoffset() == timedelta(0)
        assert _as_utc(job.available_at) == first.job.available_at
        assert len(executions) == 1
        assert run is not None
        assert run.status == RunStatus.QUEUED.value


def test_execution_constraint_failure_rolls_back_and_service_recovers(
    sqlite_failure_context: _SqliteFailureContext,
) -> None:
    _prepare_running_job(sqlite_failure_context)
    with sqlite_failure_context.session_factory.begin() as session:
        conflicting = ToolExecutionRow(
            run_id=sqlite_failure_context.run_id,
            job_id=sqlite_failure_context.job_id,
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
        sqlite_failure_context.session_factory,
        clock=lambda: COMMIT_TIME,
    )
    with pytest.raises(JobFailureCommitError):
        service.commit_failure(_request(sqlite_failure_context))

    with sqlite_failure_context.session_factory() as session:
        job = session.get(JobRow, sqlite_failure_context.job_id)
        run = session.get(AnalysisRunRow, sqlite_failure_context.run_id)
        executions = session.scalars(select(ToolExecutionRow)).all()
        assert job is not None
        assert job.status == JobStatus.RUNNING.value
        assert job.leased_by == WORKER_ID
        assert job.lease_token == LEASE_TOKEN
        assert job.finished_at is None
        assert run is not None
        assert run.status == RunStatus.RUNNING.value
        assert [execution.id for execution in executions] == [conflicting_id]

    with sqlite_failure_context.session_factory.begin() as session:
        conflicting = session.get(ToolExecutionRow, conflicting_id)
        assert conflicting is not None
        session.delete(conflicting)

    result = service.commit_failure(_request(sqlite_failure_context))
    assert result.retry_scheduled is True
    assert result.job.status is JobStatus.RETRY_PENDING


def test_failure_commit_rolls_back_execution_job_and_run_together(
    sqlite_failure_context: _SqliteFailureContext,
) -> None:
    _prepare_running_job(sqlite_failure_context)

    def fail_before_commit(_session: Session) -> None:
        raise SQLAlchemyError("injected failure commit failure")

    event.listen(sqlite_failure_context.session_factory, "before_commit", fail_before_commit)
    try:
        with pytest.raises(JobFailureCommitError):
            JobFailureCommitService(
                sqlite_failure_context.session_factory,
                clock=lambda: COMMIT_TIME,
            ).commit_failure(_request(sqlite_failure_context))
    finally:
        event.remove(
            sqlite_failure_context.session_factory,
            "before_commit",
            fail_before_commit,
        )

    _assert_no_failure_data(sqlite_failure_context)

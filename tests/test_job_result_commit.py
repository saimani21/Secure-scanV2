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
from securescan.domain.enums import ExecutionOutcome, JobStatus, RunStatus, TargetType
from securescan.domain.models import ScanReport, TargetProfile
from securescan.jobs import (
    InvalidCanonicalReportError,
    InvalidToolExecutionCommitError,
    JobCancellationRequestedError,
    JobExecutionService,
    JobLeaseExpiredError,
    JobLeaseOwnershipError,
    JobLeaseTokenMismatchError,
    JobNotFoundError,
    JobRepository,
    JobResultCommitError,
    JobResultCommitRequest,
    JobResultCommitResult,
    JobResultCommitService,
    JobStateConflictError,
    JobSubmissionRequest,
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
    initialize_database,
)

T0 = datetime(2037, 1, 2, 3, 4, 5, tzinfo=UTC)
COMMIT_TIME = T0 + timedelta(seconds=10)
WORKER_ID = "result-commit-worker"
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000070"))
OTHER_LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000071"))


@dataclass(frozen=True, slots=True)
class _SqliteResultContext:
    session_factory: sessionmaker[Session]
    repository: JobRepository
    job_id: str
    run_id: str


@pytest.fixture
def sqlite_result_context(tmp_path: Path) -> Iterator[_SqliteResultContext]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'job-result-commit.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)

    with session_factory.begin() as session:
        project = ProjectRow(name="Job result commit test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="8" * 64,
            source_path="/tmp/job-result-target",
        )
        session.add(target)
        session.flush()
        target_id = target.id

    submitted = JobSubmissionService(session_factory).submit(
        JobSubmissionRequest(
            target_id=target_id,
            adapter_id="fake-scanner",
            idempotency_key="9" * 64,
        )
    )

    try:
        yield _SqliteResultContext(
            session_factory=session_factory,
            repository=JobRepository(session_factory),
            job_id=submitted.job_id,
            run_id=submitted.run_id,
        )
    finally:
        engine.dispose()


def _prepare_leased_job(context: _SqliteResultContext) -> None:
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
        job.attempt_count = 1


def _prepare_running_job(context: _SqliteResultContext) -> None:
    _prepare_leased_job(context)
    JobExecutionService(
        context.session_factory,
        clock=lambda: T0 + timedelta(seconds=5),
    ).start_job(context.job_id, WORKER_ID, LEASE_TOKEN)


def _report_json(run_id: str, status: RunStatus = RunStatus.COMPLETED) -> dict[str, Any]:
    report = ScanReport(
        run_id=UUID(run_id),
        target=TargetProfile(
            target_type=TargetType.SOURCE_REPOSITORY,
            path=Path("/tmp/job-result-target"),
            content_digest="8" * 64,
            metadata={"origin": {"kind": "test"}},
        ),
        status=status,
        executions=[],
        observations=[],
        generated_at=COMMIT_TIME,
    )
    return report.model_dump(mode="json")


def _tool_execution(**overrides: Any) -> ToolExecutionCommit:
    values: dict[str, Any] = {
        "tool_version": " 1.2.3 ",
        "adapter_version": " 2.3.4 ",
        "outcome": ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
        "exit_code": 0,
        "duration_ms": 125,
        "warning_json": [{"code": "controlled-warning", "details": {"count": 1}}],
        "error": None,
    }
    values.update(overrides)
    return ToolExecutionCommit(**values)


def _request(
    context: _SqliteResultContext,
    *,
    final_status: JobStatus = JobStatus.SUCCEEDED,
    report_json: dict[str, Any] | None = None,
    tool_execution: ToolExecutionCommit | None = None,
    worker_id: str = WORKER_ID,
    lease_token: str = LEASE_TOKEN,
    job_id: str | None = None,
) -> JobResultCommitRequest:
    return JobResultCommitRequest(
        job_id=job_id or context.job_id,
        worker_id=worker_id,
        lease_token=lease_token,
        final_status=final_status,
        report_json=report_json or _report_json(context.run_id),
        tool_execution=tool_execution or _tool_execution(),
    )


def _assert_no_result_data(context: _SqliteResultContext) -> None:
    with context.session_factory() as session:
        job = session.get(JobRow, context.job_id)
        run = session.get(AnalysisRunRow, context.run_id)
        execution_count = session.scalar(select(func.count()).select_from(ToolExecutionRow))
        assert job is not None
        assert job.status == JobStatus.RUNNING.value
        assert run is not None
        assert run.report_json is None
        assert run.status == RunStatus.RUNNING.value
        assert execution_count == 0


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@pytest.mark.parametrize(
    "tool_execution",
    [
        _tool_execution(tool_version=" "),
        _tool_execution(adapter_version="\t"),
        _tool_execution(duration_ms=-1),
    ],
)
def test_invalid_tool_execution_commit_is_rejected(
    sqlite_result_context: _SqliteResultContext,
    tool_execution: ToolExecutionCommit,
) -> None:
    _prepare_running_job(sqlite_result_context)

    with pytest.raises(InvalidToolExecutionCommitError):
        JobResultCommitService(sqlite_result_context.session_factory).commit_result(
            _request(sqlite_result_context, tool_execution=tool_execution)
        )

    _assert_no_result_data(sqlite_result_context)


def test_invalid_canonical_report_is_rejected(
    sqlite_result_context: _SqliteResultContext,
) -> None:
    _prepare_running_job(sqlite_result_context)

    with pytest.raises(InvalidCanonicalReportError) as error:
        JobResultCommitService(sqlite_result_context.session_factory).commit_result(
            _request(sqlite_result_context, report_json={"schema_version": "invalid"})
        )

    assert error.value.__cause__ is not None
    _assert_no_result_data(sqlite_result_context)


def test_unknown_job_raises_not_found(
    sqlite_result_context: _SqliteResultContext,
) -> None:
    unknown_job_id = str(uuid4())

    with pytest.raises(JobNotFoundError) as error:
        JobResultCommitService(
            sqlite_result_context.session_factory,
            clock=lambda: COMMIT_TIME,
        ).commit_result(_request(sqlite_result_context, job_id=unknown_job_id))

    assert error.value.job_id == unknown_job_id


def test_nonrunning_job_raises_state_conflict(
    sqlite_result_context: _SqliteResultContext,
) -> None:
    _prepare_leased_job(sqlite_result_context)

    with pytest.raises(JobStateConflictError) as error:
        JobResultCommitService(
            sqlite_result_context.session_factory,
            clock=lambda: COMMIT_TIME,
        ).commit_result(_request(sqlite_result_context))

    assert error.value.actual_status is JobStatus.LEASED


@pytest.mark.parametrize(
    ("worker_id", "lease_token", "error_type"),
    [
        ("another-worker", LEASE_TOKEN, JobLeaseOwnershipError),
        (WORKER_ID, OTHER_LEASE_TOKEN, JobLeaseTokenMismatchError),
    ],
)
def test_wrong_worker_or_token_cannot_commit(
    sqlite_result_context: _SqliteResultContext,
    worker_id: str,
    lease_token: str,
    error_type: type[Exception],
) -> None:
    _prepare_running_job(sqlite_result_context)

    with pytest.raises(error_type):
        JobResultCommitService(
            sqlite_result_context.session_factory,
            clock=lambda: COMMIT_TIME,
        ).commit_result(
            _request(
                sqlite_result_context,
                worker_id=worker_id,
                lease_token=lease_token,
            )
        )

    _assert_no_result_data(sqlite_result_context)


@pytest.mark.parametrize(
    ("failure_mode", "error_type"),
    [
        ("expired", JobLeaseExpiredError),
        ("cancelled", JobCancellationRequestedError),
    ],
)
def test_expired_or_cancelled_job_cannot_commit(
    sqlite_result_context: _SqliteResultContext,
    failure_mode: str,
    error_type: type[Exception],
) -> None:
    _prepare_running_job(sqlite_result_context)
    with sqlite_result_context.session_factory.begin() as session:
        job = session.get(JobRow, sqlite_result_context.job_id)
        assert job is not None
        if failure_mode == "expired":
            job.lease_expires_at = COMMIT_TIME
        else:
            job.cancel_requested = True

    with pytest.raises(error_type):
        JobResultCommitService(
            sqlite_result_context.session_factory,
            clock=lambda: COMMIT_TIME,
        ).commit_result(_request(sqlite_result_context))

    _assert_no_result_data(sqlite_result_context)


def test_succeeded_result_is_committed_atomically(
    sqlite_result_context: _SqliteResultContext,
) -> None:
    _prepare_running_job(sqlite_result_context)
    report_json = _report_json(sqlite_result_context.run_id)
    tool_execution = _tool_execution()
    result = JobResultCommitService(
        sqlite_result_context.session_factory,
        clock=lambda: COMMIT_TIME,
    ).commit_result(
        _request(
            sqlite_result_context,
            report_json=report_json,
            tool_execution=tool_execution,
        )
    )

    assert isinstance(result, JobResultCommitResult)
    assert result.job.status is JobStatus.SUCCEEDED
    assert result.job.leased_by is None
    assert result.job.lease_token is None
    assert result.job.lease_expires_at is None
    assert result.attempt_number == result.job.attempt_count == 1
    assert result.run_id == sqlite_result_context.run_id
    with sqlite_result_context.session_factory() as session:
        executions = session.scalars(select(ToolExecutionRow)).all()
        run = session.get(AnalysisRunRow, result.run_id)
        assert len(executions) == 1
        execution = executions[0]
        assert execution.id == result.tool_execution_id
        assert execution.job_id == sqlite_result_context.job_id
        assert execution.run_id == result.run_id
        assert execution.attempt_number == 1
        assert execution.adapter_id == "fake-scanner"
        assert execution.tool_version == "1.2.3"
        assert execution.adapter_version == "2.3.4"
        assert execution.outcome == tool_execution.outcome
        assert execution.exit_code == tool_execution.exit_code
        assert execution.duration_ms == tool_execution.duration_ms
        assert execution.warning_json == tool_execution.warning_json
        assert execution.error is None
        assert run is not None
        assert run.status == RunStatus.COMPLETED.value
        assert run.report_json == result.report_json

    report_json["target"]["metadata"]["origin"]["kind"] = "mutated"
    tool_execution.warning_json[0]["details"]["count"] = 999
    result.report_json["target"]["metadata"]["origin"]["kind"] = "returned-mutation"
    with sqlite_result_context.session_factory() as session:
        run = session.get(AnalysisRunRow, result.run_id)
        execution = session.get(ToolExecutionRow, result.tool_execution_id)
        assert run is not None
        assert run.report_json["target"]["metadata"]["origin"]["kind"] == "test"
        assert execution is not None
        assert execution.warning_json[0]["details"]["count"] == 1


def test_partial_result_is_committed_atomically(
    sqlite_result_context: _SqliteResultContext,
) -> None:
    _prepare_running_job(sqlite_result_context)
    tool_execution = _tool_execution(
        outcome=ExecutionOutcome.PARTIAL_ANALYSIS.value,
        exit_code=2,
        warning_json=[{"code": "partial-output"}],
        error="Analysis was incomplete",
    )
    result = JobResultCommitService(
        sqlite_result_context.session_factory,
        clock=lambda: COMMIT_TIME,
    ).commit_result(
        _request(
            sqlite_result_context,
            final_status=JobStatus.PARTIAL,
            report_json=_report_json(sqlite_result_context.run_id, RunStatus.PARTIAL),
            tool_execution=tool_execution,
        )
    )

    assert result.job.status is JobStatus.PARTIAL
    with sqlite_result_context.session_factory() as session:
        execution = session.get(ToolExecutionRow, result.tool_execution_id)
        run = session.get(AnalysisRunRow, result.run_id)
        assert execution is not None
        assert execution.warning_json == [{"code": "partial-output"}]
        assert execution.error == "Analysis was incomplete"
        assert execution.outcome == ExecutionOutcome.PARTIAL_ANALYSIS.value
        assert run is not None
        assert run.status == RunStatus.PARTIAL.value
        assert run.report_json == result.report_json


def test_second_result_commit_is_rejected_without_duplicate_execution(
    sqlite_result_context: _SqliteResultContext,
) -> None:
    _prepare_running_job(sqlite_result_context)
    service = JobResultCommitService(
        sqlite_result_context.session_factory,
        clock=lambda: COMMIT_TIME,
    )
    first = service.commit_result(_request(sqlite_result_context))

    with pytest.raises(JobStateConflictError):
        service.commit_result(
            _request(
                sqlite_result_context,
                final_status=JobStatus.PARTIAL,
                report_json=_report_json(sqlite_result_context.run_id, RunStatus.PARTIAL),
            )
        )

    with sqlite_result_context.session_factory() as session:
        job = session.get(JobRow, sqlite_result_context.job_id)
        run = session.get(AnalysisRunRow, sqlite_result_context.run_id)
        executions = session.scalars(select(ToolExecutionRow)).all()
        assert job is not None
        assert job.status == JobStatus.SUCCEEDED.value
        assert first.job.finished_at is not None
        assert first.job.finished_at.utcoffset() == timedelta(0)
        assert _as_utc(job.finished_at) == first.job.finished_at
        assert len(executions) == 1
        assert run is not None
        assert run.report_json == first.report_json


def test_execution_insert_failure_rolls_back_job_and_report(
    sqlite_result_context: _SqliteResultContext,
) -> None:
    _prepare_running_job(sqlite_result_context)
    with sqlite_result_context.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, sqlite_result_context.run_id)
        assert run is not None
        conflicting = ToolExecutionRow(
            run_id=sqlite_result_context.run_id,
            job_id=sqlite_result_context.job_id,
            attempt_number=1,
            adapter_id="fake-scanner",
            tool_version="existing",
            adapter_version="existing",
            outcome=ExecutionOutcome.INTERNAL_ERROR.value,
            duration_ms=1,
            warning_json=[],
        )
        session.add(conflicting)
        session.flush()
        conflicting_id = conflicting.id

    service = JobResultCommitService(
        sqlite_result_context.session_factory,
        clock=lambda: COMMIT_TIME,
    )
    with pytest.raises(JobResultCommitError):
        service.commit_result(_request(sqlite_result_context))

    with sqlite_result_context.session_factory() as session:
        job = session.get(JobRow, sqlite_result_context.job_id)
        run = session.get(AnalysisRunRow, sqlite_result_context.run_id)
        executions = session.scalars(select(ToolExecutionRow)).all()
        assert job is not None
        assert job.status == JobStatus.RUNNING.value
        assert job.leased_by == WORKER_ID
        assert job.lease_token == LEASE_TOKEN
        assert job.finished_at is None
        assert run is not None
        assert run.report_json is None
        assert run.status == RunStatus.RUNNING.value
        assert [execution.id for execution in executions] == [conflicting_id]

    with sqlite_result_context.session_factory.begin() as session:
        conflicting = session.get(ToolExecutionRow, conflicting_id)
        assert conflicting is not None
        session.delete(conflicting)

    result = service.commit_result(_request(sqlite_result_context))
    assert result.job.status is JobStatus.SUCCEEDED


def test_result_commit_rolls_back_execution_job_run_and_report_together(
    sqlite_result_context: _SqliteResultContext,
) -> None:
    _prepare_running_job(sqlite_result_context)

    def fail_before_commit(_session: Session) -> None:
        raise SQLAlchemyError("injected result commit failure")

    event.listen(sqlite_result_context.session_factory, "before_commit", fail_before_commit)
    try:
        with pytest.raises(JobResultCommitError):
            JobResultCommitService(
                sqlite_result_context.session_factory,
                clock=lambda: COMMIT_TIME,
            ).commit_result(_request(sqlite_result_context))
    finally:
        event.remove(
            sqlite_result_context.session_factory,
            "before_commit",
            fail_before_commit,
        )

    _assert_no_result_data(sqlite_result_context)

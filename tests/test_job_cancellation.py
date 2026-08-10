from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
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
    InvalidCancellationRequestError,
    JobCancellationConflictError,
    JobCancellationError,
    JobCancellationNotRequestedError,
    JobCancellationService,
    JobExecutionService,
    JobFailureCommitRequest,
    JobFailureCommitService,
    JobFinalizationService,
    JobLeaseExpiredError,
    JobLeaseOwnershipError,
    JobLeaseTokenMismatchError,
    JobNotFoundError,
    JobRepository,
    JobSubmissionRequest,
    JobSubmissionService,
    UnsupportedQueueDatabaseError,
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

LEASE_TIME = datetime(2041, 2, 3, 4, 5, 6, tzinfo=UTC)
START_TIME = LEASE_TIME + timedelta(seconds=2)
REQUEST_TIME = LEASE_TIME + timedelta(seconds=5)
ACK_TIME = LEASE_TIME + timedelta(seconds=10)
WORKER_ID = "cancellation-worker"
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-0000000000c1"))
OTHER_TOKEN = str(UUID("00000000-0000-4000-8000-0000000000c2"))


@dataclass(frozen=True, slots=True)
class _CancellationContext:
    session_factory: sessionmaker[Session]
    repository: JobRepository
    job_id: str
    run_id: str


@pytest.fixture
def cancellation_context(tmp_path: Path) -> Iterator[_CancellationContext]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'job-cancellation.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)

    with session_factory.begin() as session:
        project = ProjectRow(name="Job cancellation test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="c" * 64,
            source_path="/tmp/job-cancellation-target",
        )
        session.add(target)
        session.flush()
        target_id = target.id

    submitted = JobSubmissionService(session_factory).submit(
        JobSubmissionRequest(
            target_id=target_id,
            adapter_id="fake-scanner",
            idempotency_key="c" * 64,
            payload_json={"preserve": True},
        )
    )
    try:
        yield _CancellationContext(
            session_factory=session_factory,
            repository=JobRepository(session_factory),
            job_id=submitted.job_id,
            run_id=submitted.run_id,
        )
    finally:
        engine.dispose()


def _prepare_leased_job(
    context: _CancellationContext,
    *,
    lease_expires_at: datetime | None = None,
) -> None:
    context.repository.transition_job(
        context.job_id,
        JobStatus.QUEUED,
        JobStatus.LEASED,
    )
    with context.session_factory.begin() as session:
        job = session.get(JobRow, context.job_id)
        run = session.get(AnalysisRunRow, context.run_id)
        assert job is not None
        assert run is not None
        job.leased_by = WORKER_ID
        job.lease_token = LEASE_TOKEN
        job.lease_expires_at = lease_expires_at or LEASE_TIME + timedelta(seconds=60)
        job.heartbeat_at = LEASE_TIME
        job.attempt_count = 1
        run.status = RunStatus.RUNNING.value


def _prepare_running_job(
    context: _CancellationContext,
    *,
    lease_expires_at: datetime | None = None,
) -> None:
    _prepare_leased_job(context, lease_expires_at=lease_expires_at)
    JobExecutionService(
        context.session_factory,
        clock=lambda: START_TIME,
    ).start_job(
        context.job_id,
        WORKER_ID,
        LEASE_TOKEN,
    )


def _request(context: _CancellationContext, timestamp: datetime = REQUEST_TIME):
    return JobCancellationService(
        context.session_factory,
        clock=lambda: timestamp,
    ).request_cancellation(context.job_id)


def _tool_execution_count(context: _CancellationContext) -> int:
    with context.session_factory() as session:
        count = session.scalar(select(func.count()).select_from(ToolExecutionRow))
        assert count is not None
        return count


def _as_utc(timestamp: datetime | None) -> datetime | None:
    if timestamp is None or timestamp.tzinfo is not None:
        return timestamp
    return timestamp.replace(tzinfo=UTC)


@pytest.mark.parametrize(
    "job_id",
    [
        "",
        "not-a-uuid",
        "{00000000-0000-4000-8000-000000000001}",
        "00000000-0000-4000-8000-00000000000A",
    ],
)
def test_invalid_job_ids_are_rejected_before_persistence(
    cancellation_context: _CancellationContext,
    job_id: str,
) -> None:
    with pytest.raises(InvalidCancellationRequestError) as error:
        JobCancellationService(
            cancellation_context.session_factory,
        ).request_cancellation(job_id)

    assert str(error.value) == "Cancellation job ID must be a canonical UUID string"


def test_unknown_job_is_rejected(
    cancellation_context: _CancellationContext,
) -> None:
    with pytest.raises(JobNotFoundError):
        JobCancellationService(
            cancellation_context.session_factory,
        ).request_cancellation(str(uuid4()))


def test_queued_job_is_cancelled_immediately(
    cancellation_context: _CancellationContext,
) -> None:
    result = _request(cancellation_context)

    assert result.immediate is True
    assert result.already_requested is False
    assert result.job.status is JobStatus.CANCELLED
    assert result.job.cancel_requested is True
    assert result.job.cancel_requested_at == REQUEST_TIME
    assert result.job.finished_at == REQUEST_TIME
    assert result.job.payload_json == {"preserve": True}
    with cancellation_context.session_factory() as session:
        run = session.get(AnalysisRunRow, cancellation_context.run_id)
        assert run is not None
        assert run.status == RunStatus.CANCELLED.value
    assert _tool_execution_count(cancellation_context) == 0


def test_retry_pending_cancellation_preserves_failure_evidence(
    cancellation_context: _CancellationContext,
) -> None:
    _prepare_running_job(cancellation_context)
    failure_time = START_TIME + timedelta(seconds=1)
    failure = JobFailureCommitService(
        cancellation_context.session_factory,
        clock=lambda: failure_time,
        retry_delay_seconds=lambda _attempt: 20,
    ).commit_failure(
        JobFailureCommitRequest(
            job_id=cancellation_context.job_id,
            worker_id=WORKER_ID,
            lease_token=LEASE_TOKEN,
            tool_execution=FailedToolExecutionCommit(
                tool_version="1.0",
                adapter_version="1.0",
                outcome=ExecutionOutcome.TIMEOUT.value,
                exit_code=124,
                duration_ms=100,
                warning_json=[],
                error="transient scanner timeout",
                failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
                retryable=True,
            ),
        )
    )
    before = cancellation_context.repository.get_job(cancellation_context.job_id)

    result = _request(cancellation_context)

    assert failure.retry_scheduled is True
    assert result.job.status is JobStatus.CANCELLED
    assert result.job.last_error == "transient scanner timeout"
    assert result.job.available_at == before.available_at
    assert result.job.attempt_count == before.attempt_count
    assert _tool_execution_count(cancellation_context) == 1


def test_leased_cancellation_request_preserves_active_lease(
    cancellation_context: _CancellationContext,
) -> None:
    _prepare_leased_job(cancellation_context)
    before = cancellation_context.repository.get_job(cancellation_context.job_id)

    result = _request(cancellation_context)

    assert result.immediate is False
    assert result.already_requested is False
    assert result.job.status is JobStatus.LEASED
    assert result.job.cancel_requested is True
    assert result.job.cancel_requested_at == REQUEST_TIME
    assert result.job.leased_by == before.leased_by
    assert result.job.lease_token == before.lease_token
    assert result.job.lease_expires_at == before.lease_expires_at
    assert result.job.heartbeat_at == before.heartbeat_at
    assert result.job.finished_at == before.finished_at


def test_running_cancellation_request_preserves_active_state(
    cancellation_context: _CancellationContext,
) -> None:
    _prepare_running_job(cancellation_context)
    before = cancellation_context.repository.get_job(cancellation_context.job_id)

    result = _request(cancellation_context)

    assert result.immediate is False
    assert result.job.status is JobStatus.RUNNING
    assert result.job.leased_by == before.leased_by
    assert result.job.lease_token == before.lease_token
    assert result.job.lease_expires_at == before.lease_expires_at
    assert result.job.heartbeat_at == before.heartbeat_at
    assert result.job.started_at == before.started_at
    assert result.job.finished_at == before.finished_at


def test_repeated_request_is_idempotent_and_preserves_timestamp(
    cancellation_context: _CancellationContext,
) -> None:
    _prepare_running_job(cancellation_context)
    first = _request(cancellation_context)
    second = _request(
        cancellation_context,
        REQUEST_TIME + timedelta(seconds=20),
    )

    assert first.already_requested is False
    assert second.already_requested is True
    assert second.immediate is False
    assert _as_utc(second.job.cancel_requested_at) == _as_utc(
        first.job.cancel_requested_at
    )
    assert _as_utc(second.job.updated_at) == _as_utc(first.job.updated_at)


def test_completed_job_rejects_cancellation(
    cancellation_context: _CancellationContext,
) -> None:
    _prepare_running_job(cancellation_context)
    JobFinalizationService(
        cancellation_context.session_factory,
        clock=lambda: ACK_TIME,
    ).finalize_job(
        cancellation_context.job_id,
        WORKER_ID,
        LEASE_TOKEN,
        JobStatus.SUCCEEDED,
    )

    with pytest.raises(JobCancellationConflictError) as error:
        _request(cancellation_context)

    assert error.value.actual_status is JobStatus.SUCCEEDED


def test_acknowledgement_without_request_is_rejected(
    cancellation_context: _CancellationContext,
) -> None:
    _prepare_running_job(cancellation_context)

    with pytest.raises(JobCancellationNotRequestedError):
        JobCancellationService(
            cancellation_context.session_factory,
            clock=lambda: ACK_TIME,
        ).acknowledge_cancellation(
            cancellation_context.job_id,
            WORKER_ID,
            LEASE_TOKEN,
        )


@pytest.mark.parametrize(
    ("worker_id", "lease_token", "error_type"),
    [
        ("wrong-worker", LEASE_TOKEN, JobLeaseOwnershipError),
        (WORKER_ID, OTHER_TOKEN, JobLeaseTokenMismatchError),
    ],
)
def test_acknowledgement_requires_matching_lease_owner_and_token(
    cancellation_context: _CancellationContext,
    worker_id: str,
    lease_token: str,
    error_type: type[Exception],
) -> None:
    _prepare_running_job(cancellation_context)
    _request(cancellation_context)

    with pytest.raises(error_type):
        JobCancellationService(
            cancellation_context.session_factory,
            clock=lambda: ACK_TIME,
        ).acknowledge_cancellation(
            cancellation_context.job_id,
            worker_id,
            lease_token,
        )


def test_expired_lease_cannot_acknowledge_cancellation(
    cancellation_context: _CancellationContext,
) -> None:
    _prepare_running_job(
        cancellation_context,
        lease_expires_at=ACK_TIME,
    )
    _request(cancellation_context)

    with pytest.raises(JobLeaseExpiredError):
        JobCancellationService(
            cancellation_context.session_factory,
            clock=lambda: ACK_TIME,
        ).acknowledge_cancellation(
            cancellation_context.job_id,
            WORKER_ID,
            LEASE_TOKEN,
        )


def test_owner_acknowledgement_finalizes_and_clears_lease(
    cancellation_context: _CancellationContext,
) -> None:
    _prepare_running_job(cancellation_context)
    requested = _request(cancellation_context)

    acknowledged = JobCancellationService(
        cancellation_context.session_factory,
        clock=lambda: ACK_TIME,
    ).acknowledge_cancellation(
        cancellation_context.job_id,
        WORKER_ID,
        LEASE_TOKEN,
    )

    assert acknowledged.status is JobStatus.CANCELLED
    assert _as_utc(acknowledged.finished_at) == ACK_TIME
    assert acknowledged.cancel_requested is True
    assert _as_utc(acknowledged.cancel_requested_at) == _as_utc(
        requested.job.cancel_requested_at
    )
    assert acknowledged.leased_by is None
    assert acknowledged.lease_token is None
    assert acknowledged.lease_expires_at is None
    assert _as_utc(acknowledged.heartbeat_at) == ACK_TIME
    with cancellation_context.session_factory() as session:
        run = session.get(AnalysisRunRow, cancellation_context.run_id)
        assert run is not None
        assert run.status == RunStatus.CANCELLED.value
    assert _tool_execution_count(cancellation_context) == 0


def test_sqlite_rejects_expired_cancellation_finalizer(
    cancellation_context: _CancellationContext,
) -> None:
    with pytest.raises(UnsupportedQueueDatabaseError):
        JobCancellationService(
            cancellation_context.session_factory,
            clock=lambda: ACK_TIME,
        ).finalize_expired_cancellations()


@pytest.mark.parametrize("limit", [None, True, 0, 1001])
def test_invalid_finalizer_limits_are_rejected_before_database_access(
    cancellation_context: _CancellationContext,
    limit: object,
) -> None:
    with pytest.raises(
        InvalidCancellationRequestError,
        match="Cancellation finalizer limit",
    ):
        JobCancellationService(
            cancellation_context.session_factory,
        ).finalize_expired_cancellations(limit)  # type: ignore[arg-type]


def test_cancellation_acknowledgement_rolls_back_job_and_run_together(
    cancellation_context: _CancellationContext,
) -> None:
    _prepare_running_job(cancellation_context)
    requested = _request(cancellation_context)
    assert requested.immediate is False

    def fail_before_commit(_session: Session) -> None:
        raise SQLAlchemyError("injected cancellation acknowledgement failure")

    event.listen(cancellation_context.session_factory, "before_commit", fail_before_commit)
    try:
        with pytest.raises(JobCancellationError):
            JobCancellationService(
                cancellation_context.session_factory,
                clock=lambda: ACK_TIME,
            ).acknowledge_cancellation(
                cancellation_context.job_id,
                WORKER_ID,
                LEASE_TOKEN,
            )
    finally:
        event.remove(
            cancellation_context.session_factory,
            "before_commit",
            fail_before_commit,
        )

    with cancellation_context.session_factory() as session:
        job = session.get(JobRow, cancellation_context.job_id)
        run = session.get(AnalysisRunRow, cancellation_context.run_id)
        assert job is not None
        assert run is not None
        assert job.status == JobStatus.RUNNING.value
        assert job.cancel_requested is True
        assert job.leased_by == WORKER_ID
        assert job.lease_token == LEASE_TOKEN
        assert run.status == RunStatus.RUNNING.value
    assert _tool_execution_count(cancellation_context) == 0

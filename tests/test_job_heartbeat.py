from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import Settings
from securescan.domain.enums import JobStatus, TargetType
from securescan.jobs import (
    InvalidHeartbeatRequestError,
    JobCancellationRequestedError,
    JobExecutionService,
    JobHeartbeatService,
    JobLeaseExpiredError,
    JobLeaseOwnershipError,
    JobLeaseTokenMismatchError,
    JobNotFoundError,
    JobRecord,
    JobRepository,
    JobStateConflictError,
    JobSubmissionRequest,
    JobSubmissionService,
)
from securescan.persistence.database import (
    JobRow,
    ProjectRow,
    TargetRow,
    create_session_factory,
    initialize_database,
)

T0 = datetime(2035, 9, 10, 11, 12, 13, tzinfo=UTC)
WORKER_ID = "heartbeat-worker"
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000030"))
OTHER_LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000031"))


@dataclass(frozen=True, slots=True)
class _SqliteHeartbeatContext:
    session_factory: sessionmaker[Session]
    repository: JobRepository
    job_id: str


@pytest.fixture
def sqlite_heartbeat_context(
    tmp_path: Path,
) -> Iterator[_SqliteHeartbeatContext]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'job-heartbeat.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)

    with session_factory.begin() as session:
        project = ProjectRow(name="Job heartbeat test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="8" * 64,
            source_path="/tmp/job-heartbeat-target",
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
        yield _SqliteHeartbeatContext(
            session_factory=session_factory,
            repository=JobRepository(session_factory),
            job_id=submitted.job_id,
        )
    finally:
        engine.dispose()


def _prepare_leased_job(context: _SqliteHeartbeatContext) -> JobRecord:
    context.repository.transition_job(
        job_id=context.job_id,
        expected_status=JobStatus.QUEUED,
        requested_status=JobStatus.LEASED,
    )
    with context.session_factory.begin() as session:
        row = session.get(JobRow, context.job_id)
        assert row is not None
        row.leased_by = WORKER_ID
        row.lease_token = LEASE_TOKEN
        row.heartbeat_at = T0 - timedelta(seconds=10)
        row.lease_expires_at = T0 + timedelta(seconds=60)
        row.attempt_count = 1

    leased = context.repository.get_job(context.job_id)
    assert leased is not None
    return leased


def _prepare_running_job(context: _SqliteHeartbeatContext) -> JobRecord:
    _prepare_leased_job(context)
    return JobExecutionService(
        context.session_factory,
        clock=lambda: T0,
    ).start_job(context.job_id, WORKER_ID, LEASE_TOKEN)


def _without_timezone(timestamp: datetime | None) -> datetime | None:
    if timestamp is None:
        return None
    return timestamp.replace(tzinfo=None)


@pytest.mark.parametrize("lease_seconds", [0, -1])
def test_nonpositive_heartbeat_duration_is_rejected(
    sqlite_heartbeat_context: _SqliteHeartbeatContext,
    lease_seconds: int,
) -> None:
    service = JobHeartbeatService(sqlite_heartbeat_context.session_factory)
    before = sqlite_heartbeat_context.repository.get_job(sqlite_heartbeat_context.job_id)

    with pytest.raises(InvalidHeartbeatRequestError) as error:
        service.renew_lease(
            sqlite_heartbeat_context.job_id,
            WORKER_ID,
            LEASE_TOKEN,
            lease_seconds=lease_seconds,
        )

    assert error.value.lease_seconds == lease_seconds
    assert sqlite_heartbeat_context.repository.get_job(sqlite_heartbeat_context.job_id) == before


def test_unknown_job_raises_not_found(
    sqlite_heartbeat_context: _SqliteHeartbeatContext,
) -> None:
    service = JobHeartbeatService(
        sqlite_heartbeat_context.session_factory,
        clock=lambda: T0 + timedelta(seconds=10),
    )
    job_id = str(uuid4())

    with pytest.raises(JobNotFoundError) as error:
        service.renew_lease(job_id, WORKER_ID, LEASE_TOKEN)

    assert error.value.job_id == job_id


def test_nonrunning_job_raises_state_conflict(
    sqlite_heartbeat_context: _SqliteHeartbeatContext,
) -> None:
    _prepare_leased_job(sqlite_heartbeat_context)
    service = JobHeartbeatService(
        sqlite_heartbeat_context.session_factory,
        clock=lambda: T0 + timedelta(seconds=10),
    )

    with pytest.raises(JobStateConflictError) as error:
        service.renew_lease(
            sqlite_heartbeat_context.job_id,
            WORKER_ID,
            LEASE_TOKEN,
        )

    assert error.value.expected_status is JobStatus.RUNNING
    assert error.value.actual_status is JobStatus.LEASED


def test_wrong_worker_cannot_renew_lease(
    sqlite_heartbeat_context: _SqliteHeartbeatContext,
) -> None:
    before = _prepare_running_job(sqlite_heartbeat_context)
    service = JobHeartbeatService(
        sqlite_heartbeat_context.session_factory,
        clock=lambda: T0 + timedelta(seconds=10),
    )

    with pytest.raises(JobLeaseOwnershipError):
        service.renew_lease(
            sqlite_heartbeat_context.job_id,
            "worker-other",
            LEASE_TOKEN,
        )

    persisted = sqlite_heartbeat_context.repository.get_job(sqlite_heartbeat_context.job_id)
    assert persisted is not None
    assert persisted.heartbeat_at == before.heartbeat_at
    assert persisted.lease_expires_at == before.lease_expires_at


def test_wrong_token_cannot_renew_lease(
    sqlite_heartbeat_context: _SqliteHeartbeatContext,
) -> None:
    before = _prepare_running_job(sqlite_heartbeat_context)
    service = JobHeartbeatService(
        sqlite_heartbeat_context.session_factory,
        clock=lambda: T0 + timedelta(seconds=10),
    )

    with pytest.raises(JobLeaseTokenMismatchError):
        service.renew_lease(
            sqlite_heartbeat_context.job_id,
            WORKER_ID,
            OTHER_LEASE_TOKEN,
        )

    persisted = sqlite_heartbeat_context.repository.get_job(sqlite_heartbeat_context.job_id)
    assert persisted is not None
    assert persisted.lease_token == LEASE_TOKEN
    assert persisted.heartbeat_at == before.heartbeat_at
    assert persisted.lease_expires_at == before.lease_expires_at


def test_expired_lease_cannot_be_revived(
    sqlite_heartbeat_context: _SqliteHeartbeatContext,
) -> None:
    before = _prepare_running_job(sqlite_heartbeat_context)
    operation_time = T0 + timedelta(seconds=10)
    with sqlite_heartbeat_context.session_factory.begin() as session:
        row = session.get(JobRow, sqlite_heartbeat_context.job_id)
        assert row is not None
        row.lease_expires_at = operation_time

    service = JobHeartbeatService(
        sqlite_heartbeat_context.session_factory,
        clock=lambda: operation_time,
    )
    with pytest.raises(JobLeaseExpiredError):
        service.renew_lease(
            sqlite_heartbeat_context.job_id,
            WORKER_ID,
            LEASE_TOKEN,
        )

    persisted = sqlite_heartbeat_context.repository.get_job(sqlite_heartbeat_context.job_id)
    assert persisted is not None
    assert _without_timezone(persisted.lease_expires_at) == _without_timezone(operation_time)
    assert persisted.heartbeat_at == before.heartbeat_at


def test_cancel_requested_job_cannot_renew(
    sqlite_heartbeat_context: _SqliteHeartbeatContext,
) -> None:
    before = _prepare_running_job(sqlite_heartbeat_context)
    with sqlite_heartbeat_context.session_factory.begin() as session:
        row = session.get(JobRow, sqlite_heartbeat_context.job_id)
        assert row is not None
        row.cancel_requested = True

    service = JobHeartbeatService(
        sqlite_heartbeat_context.session_factory,
        clock=lambda: T0 + timedelta(seconds=10),
    )
    with pytest.raises(JobCancellationRequestedError):
        service.renew_lease(
            sqlite_heartbeat_context.job_id,
            WORKER_ID,
            LEASE_TOKEN,
        )

    persisted = sqlite_heartbeat_context.repository.get_job(sqlite_heartbeat_context.job_id)
    assert persisted is not None
    assert persisted.heartbeat_at == before.heartbeat_at
    assert persisted.lease_expires_at == before.lease_expires_at


def test_owner_renews_lease_without_shortening_or_regressing_timestamps(
    sqlite_heartbeat_context: _SqliteHeartbeatContext,
) -> None:
    running = _prepare_running_job(sqlite_heartbeat_context)
    started_at = running.started_at

    first_time = T0 + timedelta(seconds=10)
    first = JobHeartbeatService(
        sqlite_heartbeat_context.session_factory,
        clock=lambda: first_time,
    ).renew_lease(
        sqlite_heartbeat_context.job_id,
        WORKER_ID,
        LEASE_TOKEN,
        lease_seconds=30,
    )

    assert _without_timezone(first.lease_expires_at) == _without_timezone(
        T0 + timedelta(seconds=60)
    )
    assert _without_timezone(first.heartbeat_at) == _without_timezone(first_time)
    assert _without_timezone(first.updated_at) >= _without_timezone(first_time)
    assert first.status is JobStatus.RUNNING
    assert first.leased_by == WORKER_ID
    assert first.lease_token == LEASE_TOKEN
    assert first.attempt_count == 1
    assert first.started_at == started_at
    assert first.finished_at is None

    second_time = T0 + timedelta(seconds=40)
    second = JobHeartbeatService(
        sqlite_heartbeat_context.session_factory,
        clock=lambda: second_time,
    ).renew_lease(
        sqlite_heartbeat_context.job_id,
        WORKER_ID,
        LEASE_TOKEN,
        lease_seconds=30,
    )

    assert _without_timezone(second.lease_expires_at) == _without_timezone(
        T0 + timedelta(seconds=70)
    )
    assert _without_timezone(second.heartbeat_at) == _without_timezone(second_time)
    assert sqlite_heartbeat_context.repository.get_job(sqlite_heartbeat_context.job_id) == second

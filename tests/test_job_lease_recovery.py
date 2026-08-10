from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import Settings
from securescan.domain.enums import JobStatus, TargetType
from securescan.jobs import (
    InvalidLeaseRecoveryRequestError,
    JobLeaseRecoveryService,
    JobRepository,
    JobSubmissionRequest,
    JobSubmissionService,
    UnsupportedQueueDatabaseError,
)
from securescan.persistence.database import (
    JobRow,
    ProjectRow,
    TargetRow,
    create_session_factory,
    initialize_database,
)

RECOVERY_TIME = datetime(2040, 1, 2, 3, 4, 5, tzinfo=UTC)
WORKER_ID = "sqlite-expired-worker"
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000100"))


@dataclass(frozen=True, slots=True)
class _SqliteRecoveryContext:
    session_factory: sessionmaker[Session]
    repository: JobRepository
    job_id: str


@pytest.fixture
def sqlite_recovery_context(tmp_path: Path) -> Iterator[_SqliteRecoveryContext]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'job-lease-recovery.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)
    with session_factory.begin() as session:
        project = ProjectRow(name="SQLite lease recovery test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="f" * 64,
            source_path="/tmp/sqlite-lease-recovery",
        )
        session.add(target)
        session.flush()
        target_id = target.id
    submitted = JobSubmissionService(session_factory).submit(
        JobSubmissionRequest(
            target_id=target_id,
            adapter_id="fake-scanner",
            idempotency_key="b" * 64,
        )
    )
    try:
        yield _SqliteRecoveryContext(
            session_factory=session_factory,
            repository=JobRepository(session_factory),
            job_id=submitted.job_id,
        )
    finally:
        engine.dispose()


def _prepare_expired_leased_job(context: _SqliteRecoveryContext) -> None:
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
        job.lease_expires_at = RECOVERY_TIME - timedelta(seconds=1)
        job.heartbeat_at = RECOVERY_TIME - timedelta(seconds=30)
        job.attempt_count = 1


@pytest.mark.parametrize("limit", [0, -1, 1001])
def test_invalid_recovery_limit_is_rejected(
    sqlite_recovery_context: _SqliteRecoveryContext,
    limit: int,
) -> None:
    before = sqlite_recovery_context.repository.get_job(sqlite_recovery_context.job_id)

    with pytest.raises(InvalidLeaseRecoveryRequestError) as error:
        JobLeaseRecoveryService(
            sqlite_recovery_context.session_factory
        ).recover_expired_jobs(limit)

    assert error.value.limit == limit
    assert sqlite_recovery_context.repository.get_job(
        sqlite_recovery_context.job_id
    ) == before


def test_sqlite_is_rejected_for_atomic_recovery(
    sqlite_recovery_context: _SqliteRecoveryContext,
) -> None:
    _prepare_expired_leased_job(sqlite_recovery_context)
    before = sqlite_recovery_context.repository.get_job(sqlite_recovery_context.job_id)
    assert before is not None
    assert before.status is JobStatus.LEASED

    with pytest.raises(UnsupportedQueueDatabaseError) as error:
        JobLeaseRecoveryService(
            sqlite_recovery_context.session_factory,
            clock=lambda: RECOVERY_TIME,
        ).recover_expired_jobs(limit=1)

    assert error.value.dialect_name == "sqlite"
    after = sqlite_recovery_context.repository.get_job(sqlite_recovery_context.job_id)
    assert after is not None
    assert after.status is JobStatus.LEASED
    assert after.leased_by == before.leased_by
    assert after.lease_token == before.lease_token
    assert after.lease_expires_at == before.lease_expires_at
    assert after.attempt_count == before.attempt_count

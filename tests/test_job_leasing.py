from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import Settings
from securescan.domain.enums import JobStatus, TargetType
from securescan.jobs import (
    InvalidLeaseRequestError,
    JobLeasingService,
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


@pytest.fixture
def sqlite_leasing_context(
    tmp_path: Path,
) -> Iterator[tuple[JobLeasingService, sessionmaker[Session], str]]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'job-leasing.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)

    with session_factory.begin() as session:
        project = ProjectRow(name="Job leasing test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="a" * 64,
            source_path="/tmp/job-leasing-target",
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
        yield JobLeasingService(session_factory), session_factory, submitted.job_id
    finally:
        engine.dispose()


def test_blank_worker_id_is_rejected(
    sqlite_leasing_context: tuple[JobLeasingService, sessionmaker[Session], str],
) -> None:
    service, _, _ = sqlite_leasing_context

    with pytest.raises(InvalidLeaseRequestError, match="worker_id"):
        service.lease_next_job(" \t ")


@pytest.mark.parametrize("lease_seconds", [0, -1])
def test_nonpositive_lease_duration_is_rejected(
    sqlite_leasing_context: tuple[JobLeasingService, sessionmaker[Session], str],
    lease_seconds: int,
) -> None:
    service, _, _ = sqlite_leasing_context

    with pytest.raises(InvalidLeaseRequestError, match="lease_seconds"):
        service.lease_next_job("worker-1", lease_seconds=lease_seconds)


def test_sqlite_is_rejected_without_changing_job_state(
    sqlite_leasing_context: tuple[JobLeasingService, sessionmaker[Session], str],
) -> None:
    service, session_factory, job_id = sqlite_leasing_context

    with pytest.raises(UnsupportedQueueDatabaseError) as error:
        service.lease_next_job("worker-1")

    assert error.value.dialect_name == "sqlite"

    with session_factory() as session:
        job = session.get(JobRow, job_id)
        assert job is not None
        assert job.status == JobStatus.QUEUED.value
        assert job.attempt_count == 0
        assert job.leased_by is None
        assert job.lease_token is None
        assert job.heartbeat_at is None
        assert job.lease_expires_at is None

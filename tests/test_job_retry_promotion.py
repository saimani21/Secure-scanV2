from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import Settings
from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    TargetType,
)
from securescan.jobs import (
    FailedToolExecutionCommit,
    InvalidRetryPromotionRequestError,
    JobExecutionService,
    JobFailureCommitRequest,
    JobFailureCommitService,
    JobRepository,
    JobRetryPromotionService,
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

T0 = datetime(2039, 1, 2, 3, 4, 5, tzinfo=UTC)
WORKER_ID = "sqlite-retry-promotion-worker"
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000090"))


@dataclass(frozen=True, slots=True)
class _SqlitePromotionContext:
    session_factory: sessionmaker[Session]
    repository: JobRepository
    job_id: str


@pytest.fixture
def sqlite_promotion_context(tmp_path: Path) -> Iterator[_SqlitePromotionContext]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'job-retry-promotion.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)
    with session_factory.begin() as session:
        project = ProjectRow(name="SQLite retry promotion test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="d" * 64,
            source_path="/tmp/sqlite-retry-promotion",
        )
        session.add(target)
        session.flush()
        target_id = target.id
    submitted = JobSubmissionService(session_factory).submit(
        JobSubmissionRequest(
            target_id=target_id,
            adapter_id="fake-scanner",
            idempotency_key="a" * 64,
        )
    )
    try:
        yield _SqlitePromotionContext(
            session_factory=session_factory,
            repository=JobRepository(session_factory),
            job_id=submitted.job_id,
        )
    finally:
        engine.dispose()


def _prepare_due_retry(context: _SqlitePromotionContext) -> None:
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
        job.lease_expires_at = T0 + timedelta(seconds=60)
        job.heartbeat_at = T0
        job.attempt_count = 1
        job.last_error = "Earlier failure evidence"
    JobExecutionService(
        context.session_factory,
        clock=lambda: T0 + timedelta(seconds=1),
    ).start_job(context.job_id, WORKER_ID, LEASE_TOKEN)
    JobFailureCommitService(
        context.session_factory,
        clock=lambda: T0 + timedelta(seconds=2),
        retry_delay_seconds=lambda _attempt: 5,
    ).commit_failure(
        JobFailureCommitRequest(
            job_id=context.job_id,
            worker_id=WORKER_ID,
            lease_token=LEASE_TOKEN,
            tool_execution=FailedToolExecutionCommit(
                tool_version="1.0.0",
                adapter_version="1.0.0",
                outcome=ExecutionOutcome.INTERNAL_ERROR.value,
                exit_code=2,
                duration_ms=10,
                warning_json=[],
                error="Retryable infrastructure failure",
                failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
                retryable=True,
            ),
        )
    )


@pytest.mark.parametrize("limit", [0, -1, 1001])
def test_invalid_promotion_limit_is_rejected(
    sqlite_promotion_context: _SqlitePromotionContext,
    limit: int,
) -> None:
    before = sqlite_promotion_context.repository.get_job(sqlite_promotion_context.job_id)

    with pytest.raises(InvalidRetryPromotionRequestError) as error:
        JobRetryPromotionService(
            sqlite_promotion_context.session_factory
        ).promote_due_retries(limit)

    assert error.value.limit == limit
    assert sqlite_promotion_context.repository.get_job(
        sqlite_promotion_context.job_id
    ) == before


def test_sqlite_is_rejected_for_atomic_retry_promotion(
    sqlite_promotion_context: _SqlitePromotionContext,
) -> None:
    _prepare_due_retry(sqlite_promotion_context)
    before = sqlite_promotion_context.repository.get_job(sqlite_promotion_context.job_id)
    assert before is not None
    assert before.status is JobStatus.RETRY_PENDING

    with pytest.raises(UnsupportedQueueDatabaseError) as error:
        JobRetryPromotionService(
            sqlite_promotion_context.session_factory,
            clock=lambda: T0 + timedelta(seconds=8),
        ).promote_due_retries(limit=1)

    assert error.value.dialect_name == "sqlite"
    after = sqlite_promotion_context.repository.get_job(sqlite_promotion_context.job_id)
    assert after is not None
    assert after.status is JobStatus.RETRY_PENDING
    assert after.available_at == before.available_at
    assert after.attempt_count == before.attempt_count
    assert after.last_error == before.last_error

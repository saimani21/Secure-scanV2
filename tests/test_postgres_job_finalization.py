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
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import get_settings
from securescan.domain.enums import JobStatus, TargetType
from securescan.jobs import (
    JobExecutionService,
    JobFinalizationService,
    JobLeasingService,
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
)

pytestmark = pytest.mark.postgres

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"


@dataclass(frozen=True, slots=True)
class _PostgresFinalizationContext:
    session_factory: sessionmaker[Session]
    target_id: str


@dataclass(frozen=True, slots=True)
class _RunningJob:
    job_id: str
    worker_id: str
    lease_token: str
    record: JobRecord


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL job finalization integration test"
        )

    try:
        parsed_url = make_url(database_url)
    except ArgumentError as exc:
        pytest.fail(f"Unsafe SECURESCAN_TEST_POSTGRES_URL: URL could not be parsed: {exc}")

    if not parsed_url.get_backend_name().startswith("postgresql"):
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: backend must be PostgreSQL")

    database_name = parsed_url.database
    if not database_name:
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: database name is required")
    if not database_name.endswith("_test"):
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
def postgres_finalization_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresFinalizationContext]:
    database_url = _validated_test_database_url()
    alembic_config = Config(str(ALEMBIC_INI_PATH))
    alembic_config.set_main_option("script_location", str(MIGRATIONS_PATH))

    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()
    engine: Engine | None = None

    try:
        _reset_public_schema(database_url)
        command.upgrade(alembic_config, "head")

        settings = get_settings()
        engine, session_factory = create_session_factory(settings)
        with session_factory.begin() as session:
            project = ProjectRow(name="PostgreSQL job finalization test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="d" * 64,
                source_path="/tmp/postgres-job-finalization-target",
            )
            session.add(target)
            session.flush()
            target_id = target.id

        yield _PostgresFinalizationContext(
            session_factory=session_factory,
            target_id=target_id,
        )
    finally:
        if engine is not None:
            engine.dispose()
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def _prepare_running_job(
    context: _PostgresFinalizationContext,
    idempotency_key: str,
    worker_id: str,
    lease_time: datetime,
    execution_time: datetime,
) -> _RunningJob:
    submitted = JobSubmissionService(context.session_factory).submit(
        JobSubmissionRequest(
            target_id=context.target_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
            payload_json={"idempotency_key": idempotency_key},
        )
    )
    leased = JobLeasingService(
        context.session_factory,
        clock=lambda: lease_time,
    ).lease_next_job(worker_id, lease_seconds=60)
    assert leased is not None
    assert leased.lease_token is not None
    started = JobExecutionService(
        context.session_factory,
        clock=lambda: execution_time,
    ).start_job(
        submitted.job_id,
        worker_id,
        leased.lease_token,
    )
    return _RunningJob(
        job_id=submitted.job_id,
        worker_id=worker_id,
        lease_token=leased.lease_token,
        record=started,
    )


def test_postgres_owner_finalizes_succeeded_job(
    postgres_finalization_context: _PostgresFinalizationContext,
) -> None:
    lease_time = datetime(2036, 2, 3, 4, 5, 6, tzinfo=UTC)
    execution_time = lease_time + timedelta(seconds=5)
    finalization_time = lease_time + timedelta(seconds=10)
    running = _prepare_running_job(
        postgres_finalization_context,
        "e" * 64,
        "postgres-finalization-worker",
        lease_time,
        execution_time,
    )

    finalized = JobFinalizationService(
        postgres_finalization_context.session_factory,
        clock=lambda: finalization_time,
    ).finalize_job(
        running.job_id,
        running.worker_id,
        running.lease_token,
        JobStatus.SUCCEEDED,
    )

    assert finalized.status is JobStatus.SUCCEEDED
    assert finalized.finished_at == finalization_time
    assert finalized.heartbeat_at >= finalization_time
    assert finalized.leased_by is None
    assert finalized.lease_token is None
    assert finalized.lease_expires_at is None
    assert finalized.attempt_count == 1
    assert finalized.started_at == running.record.started_at
    assert (
        JobRepository(postgres_finalization_context.session_factory).get_job(running.job_id)
        == finalized
    )


def test_postgres_owner_finalizes_partial_job(
    postgres_finalization_context: _PostgresFinalizationContext,
) -> None:
    lease_time = datetime(2036, 3, 4, 5, 6, 7, tzinfo=UTC)
    execution_time = lease_time + timedelta(seconds=5)
    finalization_time = lease_time + timedelta(seconds=10)
    running = _prepare_running_job(
        postgres_finalization_context,
        "f" * 64,
        "postgres-partial-worker",
        lease_time,
        execution_time,
    )

    finalized = JobFinalizationService(
        postgres_finalization_context.session_factory,
        clock=lambda: finalization_time,
    ).finalize_job(
        running.job_id,
        running.worker_id,
        running.lease_token,
        JobStatus.PARTIAL,
    )

    assert finalized.status is JobStatus.PARTIAL
    assert finalized.leased_by is None
    assert finalized.lease_token is None
    assert finalized.lease_expires_at is None
    assert (
        JobRepository(postgres_finalization_context.session_factory).get_job(running.job_id)
        == finalized
    )


def test_concurrent_terminal_finalization_commits_exactly_once(
    postgres_finalization_context: _PostgresFinalizationContext,
) -> None:
    lease_time = datetime(2036, 4, 5, 6, 7, 8, tzinfo=UTC)
    execution_time = lease_time + timedelta(seconds=5)
    finalization_time = lease_time + timedelta(seconds=10)
    running = _prepare_running_job(
        postgres_finalization_context,
        "0" * 64,
        "concurrent-finalization-worker",
        lease_time,
        execution_time,
    )
    services = [
        JobFinalizationService(
            postgres_finalization_context.session_factory,
            clock=lambda: finalization_time,
        )
        for _ in range(2)
    ]
    statuses = [JobStatus.SUCCEEDED, JobStatus.PARTIAL]
    outcomes: list[JobRecord | JobStateConflictError] = []

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                service.finalize_job,
                running.job_id,
                running.worker_id,
                running.lease_token,
                final_status,
            )
            for service, final_status in zip(services, statuses, strict=True)
        ]
        for future in futures:
            try:
                outcomes.append(future.result(timeout=5))
            except JobStateConflictError as exc:
                outcomes.append(exc)

    successful = [outcome for outcome in outcomes if isinstance(outcome, JobRecord)]
    conflicts = [outcome for outcome in outcomes if isinstance(outcome, JobStateConflictError)]
    assert len(successful) == 1
    assert len(conflicts) == 1

    with postgres_finalization_context.session_factory() as session:
        persisted = session.get(JobRow, running.job_id)
        assert persisted is not None
        assert persisted.status in {
            JobStatus.SUCCEEDED.value,
            JobStatus.PARTIAL.value,
        }
        assert persisted.status == successful[0].status.value
        assert persisted.finished_at == finalization_time
        assert persisted.leased_by is None
        assert persisted.lease_token is None
        assert persisted.lease_expires_at is None
        assert persisted.attempt_count == 1

from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

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
    JobHeartbeatService,
    JobLeaseTokenMismatchError,
    JobLeasingService,
    JobRecord,
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
class _PostgresHeartbeatContext:
    session_factory: sessionmaker[Session]
    target_id: str


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL job heartbeat integration test"
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
def postgres_heartbeat_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresHeartbeatContext]:
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
            project = ProjectRow(name="PostgreSQL job heartbeat test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="a" * 64,
                source_path="/tmp/postgres-job-heartbeat-target",
            )
            session.add(target)
            session.flush()
            target_id = target.id

        yield _PostgresHeartbeatContext(
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


def _submit_job(
    context: _PostgresHeartbeatContext,
    idempotency_key: str,
) -> str:
    result = JobSubmissionService(context.session_factory).submit(
        JobSubmissionRequest(
            target_id=context.target_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
            payload_json={"idempotency_key": idempotency_key},
        )
    )
    return result.job_id


def test_postgres_running_job_renews_lease(
    postgres_heartbeat_context: _PostgresHeartbeatContext,
) -> None:
    lease_time = datetime(2035, 10, 11, 12, 13, 14, tzinfo=UTC)
    execution_time = lease_time + timedelta(seconds=5)
    renewal_time = lease_time + timedelta(seconds=20)
    worker_id = "postgres-heartbeat-worker"
    job_id = _submit_job(postgres_heartbeat_context, "b" * 64)

    leased = JobLeasingService(
        postgres_heartbeat_context.session_factory,
        clock=lambda: lease_time,
    ).lease_next_job(worker_id, lease_seconds=30)
    assert leased is not None
    assert leased.lease_token is not None

    started = JobExecutionService(
        postgres_heartbeat_context.session_factory,
        clock=lambda: execution_time,
    ).start_job(job_id, worker_id, leased.lease_token)
    renewed = JobHeartbeatService(
        postgres_heartbeat_context.session_factory,
        clock=lambda: renewal_time,
    ).renew_lease(
        job_id,
        worker_id,
        leased.lease_token,
        lease_seconds=60,
    )

    assert renewed.status is JobStatus.RUNNING
    assert renewed.leased_by == worker_id
    assert renewed.lease_token == leased.lease_token
    assert renewed.heartbeat_at == renewal_time
    assert renewed.lease_expires_at == renewal_time + timedelta(seconds=60)
    assert renewed.attempt_count == 1
    assert renewed.started_at == started.started_at

    with postgres_heartbeat_context.session_factory() as session:
        persisted = session.get(JobRow, job_id)
        assert persisted is not None
        assert persisted.status == renewed.status.value
        assert persisted.leased_by == renewed.leased_by
        assert persisted.lease_token == renewed.lease_token
        assert persisted.heartbeat_at == renewed.heartbeat_at
        assert persisted.lease_expires_at == renewed.lease_expires_at
        assert persisted.attempt_count == renewed.attempt_count


def test_stale_token_cannot_heartbeat_new_lease_for_same_worker(
    postgres_heartbeat_context: _PostgresHeartbeatContext,
) -> None:
    first_lease_time = datetime(2035, 11, 12, 13, 14, 15, tzinfo=UTC)
    second_lease_time = first_lease_time + timedelta(seconds=10)
    execution_time = second_lease_time + timedelta(seconds=5)
    renewal_time = second_lease_time + timedelta(seconds=10)
    worker_id = "worker-reused"
    job_id = _submit_job(postgres_heartbeat_context, "c" * 64)
    first_token = UUID("00000000-0000-4000-8000-000000000040")
    second_token = UUID("00000000-0000-4000-8000-000000000041")

    first_lease = JobLeasingService(
        postgres_heartbeat_context.session_factory,
        clock=lambda: first_lease_time,
        token_factory=lambda: first_token,
    ).lease_next_job(worker_id, lease_seconds=60)
    assert first_lease is not None
    assert first_lease.lease_token == str(first_token)

    with postgres_heartbeat_context.session_factory.begin() as session:
        row = session.get(JobRow, job_id)
        assert row is not None
        row.status = JobStatus.QUEUED.value
        row.leased_by = None
        row.lease_token = None
        row.lease_expires_at = None
        row.heartbeat_at = None
        row.available_at = second_lease_time

    second_lease = JobLeasingService(
        postgres_heartbeat_context.session_factory,
        clock=lambda: second_lease_time,
        token_factory=lambda: second_token,
    ).lease_next_job(worker_id, lease_seconds=60)
    assert second_lease is not None
    assert second_lease.lease_token == str(second_token)
    assert second_lease.lease_token != first_lease.lease_token

    started = JobExecutionService(
        postgres_heartbeat_context.session_factory,
        clock=lambda: execution_time,
    ).start_job(job_id, worker_id, second_lease.lease_token)
    before_heartbeat = started.heartbeat_at
    before_expiry = started.lease_expires_at

    service = JobHeartbeatService(
        postgres_heartbeat_context.session_factory,
        clock=lambda: renewal_time,
    )
    with pytest.raises(JobLeaseTokenMismatchError):
        service.renew_lease(
            job_id,
            worker_id,
            first_lease.lease_token,
            lease_seconds=90,
        )

    with postgres_heartbeat_context.session_factory() as session:
        persisted = session.get(JobRow, job_id)
        assert persisted is not None
        assert persisted.lease_token == second_lease.lease_token
        assert persisted.heartbeat_at == before_heartbeat
        assert persisted.lease_expires_at == before_expiry

    renewed = service.renew_lease(
        job_id,
        worker_id,
        second_lease.lease_token,
        lease_seconds=90,
    )
    assert renewed.status is JobStatus.RUNNING
    assert renewed.lease_token == second_lease.lease_token
    assert renewed.heartbeat_at == renewal_time
    assert renewed.lease_expires_at == renewal_time + timedelta(seconds=90)


def test_concurrent_heartbeats_keep_monotonic_expiry_and_timestamps(
    postgres_heartbeat_context: _PostgresHeartbeatContext,
) -> None:
    lease_time = datetime(2035, 12, 13, 14, 15, 16, tzinfo=UTC)
    execution_time = lease_time + timedelta(seconds=5)
    earlier_time = lease_time + timedelta(seconds=10)
    later_time = lease_time + timedelta(seconds=20)
    later_candidate_expiry = later_time + timedelta(seconds=150)
    worker_id = "concurrent-heartbeat-worker"
    job_id = _submit_job(postgres_heartbeat_context, "d" * 64)

    leased = JobLeasingService(
        postgres_heartbeat_context.session_factory,
        clock=lambda: lease_time,
    ).lease_next_job(worker_id, lease_seconds=120)
    assert leased is not None
    assert leased.lease_token is not None
    JobExecutionService(
        postgres_heartbeat_context.session_factory,
        clock=lambda: execution_time,
    ).start_job(job_id, worker_id, leased.lease_token)

    services_and_durations = [
        (
            JobHeartbeatService(
                postgres_heartbeat_context.session_factory,
                clock=lambda: earlier_time,
            ),
            30,
        ),
        (
            JobHeartbeatService(
                postgres_heartbeat_context.session_factory,
                clock=lambda: later_time,
            ),
            150,
        ),
    ]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                service.renew_lease,
                job_id,
                worker_id,
                leased.lease_token,
                lease_seconds,
            )
            for service, lease_seconds in services_and_durations
        ]
        results = [future.result(timeout=5) for future in futures]

    assert all(isinstance(result, JobRecord) for result in results)
    assert all(result.status is JobStatus.RUNNING for result in results)

    with postgres_heartbeat_context.session_factory() as session:
        persisted = session.get(JobRow, job_id)
        assert persisted is not None
        assert persisted.status == JobStatus.RUNNING.value
        assert persisted.heartbeat_at == later_time
        assert persisted.updated_at >= later_time
        assert persisted.lease_expires_at == later_candidate_expiry
        assert persisted.leased_by == worker_id
        assert persisted.lease_token == leased.lease_token
        assert persisted.attempt_count == 1

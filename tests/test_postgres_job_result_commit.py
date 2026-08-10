from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import get_settings
from securescan.domain.enums import ExecutionOutcome, JobStatus, RunStatus, TargetType
from securescan.domain.models import ScanReport, TargetProfile
from securescan.jobs import (
    JobExecutionService,
    JobLeasingService,
    JobRecord,
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
)

pytestmark = pytest.mark.postgres

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"
LEASE_TIME = datetime(2037, 2, 3, 4, 5, 6, tzinfo=UTC)
EXECUTION_TIME = LEASE_TIME + timedelta(seconds=5)
COMMIT_TIME = LEASE_TIME + timedelta(seconds=10)


@dataclass(frozen=True, slots=True)
class _PostgresResultContext:
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
            "skipping PostgreSQL result-commit integration test"
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
def postgres_result_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresResultContext]:
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
            project = ProjectRow(name="PostgreSQL result commit test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="a" * 64,
                source_path="/tmp/postgres-result-target",
            )
            session.add(target)
            session.flush()
            target_id = target.id
        yield _PostgresResultContext(session_factory, target_id)
    finally:
        if engine is not None:
            engine.dispose()
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def _prepare_running_job(
    context: _PostgresResultContext,
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


def _report_json(
    run_id: str,
    status: RunStatus,
    result_name: str,
) -> dict[str, Any]:
    return ScanReport(
        run_id=UUID(run_id),
        target=TargetProfile(
            target_type=TargetType.SOURCE_REPOSITORY,
            path=Path("/tmp/postgres-result-target"),
            content_digest="a" * 64,
            metadata={"result_name": result_name},
        ),
        status=status,
        executions=[],
        observations=[],
        generated_at=COMMIT_TIME,
    ).model_dump(mode="json")


def _request(
    running: _RunningJob,
    final_status: JobStatus,
    result_name: str,
) -> JobResultCommitRequest:
    partial = final_status is JobStatus.PARTIAL
    return JobResultCommitRequest(
        job_id=running.job_id,
        worker_id=running.worker_id,
        lease_token=running.lease_token,
        final_status=final_status,
        report_json=_report_json(
            running.run_id,
            RunStatus.PARTIAL if partial else RunStatus.COMPLETED,
            result_name,
        ),
        tool_execution=ToolExecutionCommit(
            tool_version="1.2.3",
            adapter_version="2.3.4",
            outcome=(
                ExecutionOutcome.PARTIAL_ANALYSIS.value
                if partial
                else ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value
            ),
            exit_code=2 if partial else 0,
            duration_ms=250,
            warning_json=[{"code": "partial"}] if partial else [],
            error="Incomplete analysis" if partial else None,
        ),
    )


def _assert_committed_records(
    context: _PostgresResultContext,
    result: JobResultCommitResult,
    final_status: JobStatus,
) -> None:
    with context.session_factory() as session:
        job = session.get(JobRow, result.job.id)
        run = session.get(AnalysisRunRow, result.run_id)
        executions = session.scalars(
            select(ToolExecutionRow).where(ToolExecutionRow.job_id == result.job.id)
        ).all()
        assert job is not None
        assert job.status == final_status.value
        assert job.leased_by is None
        assert job.lease_token is None
        assert job.lease_expires_at is None
        assert job.attempt_count == 1
        assert len(executions) == 1
        assert executions[0].id == result.tool_execution_id
        assert executions[0].job_id == result.job.id
        assert executions[0].attempt_number == result.attempt_number == 1
        assert run is not None
        expected_run_status = (
            RunStatus.PARTIAL if final_status is JobStatus.PARTIAL else RunStatus.COMPLETED
        )
        assert run.status == expected_run_status.value
        assert run.report_json == result.report_json


def test_postgres_succeeded_result_commits_all_records(
    postgres_result_context: _PostgresResultContext,
) -> None:
    running = _prepare_running_job(
        postgres_result_context,
        "b" * 64,
        "postgres-succeeded-worker",
    )
    result = JobResultCommitService(
        postgres_result_context.session_factory,
        clock=lambda: COMMIT_TIME,
    ).commit_result(_request(running, JobStatus.SUCCEEDED, "succeeded"))

    assert result.job.status is JobStatus.SUCCEEDED
    assert result.run_id == running.run_id
    _assert_committed_records(postgres_result_context, result, JobStatus.SUCCEEDED)


def test_postgres_partial_result_commits_all_records(
    postgres_result_context: _PostgresResultContext,
) -> None:
    running = _prepare_running_job(
        postgres_result_context,
        "c" * 64,
        "postgres-partial-worker",
    )
    result = JobResultCommitService(
        postgres_result_context.session_factory,
        clock=lambda: COMMIT_TIME,
    ).commit_result(_request(running, JobStatus.PARTIAL, "partial"))

    assert result.job.status is JobStatus.PARTIAL
    _assert_committed_records(postgres_result_context, result, JobStatus.PARTIAL)


def test_concurrent_result_commits_commit_exactly_once(
    postgres_result_context: _PostgresResultContext,
) -> None:
    running = _prepare_running_job(
        postgres_result_context,
        "d" * 64,
        "postgres-concurrent-worker",
    )
    services = [
        JobResultCommitService(
            postgres_result_context.session_factory,
            clock=lambda: COMMIT_TIME,
        )
        for _ in range(2)
    ]
    requests = [
        _request(running, JobStatus.SUCCEEDED, "succeeded"),
        _request(running, JobStatus.PARTIAL, "partial"),
    ]
    outcomes: list[JobResultCommitResult | JobStateConflictError] = []

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(service.commit_result, request)
            for service, request in zip(services, requests, strict=True)
        ]
        for future in futures:
            try:
                outcomes.append(future.result(timeout=5))
            except JobStateConflictError as exc:
                outcomes.append(exc)

    successful = [
        outcome for outcome in outcomes if isinstance(outcome, JobResultCommitResult)
    ]
    conflicts = [outcome for outcome in outcomes if isinstance(outcome, JobStateConflictError)]
    assert len(successful) == 1
    assert len(conflicts) == 1
    winner = successful[0]
    _assert_committed_records(postgres_result_context, winner, winner.job.status)
    with postgres_result_context.session_factory() as session:
        run = session.get(AnalysisRunRow, running.run_id)
        assert run is not None
        assert run.report_json["target"]["metadata"]["result_name"] == (
            "partial" if winner.job.status is JobStatus.PARTIAL else "succeeded"
        )


def test_postgres_execution_constraint_failure_rolls_back_everything(
    postgres_result_context: _PostgresResultContext,
) -> None:
    running = _prepare_running_job(
        postgres_result_context,
        "e" * 64,
        "postgres-rollback-worker",
    )
    with postgres_result_context.session_factory.begin() as session:
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
        )
        session.add(conflicting)
        session.flush()
        conflicting_id = conflicting.id

    service = JobResultCommitService(
        postgres_result_context.session_factory,
        clock=lambda: COMMIT_TIME,
    )
    with pytest.raises(JobResultCommitError):
        service.commit_result(_request(running, JobStatus.SUCCEEDED, "rollback"))

    with postgres_result_context.session_factory() as session:
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
        assert run.report_json is None
        assert run.status == RunStatus.RUNNING.value
        assert [execution.id for execution in executions] == [conflicting_id]

    with postgres_result_context.session_factory.begin() as session:
        conflicting = session.get(ToolExecutionRow, conflicting_id)
        assert conflicting is not None
        session.delete(conflicting)

    result = service.commit_result(_request(running, JobStatus.SUCCEEDED, "recovered"))
    assert result.job.status is JobStatus.SUCCEEDED

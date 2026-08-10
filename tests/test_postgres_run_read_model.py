from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import get_settings
from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    RunStatus,
    TargetType,
)
from securescan.domain.models import ScanReport, TargetProfile
from securescan.jobs import (
    FailedToolExecutionCommit,
    JobExecutionService,
    JobFailureCommitRequest,
    JobFailureCommitService,
    JobLeasingService,
    JobResultCommitRequest,
    JobResultCommitService,
    JobRetryPromotionService,
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
from securescan.runs import RunQueryService, recompute_analysis_run_status

pytestmark = pytest.mark.postgres

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"
BASE_TIME = datetime(2049, 2, 3, 4, 5, 6, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _PostgresRunContext:
    session_factory: sessionmaker[Session]
    target_id: str


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL run read-model integration test"
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
def postgres_run_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresRunContext]:
    database_url = _validated_test_database_url()
    config = Config(str(ALEMBIC_INI_PATH))
    config.set_main_option("script_location", str(MIGRATIONS_PATH))
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()
    engine: Engine | None = None
    try:
        _reset_public_schema(database_url)
        command.upgrade(config, "head")
        engine, factory = create_session_factory(get_settings())
        with factory.begin() as session:
            project = ProjectRow(name="PostgreSQL run read model test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="9" * 64,
                source_path="/tmp/postgres-run-read-model",
            )
            session.add(target)
            session.flush()
            target_id = target.id
        yield _PostgresRunContext(factory, target_id)
    finally:
        if engine is not None:
            engine.dispose()
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def _report(run_id: str, marker: str) -> dict[str, Any]:
    return ScanReport(
        run_id=UUID(run_id),
        target=TargetProfile(
            target_type=TargetType.SOURCE_REPOSITORY,
            path=Path("/tmp/postgres-run-read-model"),
            content_digest="9" * 64,
            metadata={"marker": marker},
        ),
        status=RunStatus.COMPLETED,
        executions=[],
        observations=[],
        generated_at=BASE_TIME + timedelta(seconds=10),
    ).model_dump(mode="json")


def _create_two_running_jobs(
    context: _PostgresRunContext,
) -> tuple[str, tuple[JobRow, JobRow]]:
    with context.session_factory.begin() as session:
        run = AnalysisRunRow(
            target_id=context.target_id,
            status=RunStatus.RUNNING.value,
            created_at=BASE_TIME,
        )
        jobs = tuple(
            JobRow(
                id=str(uuid4()),
                run=run,
                adapter_id=f"adapter-{index}",
                status=JobStatus.RUNNING.value,
                attempt_count=1,
                max_attempts=3,
                available_at=BASE_TIME,
                leased_by=f"worker-{index}",
                lease_token=str(uuid4()),
                lease_expires_at=BASE_TIME + timedelta(seconds=60),
                heartbeat_at=BASE_TIME,
                idempotency_key=str(index) * 64,
                payload_json={},
                created_at=BASE_TIME + timedelta(microseconds=index),
                updated_at=BASE_TIME,
                started_at=BASE_TIME,
            )
            for index in (1, 2)
        )
        session.add_all(jobs)
        session.flush()
        run_id = run.id
    return run_id, jobs


def _result_request(job: JobRow, run_id: str, marker: str) -> JobResultCommitRequest:
    assert job.lease_token is not None
    assert job.leased_by is not None
    return JobResultCommitRequest(
        job_id=job.id,
        worker_id=job.leased_by,
        lease_token=job.lease_token,
        final_status=JobStatus.SUCCEEDED,
        report_json=_report(run_id, marker),
        tool_execution=ToolExecutionCommit(
            tool_version="1",
            adapter_version="1",
            outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
            exit_code=0,
            duration_ms=10,
            warning_json=[],
        ),
    )


def _failure_request(
    job: JobRow,
    *,
    retryable: bool = False,
) -> JobFailureCommitRequest:
    assert job.lease_token is not None
    assert job.leased_by is not None
    return JobFailureCommitRequest(
        job_id=job.id,
        worker_id=job.leased_by,
        lease_token=job.lease_token,
        tool_execution=FailedToolExecutionCommit(
            tool_version="1",
            adapter_version="1",
            outcome=ExecutionOutcome.INTERNAL_ERROR.value,
            exit_code=1,
            duration_ms=10,
            warning_json=[],
            error="Controlled permanent failure.",
            failure_category=(
                JobFailureCategory.RETRYABLE_INFRASTRUCTURE
                if retryable
                else JobFailureCategory.NON_RETRYABLE_INPUT
            ),
            retryable=retryable,
        ),
    )


def test_postgres_concurrent_successful_jobs_aggregate_to_completed(
    postgres_run_context: _PostgresRunContext,
) -> None:
    run_id, jobs = _create_two_running_jobs(postgres_run_context)
    services = [
        JobResultCommitService(
            postgres_run_context.session_factory,
            clock=lambda: BASE_TIME + timedelta(seconds=10),
        )
        for _ in jobs
    ]
    requests = [
        _result_request(job, run_id, f"result-{index}") for index, job in enumerate(jobs, start=1)
    ]

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(service.commit_result, request)
            for service, request in zip(services, requests, strict=True)
        ]
        results = [future.result(timeout=5) for future in futures]

    with postgres_run_context.session_factory() as session:
        run = session.get(AnalysisRunRow, run_id)
        persisted_jobs = list(session.scalars(select(JobRow).where(JobRow.run_id == run_id)))
        executions = list(
            session.scalars(select(ToolExecutionRow).where(ToolExecutionRow.run_id == run_id))
        )
        assert run is not None
        assert len(results) == 2
        assert all(job.status == JobStatus.SUCCEEDED.value for job in persisted_jobs)
        assert run.status == RunStatus.COMPLETED.value
        assert len(executions) == 2


def test_postgres_success_and_failure_aggregate_to_partial(
    postgres_run_context: _PostgresRunContext,
) -> None:
    run_id, jobs = _create_two_running_jobs(postgres_run_context)
    success_service = JobResultCommitService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=10),
    )
    failure_service = JobFailureCommitService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=10),
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        success = executor.submit(
            success_service.commit_result,
            _result_request(jobs[0], run_id, "success"),
        )
        failure = executor.submit(
            failure_service.commit_failure,
            _failure_request(jobs[1]),
        )
        success.result(timeout=5)
        failure.result(timeout=5)

    with postgres_run_context.session_factory() as session:
        run = session.get(AnalysisRunRow, run_id)
        statuses = set(session.scalars(select(JobRow.status).where(JobRow.run_id == run_id)))
        executions = list(
            session.scalars(select(ToolExecutionRow).where(ToolExecutionRow.run_id == run_id))
        )
        assert run is not None
        assert statuses == {JobStatus.SUCCEEDED.value, JobStatus.FAILED.value}
        assert run.status == RunStatus.PARTIAL.value
        assert len(executions) == 2


def test_postgres_active_child_prevents_terminal_run_status(
    postgres_run_context: _PostgresRunContext,
) -> None:
    run_id, jobs = _create_two_running_jobs(postgres_run_context)

    JobResultCommitService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=10),
    ).commit_result(_result_request(jobs[0], run_id, "one-complete"))

    with postgres_run_context.session_factory() as session:
        run = session.get(AnalysisRunRow, run_id)
        active = session.get(JobRow, jobs[1].id)
        assert run is not None
        assert active is not None
        assert active.status == JobStatus.RUNNING.value
        assert run.status == RunStatus.RUNNING.value


@pytest.mark.parametrize(
    ("scenario", "expected_status"),
    [
        ("success_and_failure", RunStatus.PARTIAL),
        ("success_and_retry", RunStatus.QUEUED),
        ("both_success", RunStatus.COMPLETED),
    ],
)
def test_concurrent_sibling_job_transitions_produce_order_independent_run_status(
    postgres_run_context: _PostgresRunContext,
    scenario: str,
    expected_status: RunStatus,
) -> None:
    run_id, jobs = _create_two_running_jobs(postgres_run_context)
    success_services = [
        JobResultCommitService(
            postgres_run_context.session_factory,
            clock=lambda: BASE_TIME + timedelta(seconds=10),
        )
        for _ in jobs
    ]
    failure_service = JobFailureCommitService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=10),
        retry_delay_seconds=lambda _attempt: 5,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            success_services[0].commit_result,
            _result_request(jobs[0], run_id, f"{scenario}-first"),
        )
        if scenario == "both_success":
            second = executor.submit(
                success_services[1].commit_result,
                _result_request(jobs[1], run_id, f"{scenario}-second"),
            )
        else:
            second = executor.submit(
                failure_service.commit_failure,
                _failure_request(
                    jobs[1],
                    retryable=scenario == "success_and_retry",
                ),
            )
        first.result(timeout=5)
        second.result(timeout=5)

    with postgres_run_context.session_factory() as session:
        run = session.get(AnalysisRunRow, run_id)
        statuses = set(session.scalars(select(JobRow.status).where(JobRow.run_id == run_id)))
        assert run is not None
        assert run.status == expected_status.value
        if scenario == "success_and_failure":
            assert statuses == {JobStatus.SUCCEEDED.value, JobStatus.FAILED.value}
        elif scenario == "success_and_retry":
            assert statuses == {
                JobStatus.SUCCEEDED.value,
                JobStatus.RETRY_PENDING.value,
            }
        else:
            assert statuses == {JobStatus.SUCCEEDED.value}


def test_concurrent_updates_do_not_cross_contaminate_other_runs(
    postgres_run_context: _PostgresRunContext,
) -> None:
    first = JobSubmissionService(postgres_run_context.session_factory).submit(
        JobSubmissionRequest(
            target_id=postgres_run_context.target_id,
            adapter_id="fake-scanner",
            idempotency_key="6" * 64,
        )
    )
    first_lease = JobLeasingService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME,
    ).lease_next_job("isolated-worker-1", lease_seconds=60)
    assert first_lease is not None
    assert first_lease.lease_token is not None
    JobExecutionService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=1),
    ).start_job(first.job_id, "isolated-worker-1", first_lease.lease_token)

    second = JobSubmissionService(postgres_run_context.session_factory).submit(
        JobSubmissionRequest(
            target_id=postgres_run_context.target_id,
            adapter_id="fake-scanner",
            idempotency_key="7" * 64,
        )
    )
    second_lease = JobLeasingService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME,
    ).lease_next_job("isolated-worker-2", lease_seconds=60)
    assert second_lease is not None
    assert second_lease.lease_token is not None
    JobExecutionService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=1),
    ).start_job(second.job_id, "isolated-worker-2", second_lease.lease_token)

    with postgres_run_context.session_factory() as session:
        first_job = session.get(JobRow, first.job_id)
        second_job = session.get(JobRow, second.job_id)
        assert first_job is not None
        assert second_job is not None
        session.expunge(first_job)
        session.expunge(second_job)

    with ThreadPoolExecutor(max_workers=2) as executor:
        success = executor.submit(
            JobResultCommitService(
                postgres_run_context.session_factory,
                clock=lambda: BASE_TIME + timedelta(seconds=10),
            ).commit_result,
            _result_request(first_job, first.run_id, "isolated-success"),
        )
        retry = executor.submit(
            JobFailureCommitService(
                postgres_run_context.session_factory,
                clock=lambda: BASE_TIME + timedelta(seconds=10),
                retry_delay_seconds=lambda _attempt: 5,
            ).commit_failure,
            _failure_request(second_job, retryable=True),
        )
        success.result(timeout=5)
        retry.result(timeout=5)

    with postgres_run_context.session_factory() as session:
        first_run = session.get(AnalysisRunRow, first.run_id)
        second_run = session.get(AnalysisRunRow, second.run_id)
        assert first_run is not None
        assert second_run is not None
        assert first_run.status == RunStatus.COMPLETED.value
        assert second_run.status == RunStatus.QUEUED.value


def test_recompute_ignores_stale_cached_run_state(
    postgres_run_context: _PostgresRunContext,
) -> None:
    submitted = JobSubmissionService(postgres_run_context.session_factory).submit(
        JobSubmissionRequest(
            target_id=postgres_run_context.target_id,
            adapter_id="fake-scanner",
            idempotency_key="5" * 64,
        )
    )
    leased = JobLeasingService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME,
    ).lease_next_job("identity-map-worker", lease_seconds=60)
    assert leased is not None
    assert leased.lease_token is not None
    JobExecutionService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=1),
    ).start_job(submitted.job_id, "identity-map-worker", leased.lease_token)

    with postgres_run_context.session_factory() as stale_session:
        cached_run = stale_session.get(AnalysisRunRow, submitted.run_id)
        job = stale_session.get(JobRow, submitted.job_id)
        assert cached_run is not None
        assert job is not None
        assert cached_run.status == RunStatus.RUNNING.value
        stale_session.expunge(job)

        JobFailureCommitService(
            postgres_run_context.session_factory,
            clock=lambda: BASE_TIME + timedelta(seconds=10),
            retry_delay_seconds=lambda _attempt: 5,
        ).commit_failure(_failure_request(job, retryable=True))

        computed = recompute_analysis_run_status(
            stale_session,
            submitted.run_id,
            changed_at=BASE_TIME + timedelta(seconds=11),
        )
        stale_session.commit()
        assert computed is RunStatus.QUEUED
        assert cached_run.status == RunStatus.QUEUED.value


def test_postgres_run_query_returns_stable_attempt_history(
    postgres_run_context: _PostgresRunContext,
) -> None:
    submitted = JobSubmissionService(postgres_run_context.session_factory).submit(
        JobSubmissionRequest(
            target_id=postgres_run_context.target_id,
            adapter_id="fake-scanner",
            idempotency_key="8" * 64,
            max_attempts=3,
        )
    )
    leased_one = JobLeasingService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME,
    ).lease_next_job("attempt-worker", lease_seconds=60)
    assert leased_one is not None
    assert leased_one.lease_token is not None
    running_one = JobExecutionService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=1),
    ).start_job(submitted.job_id, "attempt-worker", leased_one.lease_token)
    JobFailureCommitService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=2),
        retry_delay_seconds=lambda _attempt: 1,
    ).commit_failure(
        JobFailureCommitRequest(
            job_id=running_one.id,
            worker_id="attempt-worker",
            lease_token=leased_one.lease_token,
            tool_execution=FailedToolExecutionCommit(
                tool_version="1",
                adapter_version="1",
                outcome=ExecutionOutcome.INTERNAL_ERROR.value,
                exit_code=1,
                duration_ms=10,
                warning_json=[],
                error="Controlled retryable failure.",
                failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
                retryable=True,
            ),
        )
    )
    JobRetryPromotionService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=3),
    ).promote_due_retries()
    leased_two = JobLeasingService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=4),
    ).lease_next_job("attempt-worker", lease_seconds=60)
    assert leased_two is not None
    assert leased_two.lease_token is not None
    running_two = JobExecutionService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=5),
    ).start_job(submitted.job_id, "attempt-worker", leased_two.lease_token)
    JobResultCommitService(
        postgres_run_context.session_factory,
        clock=lambda: BASE_TIME + timedelta(seconds=6),
    ).commit_result(
        JobResultCommitRequest(
            job_id=running_two.id,
            worker_id="attempt-worker",
            lease_token=leased_two.lease_token,
            final_status=JobStatus.SUCCEEDED,
            report_json=_report(submitted.run_id, "attempt-two"),
            tool_execution=ToolExecutionCommit(
                tool_version="2",
                adapter_version="2",
                outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
                exit_code=0,
                duration_ms=10,
                warning_json=[],
            ),
        )
    )

    service = RunQueryService(postgres_run_context.session_factory)
    first = service.list_tool_executions(submitted.run_id, limit=1, offset=0)
    second = service.list_tool_executions(submitted.run_id, limit=1, offset=1)
    jobs = service.list_jobs(submitted.run_id)

    assert first.total == second.total == 2
    assert first.items[0].attempt_number == 1
    assert second.items[0].attempt_number == 2
    assert jobs.items[0].created_at.utcoffset() == timedelta(0)
    assert not hasattr(jobs.items[0], "lease_token")
    assert not hasattr(jobs.items[0], "payload_json")

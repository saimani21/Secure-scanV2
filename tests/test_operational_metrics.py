from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    RunStatus,
    TargetType,
)
from securescan.observability.metrics import (
    OperationalMetricsPersistenceError,
    OperationalMetricsService,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    Base,
    JobRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
)

GENERATED_AT = datetime(2051, 2, 3, 4, 5, 6, tzinfo=UTC)


@pytest.fixture
def metrics_database(
    tmp_path: Path,
) -> Iterator[tuple[sessionmaker[Session], str]]:
    engine = create_engine(f"sqlite:///{tmp_path / 'metrics.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        with factory.begin() as session:
            project = ProjectRow(name="Metrics test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="a" * 64,
                source_path="/tmp/metrics",
            )
            session.add(target)
            session.flush()
            target_id = target.id
        yield factory, target_id
    finally:
        engine.dispose()


def _add_run(
    session: Session,
    target_id: str,
    run_status: RunStatus,
    job_statuses: tuple[JobStatus, ...],
) -> AnalysisRunRow:
    run = AnalysisRunRow(
        target_id=target_id,
        status=run_status.value,
        created_at=GENERATED_AT - timedelta(minutes=1),
    )
    for job_status in job_statuses:
        run.jobs.append(
            JobRow(
                adapter_id="fake-scanner",
                status=job_status.value,
                available_at=GENERATED_AT,
                idempotency_key=uuid4().hex + uuid4().hex,
                payload_json={},
                created_at=GENERATED_AT,
                updated_at=GENERATED_AT,
            )
        )
    session.add(run)
    return run


def test_metrics_count_job_and_run_states_correctly(
    metrics_database: tuple[sessionmaker[Session], str],
) -> None:
    factory, target_id = metrics_database
    with factory.begin() as session:
        _add_run(
            session,
            target_id,
            RunStatus.QUEUED,
            (JobStatus.SUBMITTED, JobStatus.QUEUED),
        )
        _add_run(
            session,
            target_id,
            RunStatus.RUNNING,
            (JobStatus.LEASED, JobStatus.RUNNING, JobStatus.RETRY_PENDING),
        )
        _add_run(
            session,
            target_id,
            RunStatus.COMPLETED,
            (JobStatus.SUCCEEDED, JobStatus.PARTIAL),
        )
        _add_run(
            session,
            target_id,
            RunStatus.FAILED,
            (JobStatus.FAILED, JobStatus.CANCELLED),
        )

    snapshot = OperationalMetricsService(
        factory,
        clock=lambda: GENERATED_AT,
    ).collect()

    assert snapshot.total_runs == 4
    assert snapshot.active_runs == 2
    assert snapshot.total_jobs == 9
    assert snapshot.queued_jobs == 2
    assert snapshot.leased_jobs == 1
    assert snapshot.running_jobs == 1
    assert snapshot.retry_pending_jobs == 1
    assert snapshot.succeeded_jobs == 1
    assert snapshot.partial_jobs == 1
    assert snapshot.failed_jobs == 1
    assert snapshot.cancelled_jobs == 1


def test_metrics_count_expired_leases_and_cancellation_requests(
    metrics_database: tuple[sessionmaker[Session], str],
) -> None:
    factory, target_id = metrics_database
    with factory.begin() as session:
        run = _add_run(
            session,
            target_id,
            RunStatus.RUNNING,
            (JobStatus.LEASED, JobStatus.RUNNING, JobStatus.RUNNING),
        )
        run.jobs[0].lease_expires_at = GENERATED_AT - timedelta(seconds=1)
        run.jobs[0].cancel_requested = True
        run.jobs[1].lease_expires_at = GENERATED_AT + timedelta(seconds=1)
        run.jobs[2].lease_expires_at = GENERATED_AT - timedelta(minutes=1)
        run.jobs[2].cancel_requested = True

    snapshot = OperationalMetricsService(
        factory,
        clock=lambda: GENERATED_AT,
    ).collect()

    assert snapshot.expired_active_leases == 2
    assert snapshot.cancellation_requested_jobs == 2
    assert snapshot.generated_at.utcoffset() == timedelta(0)


def test_metrics_summarize_execution_duration_and_failure_categories(
    metrics_database: tuple[sessionmaker[Session], str],
) -> None:
    factory, target_id = metrics_database
    with factory.begin() as session:
        run = _add_run(session, target_id, RunStatus.COMPLETED, ())
        session.flush()
        session.add_all(
            [
                ToolExecutionRow(
                    run_id=run.id,
                    adapter_id="scanner",
                    tool_version="1",
                    adapter_version="1",
                    outcome=ExecutionOutcome.TIMEOUT.value,
                    duration_ms=10,
                    failure_category=JobFailureCategory.TIMEOUT.value,
                    retryable=True,
                ),
                ToolExecutionRow(
                    run_id=run.id,
                    adapter_id="scanner",
                    tool_version="1",
                    adapter_version="1",
                    outcome=ExecutionOutcome.INVALID_OUTPUT.value,
                    duration_ms=30,
                    failure_category=JobFailureCategory.NON_RETRYABLE_PARSER.value,
                    retryable=False,
                ),
                ToolExecutionRow(
                    run_id=run.id,
                    adapter_id="scanner",
                    tool_version="1",
                    adapter_version="1",
                    outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
                    duration_ms=50,
                ),
            ]
        )

    snapshot = OperationalMetricsService(
        factory,
        clock=lambda: GENERATED_AT,
    ).collect()

    assert snapshot.total_tool_executions == 3
    assert snapshot.retryable_tool_failures == 1
    assert snapshot.permanent_tool_failures == 1
    assert snapshot.average_execution_duration_ms == 30.0
    assert snapshot.maximum_execution_duration_ms == 50
    assert snapshot.failures_by_category == {
        JobFailureCategory.NON_RETRYABLE_PARSER.value: 1,
        JobFailureCategory.TIMEOUT.value: 1,
    }
    source_categories = {"z_category": 2, "a_category": 1}
    copied_snapshot = replace(snapshot, failures_by_category=source_categories)
    source_categories["a_category"] = 99
    assert copied_snapshot.failures_by_category == {
        "a_category": 1,
        "z_category": 2,
    }


def test_metrics_persistence_failure_is_generic_and_preserves_cause() -> None:
    sensitive_error = SQLAlchemyError(
        "postgresql://admin:super-secret@database/private SELECT credentials"
    )

    def unavailable_session_factory():
        raise sensitive_error

    service = OperationalMetricsService(
        unavailable_session_factory,
        clock=lambda: GENERATED_AT,
    )

    with pytest.raises(OperationalMetricsPersistenceError) as error:
        service.collect()

    assert str(error.value) == "Operational metrics are temporarily unavailable."
    assert error.value.__cause__ is sensitive_error
    assert "postgresql://" not in str(error.value)
    assert "super-secret" not in str(error.value)

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    RunStatus,
    TargetType,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    Base,
    JobRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
)
from securescan.runs import (
    RunNotFoundError,
    RunQueryService,
    RunReportNotReadyError,
)

NOW = datetime(2047, 2, 3, 4, 5, 6, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _QueryContext:
    session_factory: sessionmaker[Session]
    run_id: str
    job_ids: tuple[str, str]


@pytest.fixture
def run_query_context(tmp_path: Path) -> _QueryContext:
    engine = create_engine(f"sqlite:///{tmp_path / 'run-query.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory.begin() as session:
        project = ProjectRow(name="Run query test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="a" * 64,
            source_path="/tmp/run-query",
        )
        run = AnalysisRunRow(
            target=target,
            status=RunStatus.PARTIAL.value,
            report_json={"schema_version": "1.0.0", "nested": {"safe": True}},
            created_at=NOW,
        )
        job_a = JobRow(
            id=str(uuid4()),
            run=run,
            adapter_id="adapter-a",
            status=JobStatus.SUCCEEDED.value,
            idempotency_key="a" * 64,
            payload_json={"secret": "hidden"},
            created_at=NOW,
            updated_at=NOW,
            available_at=NOW,
            attempt_count=1,
        )
        job_b = JobRow(
            id=str(uuid4()),
            run=run,
            adapter_id="adapter-b",
            status=JobStatus.FAILED.value,
            idempotency_key="b" * 64,
            payload_json={"secret": "hidden"},
            created_at=NOW + timedelta(seconds=1),
            updated_at=NOW + timedelta(seconds=1),
            available_at=NOW,
            attempt_count=2,
            finished_at=NOW + timedelta(seconds=2),
        )
        session.add_all(
            [
                ToolExecutionRow(
                    run=run,
                    job_id=job_b.id,
                    attempt_number=2,
                    adapter_id="adapter-b",
                    adapter_version="2",
                    tool_version="2",
                    outcome=ExecutionOutcome.INTERNAL_ERROR.value,
                    exit_code=1,
                    duration_ms=20,
                    warning_json=[{"raw": "hidden"}],
                    error="safe fixed error",
                    failure_category=(JobFailureCategory.NON_RETRYABLE_INPUT.value),
                    retryable=False,
                ),
                ToolExecutionRow(
                    run=run,
                    job_id=job_a.id,
                    attempt_number=1,
                    adapter_id="adapter-a",
                    adapter_version="1",
                    tool_version="1",
                    outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
                    exit_code=0,
                    duration_ms=10,
                    warning_json=[],
                ),
            ]
        )
        session.flush()
        context = _QueryContext(factory, run.id, (job_a.id, job_b.id))
    try:
        yield context
    finally:
        engine.dispose()


def test_get_run_returns_detached_counts_and_utc_timestamps(
    run_query_context: _QueryContext,
) -> None:
    record = RunQueryService(run_query_context.session_factory).get_run(run_query_context.run_id)

    assert record.status is RunStatus.PARTIAL
    assert record.total_jobs == 2
    assert record.active_jobs == 0
    assert record.succeeded_jobs == 1
    assert record.failed_jobs == 1
    assert record.created_at.utcoffset() == timedelta(0)
    assert record.has_report is True


def test_list_jobs_is_stable_paginated_and_hides_private_fields_by_model(
    run_query_context: _QueryContext,
) -> None:
    service = RunQueryService(run_query_context.session_factory)

    first = service.list_jobs(run_query_context.run_id, limit=1, offset=0)
    second = service.list_jobs(run_query_context.run_id, limit=1, offset=1)

    assert first.total == second.total == 2
    assert first.items[0].job_id == run_query_context.job_ids[0]
    assert second.items[0].job_id == run_query_context.job_ids[1]
    assert first.items[0].created_at.utcoffset() == timedelta(0)
    for private_field in (
        "lease_token",
        "leased_by",
        "payload_json",
        "idempotency_key",
        "last_error",
    ):
        assert not hasattr(first.items[0], private_field)


def test_list_executions_orders_attempt_history_deterministically(
    run_query_context: _QueryContext,
) -> None:
    result = RunQueryService(run_query_context.session_factory).list_tool_executions(
        run_query_context.run_id
    )

    assert result.total == 2
    assert [item.attempt_number for item in result.items] == [1, 2]
    assert not hasattr(result.items[1], "warning_json")
    assert not hasattr(result.items[1], "error")


def test_get_report_returns_defensive_copy(
    run_query_context: _QueryContext,
) -> None:
    service = RunQueryService(run_query_context.session_factory)

    report = service.get_report(run_query_context.run_id)
    report.report_json["nested"]["safe"] = False
    again = service.get_report(run_query_context.run_id)

    assert again.report_json["nested"]["safe"] is True
    with run_query_context.session_factory() as session:
        persisted = session.get(AnalysisRunRow, run_query_context.run_id)
        assert persisted is not None
        assert persisted.report_json["nested"]["safe"] is True


def test_missing_run_and_unready_report_raise_specific_errors(
    run_query_context: _QueryContext,
) -> None:
    service = RunQueryService(run_query_context.session_factory)
    with pytest.raises(RunNotFoundError):
        service.get_run(str(uuid4()))

    with run_query_context.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, run_query_context.run_id)
        assert run is not None
        run.report_json = None
    with pytest.raises(RunReportNotReadyError):
        service.get_report(run_query_context.run_id)

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from test_source_dependency_evaluation_s6ca import (
    _finish_existing_syft,
    _nodes,
    _observation,
)
from test_source_orchestration_s6a import _RUN_ID
from test_source_orchestration_s6b import _LEASE_TOKEN, _Environment

from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
)
from securescan.orchestration.coordinator import (
    SourceOrchestrationCoordinatorService,
)
from securescan.orchestration.dependency_evaluation import SourceDependencyEvaluationError
from securescan.orchestration.execution_models import SourceScannerFailureCode
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    OrchestrationNodeDisposition,
    SourceAuthority,
    frozen_source_v1_authority_roster,
)
from securescan.orchestration.service import orchestration_request_digest
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
)

_DEADLINE = datetime(2099, 1, 1, tzinfo=UTC)


@pytest.fixture
def environment(tmp_path: Path):
    value = _Environment(tmp_path)
    with value.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert parent is not None and run is not None
        parent.deadline_at = _DEADLINE
        parent.creation_request_digest = orchestration_request_digest(
            target_id=run.target_id,
            idempotency_key=parent.idempotency_key,
            deadline_iso=_DEADLINE.isoformat(),
            profile_digest=parent.profile_digest,
            plan_digest=parent.plan_digest,
            roster_digest=parent.roster_digest,
        )
    try:
        yield value
    finally:
        value.close()


def _coordinator(environment: _Environment) -> SourceOrchestrationCoordinatorService:
    return SourceOrchestrationCoordinatorService(
        environment.factory,
        environment.store,
        frozen_source_v1_authority_roster(),
        environment.projections,
    )


def test_coordinator_schedules_exactly_four_initial_jobs_then_one_osv_job(
    environment: _Environment,
) -> None:
    coordinator = _coordinator(environment)
    first = coordinator.advance(run_id=str(_RUN_ID), workspace=environment.workspace)
    second = coordinator.advance(run_id=str(_RUN_ID), workspace=environment.workspace)
    assert len(first.jobs_created) == 4
    assert second.jobs_created == ()

    syft, osv = _nodes(environment)
    _node, syft_job, _attempt = environment.start_attempt(SourceAuthority.SYFT)
    observation = _observation(syft_job, syft, ("requirements.lock",))
    _finish_existing_syft(environment, syft, syft_job, (observation,))
    dependency = coordinator.advance(
        run_id=str(_RUN_ID), workspace=environment.workspace
    )
    assert len(dependency.jobs_created) == 1
    with environment.factory() as session:
        mappings = tuple(
            session.scalars(
                select(SourceOrchestrationScannerJobRow).where(
                    SourceOrchestrationScannerJobRow.run_id == str(_RUN_ID)
                )
            )
        )
        assert len(mappings) == 5
        osv_mapping = next(item for item in mappings if item.node_id == osv.node_id)
        assert osv_mapping.input_kind == "OSV_DEPENDENCY_INPUT"


def test_zero_package_syft_makes_osv_not_applicable_without_osv_job(
    environment: _Environment,
) -> None:
    coordinator = _coordinator(environment)
    coordinator.advance(run_id=str(_RUN_ID), workspace=environment.workspace)
    _syft, osv = _nodes(environment)
    node, syft_job, _attempt = environment.start_attempt(SourceAuthority.SYFT)
    _finish_existing_syft(environment, node, syft_job, ())
    coordinator.advance(run_id=str(_RUN_ID), workspace=environment.workspace)
    with environment.factory() as session:
        durable = session.get(SourceOrchestrationNodeRow, osv.node_id)
        assert durable is not None
        assert durable.terminal_disposition == OrchestrationNodeDisposition.NOT_APPLICABLE.value
        assert durable.terminal_reason_code == "NO_PACKAGES_OBSERVED"
        assert (
            session.scalar(
                select(func.count())
                .select_from(SourceOrchestrationScannerJobRow)
                .where(SourceOrchestrationScannerJobRow.node_id == osv.node_id)
            )
            == 0
        )


def test_permanent_syft_failure_blocks_osv_without_creating_osv_job(
    environment: _Environment,
) -> None:
    coordinator = _coordinator(environment)
    coordinator.advance(run_id=str(_RUN_ID), workspace=environment.workspace)
    _syft, osv = _nodes(environment)
    _node, syft_job, attempt = environment.start_attempt(SourceAuthority.SYFT)
    environment.attempts.record_failure(
        job_id=syft_job.job_id,
        attempt_number=attempt.attempt_number,
        attempt_token=attempt.attempt_token,
        lease_token=_LEASE_TOKEN,
        failure_code=SourceScannerFailureCode.PARSER_FAILURE,
        failure_category=JobFailureCategory.NON_RETRYABLE_PARSER,
        execution_outcome=ExecutionOutcome.INVALID_OUTPUT,
        return_code=2,
        duration_ms=1,
        retryable=False,
    )

    coordinator.advance(run_id=str(_RUN_ID), workspace=environment.workspace)
    with environment.factory() as session:
        durable = session.get(SourceOrchestrationNodeRow, osv.node_id)
        assert durable is not None
        assert (
            durable.terminal_disposition
            == OrchestrationNodeDisposition.BLOCKED_BY_DEPENDENCY.value
        )
        assert durable.terminal_reason_code == "SYFT_FAILED"
        assert (
            session.scalar(
                select(func.count())
                .select_from(SourceOrchestrationScannerJobRow)
                .where(SourceOrchestrationScannerJobRow.node_id == osv.node_id)
            )
            == 0
        )


def test_deterministic_dependency_evaluation_failure_terminalizes_osv(
    environment: _Environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    coordinator = _coordinator(environment)
    coordinator.advance(run_id=str(_RUN_ID), workspace=environment.workspace)
    syft, osv = _nodes(environment)
    _node, syft_job, _attempt = environment.start_attempt(SourceAuthority.SYFT)
    observation = _observation(syft_job, syft, ("requirements.lock",))
    _finish_existing_syft(environment, syft, syft_job, (observation,))

    def fail_evaluation(*, run_id: str, osv_node_id: str) -> None:
        assert run_id == str(_RUN_ID)
        assert osv_node_id == osv.node_id
        raise SourceDependencyEvaluationError

    monkeypatch.setattr(coordinator._evaluations, "evaluate", fail_evaluation)
    result = coordinator.advance(run_id=str(_RUN_ID), workspace=environment.workspace)

    assert result.state_changed is True
    with environment.factory() as session:
        durable = session.get(SourceOrchestrationNodeRow, osv.node_id)
        assert durable is not None
        assert (
            durable.lifecycle_state,
            durable.terminal_disposition,
            durable.terminal_reason_code,
        ) == ("TERMINAL", "FAILED", "DEPENDENCY_EVALUATION_FAILED")
        assert (
            session.scalar(
                select(func.count())
                .select_from(SourceOrchestrationScannerJobRow)
                .where(SourceOrchestrationScannerJobRow.node_id == osv.node_id)
            )
            == 0
        )


def test_parent_cancellation_is_idempotent_and_never_publishes(
    environment: _Environment,
) -> None:
    coordinator = _coordinator(environment)
    first = coordinator.request_cancellation(str(_RUN_ID))
    second = coordinator.request_cancellation(str(_RUN_ID))
    assert first.lifecycle_state is OrchestrationLifecycleState.TERMINAL
    assert second.lifecycle_state is OrchestrationLifecycleState.TERMINAL
    with environment.factory() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        nodes = tuple(
            session.scalars(
                select(SourceOrchestrationNodeRow).where(
                    SourceOrchestrationNodeRow.run_id == str(_RUN_ID)
                )
            )
        )
        assert run is not None and run.report_json is None
        assert all(
            item.terminal_disposition == OrchestrationNodeDisposition.CANCELLED.value
            for item in nodes
        )


def test_generic_retry_promoter_cannot_act_on_source_jobs(
    environment: _Environment,
) -> None:
    coordinator = _coordinator(environment)
    coordinator.advance(run_id=str(_RUN_ID), workspace=environment.workspace)
    with environment.factory.begin() as session:
        mapping = session.scalar(select(SourceOrchestrationScannerJobRow))
        assert mapping is not None
        job = session.get(JobRow, mapping.job_id)
        node = session.get(SourceOrchestrationNodeRow, mapping.node_id)
        assert job is not None and node is not None
        job.status = JobStatus.RETRY_PENDING.value
        job.attempt_count = 1
        job.available_at = datetime(2000, 1, 1, tzinfo=UTC)
        node.lifecycle_state = "RETRY_PENDING"
    # No fabricated attempt means the orchestration-aware promoter fails closed.
    result = coordinator.advance(run_id=str(_RUN_ID), workspace=environment.workspace)
    assert result.retries_promoted == ()


def test_source_retry_uses_durable_attempt_completion_backoff(
    environment: _Environment,
) -> None:
    coordinator = _coordinator(environment)
    _node, job, attempt = environment.start_attempt(SourceAuthority.GITLEAKS)
    environment.attempts.record_failure(
        job_id=job.job_id,
        attempt_number=attempt.attempt_number,
        attempt_token=attempt.attempt_token,
        lease_token=_LEASE_TOKEN,
        failure_code=SourceScannerFailureCode.EXECUTION_FAILURE,
        failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
        execution_outcome=ExecutionOutcome.INTERNAL_ERROR,
        return_code=2,
        duration_ms=1,
        retryable=True,
    )
    with environment.factory.begin() as session:
        durable_job = session.get(JobRow, job.job_id)
        attempt_row = session.get(SourceOrchestrationAttemptRow, (job.job_id, 1))
        assert durable_job is not None and attempt_row is not None
        durable_job.available_at = datetime(2000, 1, 1, tzinfo=UTC)
        attempt_row.finished_at = datetime(2098, 1, 1, tzinfo=UTC)

    immediate = coordinator.advance(run_id=str(_RUN_ID))
    assert immediate.retries_promoted == ()
    with environment.factory.begin() as session:
        durable_job = session.get(JobRow, job.job_id)
        assert durable_job is not None
        attempt_row = session.get(SourceOrchestrationAttemptRow, (job.job_id, 1))
        assert attempt_row is not None and attempt_row.finished_at is not None
        durable_job.available_at = datetime(2000, 1, 1, tzinfo=UTC)
        attempt_row.finished_at = datetime(2000, 1, 1, tzinfo=UTC)

    promoted = coordinator.advance(run_id=str(_RUN_ID))
    assert promoted.retries_promoted == (job.job_id,)

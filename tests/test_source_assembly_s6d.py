from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy import select

from securescan.domain.enums import ExecutionOutcome, JobStatus
from securescan.orchestration.assembly import (
    SourceResultAssemblyError,
    SourceResultAssemblyService,
)
from securescan.orchestration.coordinator import SourceOrchestrationCoordinatorService
from securescan.orchestration.execution import SourceScannerAttemptService
from securescan.orchestration.execution_models import (
    AttemptContainmentOutcome,
    SourceSandboxCleanupReceipt,
    source_sandbox_execution_identity,
)
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    OrchestrationTerminalOutcome,
    SourceAuthority,
    frozen_source_v1_authority_roster,
    orchestration_request_digest,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
)
from tests.test_source_orchestration_s6b import (
    _DEADLINE,
    _LEASE_TOKEN,
    _NOW,
    _RUN_ID,
    _Environment,
)

_ASSEMBLY_TIME = datetime(2026, 8, 1, tzinfo=UTC)


@pytest.fixture
def engine(tmp_path):
    environment = _Environment(tmp_path)
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None
        parent.deadline_at = datetime(2099, 1, 1, tzinfo=UTC)
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert run is not None
        parent.creation_request_digest = orchestration_request_digest(
            target_id=run.target_id,
            idempotency_key=parent.idempotency_key,
            deadline_iso=parent.deadline_at.isoformat(),
            profile_digest=parent.profile_digest,
            plan_digest=parent.plan_digest,
            roster_digest=parent.roster_digest,
        )
    tokens = iter(
        UUID(f"44444444-4444-4444-8444-{value:012d}") for value in range(1, 10)
    )
    environment.attempts = SourceScannerAttemptService(
        environment.factory,
        environment.store,
        environment.projections,
        clock=lambda: _NOW,
        token_factory=lambda: next(tokens),
    )
    try:
        yield environment
    finally:
        environment.close()


def _coordinator(engine: _Environment) -> SourceOrchestrationCoordinatorService:
    return SourceOrchestrationCoordinatorService(
        engine.factory,
        engine.store,
        frozen_source_v1_authority_roster(),
        engine.projections,
    )


def _accept_local_nodes(engine: _Environment) -> None:
    for authority in (
        SourceAuthority.GITLEAKS,
        SourceAuthority.SYFT,
        SourceAuthority.CHECKOV,
        SourceAuthority.SEMGREP,
    ):
        if authority is SourceAuthority.SEMGREP:
            node, job = engine.create(authority)
            with engine.factory.begin() as session:
                durable_job = session.get(JobRow, job.job_id)
                assert durable_job is not None
                durable_job.status = JobStatus.RUNNING.value
                durable_job.attempt_count = 1
                durable_job.leased_by = "worker-s6b"
                durable_job.lease_token = _LEASE_TOKEN
                durable_job.lease_expires_at = _DEADLINE
                durable_job.started_at = _NOW
            attempt = engine.attempts.register_attempt(
                job_id=job.job_id,
                worker_id="worker-s6b",
                lease_token=_LEASE_TOKEN,
            )
            engine.attempts.record_sandbox_cleanup(
                SourceSandboxCleanupReceipt(
                    job_id=job.job_id,
                    attempt_number=attempt.attempt_number,
                    attempt_token=attempt.attempt_token,
                    execution_backend="docker-sandbox",
                    execution_id=job.job_id,
                    sandbox_identity=source_sandbox_execution_identity(
                        job.job_id, attempt.attempt_number, attempt.attempt_token
                    ),
                    cleanup_outcome=AttemptContainmentOutcome.CLEAN,
                    execution_removed=True,
                )
            )
        else:
            node, job, attempt = engine.start_attempt(authority)
        engine.attempts.accept_result(
            engine.native_result(node, job),
            lease_token=_LEASE_TOKEN,
            execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            return_code=0,
            duration_ms=1,
        )


def _ready(engine: _Environment) -> str:
    _accept_local_nodes(engine)
    result = _coordinator(engine).advance(run_id=str(_RUN_ID))
    assert result.lifecycle_state is OrchestrationLifecycleState.ASSEMBLY_READY
    return str(_RUN_ID)


def test_assembly_is_two_stage_restartable_and_exactly_once(engine: _Environment) -> None:
    run_id = _ready(engine)
    first_service = SourceResultAssemblyService(
        engine.factory, engine.store, clock=lambda: _ASSEMBLY_TIME
    )
    assembled = first_service.assemble(run_id)
    assert assembled.lifecycle_state is OrchestrationLifecycleState.COMMITTING
    assert assembled.assembled is True
    assert assembled.published is False
    with engine.factory() as session:
        assert session.get(AnalysisRunRow, run_id).report_json is None

    restarted = SourceResultAssemblyService(
        engine.factory, engine.store, clock=lambda: _ASSEMBLY_TIME
    )
    published = restarted.publish(run_id)
    duplicate = restarted.publish(run_id)
    assert published.lifecycle_state is OrchestrationLifecycleState.TERMINAL
    assert published.terminal_outcome is OrchestrationTerminalOutcome.COMPLETED
    assert published.published is True
    assert duplicate == published
    assert duplicate.artifact_sha256 == assembled.artifact_sha256
    assert engine.orchestrations.load(run_id).lifecycle_state is (
        OrchestrationLifecycleState.TERMINAL
    )
    with engine.factory() as session:
        report = session.get(AnalysisRunRow, run_id).report_json
        assert report is not None
        assert report["schema_version"] == "securescan-unified-evidence-s4-v1"
        assert {item["authority"] for item in report["coverage_outcomes"]} == {
            "checkov",
            "gitleaks",
            "osv.dev",
            "semgrep-ce",
            "syft",
        }


def test_cancelled_parent_cannot_assemble_or_publish(engine: _Environment) -> None:
    run_id = str(_RUN_ID)
    coordinator = _coordinator(engine)
    coordinator.request_cancellation(run_id)
    service = SourceResultAssemblyService(engine.factory, engine.store)
    with pytest.raises(SourceResultAssemblyError):
        service.assemble(run_id)
    with engine.factory() as session:
        assert session.get(AnalysisRunRow, run_id).report_json is None


def test_failed_authority_projects_explicit_gap_not_clean(engine: _Environment) -> None:
    _accept_local_nodes(engine)
    run_id = str(_RUN_ID)
    with engine.factory.begin() as session:
        syft = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == run_id,
                SourceOrchestrationNodeRow.authority == SourceAuthority.SYFT.value,
            )
        )
        osv = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == run_id,
                SourceOrchestrationNodeRow.authority == SourceAuthority.OSV.value,
            )
        )
        assert syft is not None and osv is not None
        # Replace the accepted Syft result with a terminal failure is forbidden;
        # exercise the failure projection on the dependent authority instead.
        osv.lifecycle_state = "TERMINAL"
        osv.terminal_disposition = "FAILED"
        osv.terminal_reason_code = "OSV_NETWORK_FAILURE"
        osv.containment_state = "NOT_STARTED"
        parent = session.get(SourceOrchestrationRow, run_id)
        assert parent is not None
        parent.lifecycle_state = "ASSEMBLY_READY"
    service = SourceResultAssemblyService(
        engine.factory, engine.store, clock=lambda: _ASSEMBLY_TIME
    )
    result = service.assemble_and_publish(run_id)
    assert result.terminal_outcome is OrchestrationTerminalOutcome.PARTIAL
    with engine.factory() as session:
        report = session.get(AnalysisRunRow, run_id).report_json
        osv_outcome = next(
            item for item in report["coverage_outcomes"] if item["authority"] == "osv.dev"
        )
        assert osv_outcome["state"] == "FAILED"
        assert osv_outcome["finding_count"] == 0
        assert osv_outcome["gap_count"] == 1


def test_assembly_rejects_durable_node_identity_drift(engine: _Environment) -> None:
    run_id = _ready(engine)
    with engine.factory.begin() as session:
        node = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == run_id
            )
        )
        assert node is not None
        node.analyzer_id = "tampered-analyzer"
    with pytest.raises(SourceResultAssemblyError):
        SourceResultAssemblyService(engine.factory, engine.store).assemble(run_id)

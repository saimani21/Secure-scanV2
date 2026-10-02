"""Characterize the I-B M2 worker-death recovery boundary without live services."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import func, select

from securescan.domain.enums import ExecutionOutcome, JobStatus
from securescan.jobs.execution import JobExecutionService
from securescan.orchestration.coordinator import SourceOrchestrationCoordinatorService
from securescan.orchestration.execution import (
    SourceScannerAttemptService,
    SourceScannerLeaseReconciliationService,
    SourceScannerResultRejectedError,
)
from securescan.orchestration.execution_models import (
    AttemptContainmentOutcome,
    SourceAttemptCleanupReceipt,
    SourceSandboxCleanupReceipt,
    source_sandbox_execution_identity,
)
from securescan.orchestration.models import (
    OrchestrationContainmentState,
    OrchestrationNodeLifecycleState,
    SourceAuthority,
    frozen_source_v1_authority_roster,
)
from securescan.orchestration.worker import SourceMappedJobLeasingService
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    SourceScanSubmissionRow,
    ToolExecutionRow,
)
from tests.test_source_orchestration_s6b import _LEASE_TOKEN, _RUN_ID, _Environment
from tests.test_source_runtime_r1 import (
    _durable_runtime,
    _prepare_product_submission,
    _Worker,
)


@pytest.mark.parametrize(
    "clean_receipt",
    [
        pytest.param(False, id="unknown-containment-fails-closed"),
        pytest.param(True, id="clean-containment-recovers"),
    ],
)
def test_expired_gitleaks_attempt_recovery_boundary(
    tmp_path: Path,
    clean_receipt: bool,
) -> None:
    environment = _Environment(tmp_path)
    try:
        _node, job, _attempt = environment.start_attempt(
            SourceAuthority.GITLEAKS, clean=clean_receipt
        )
        submissions = _prepare_product_submission(environment)
        with environment.factory.begin() as session:
            durable_job = session.get(JobRow, job.job_id)
            assert durable_job is not None
            durable_job.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)

        first = _durable_runtime(environment, submissions, worker=_Worker()).run_once()
        second = _durable_runtime(environment, submissions, worker=_Worker()).run_once()

        assert first.reconciled_attempt_count == 1
        assert second.reconciled_attempt_count == 0
        assert first.jobs_dispatched_count == second.jobs_dispatched_count == 0
        with environment.factory() as session:
            durable_job = session.get(JobRow, job.job_id)
            attempt = session.get(SourceOrchestrationAttemptRow, (job.job_id, 1))
            node = session.get(SourceOrchestrationNodeRow, _node.node_id)
            parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
            submission = session.get(SourceScanSubmissionRow, str(_RUN_ID))
            run = session.get(AnalysisRunRow, str(_RUN_ID))
            assert durable_job is not None
            assert attempt is not None
            assert node is not None
            assert parent is not None and parent.published_at is None
            assert submission is not None
            assert submission.finalized_at is None
            assert run is not None and run.report_json is None
            if clean_receipt:
                assert attempt.containment_state == OrchestrationContainmentState.CLEAN.value
                assert durable_job.status == JobStatus.RETRY_PENDING.value
                assert attempt.acceptance_state == "REJECTED"
                assert node.lifecycle_state == OrchestrationNodeLifecycleState.RETRY_PENDING.value
            else:
                assert durable_job.status == JobStatus.RUNNING.value
                assert attempt.acceptance_state == "PENDING"
                assert (
                    attempt.containment_state
                    == OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
                )
                assert (
                    node.lifecycle_state
                    == OrchestrationNodeLifecycleState.RECONCILIATION_REQUIRED.value
                )
    finally:
        environment.close()


def _expire_job(environment: _Environment, job_id: str) -> None:
    with environment.factory.begin() as session:
        row = session.get(JobRow, job_id)
        assert row is not None
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)


def _write_clean_receipt(root: Path, job_id: str, attempt_number: int, attempt_token: str) -> None:
    directory = root / job_id / str(attempt_number)
    directory.mkdir(parents=True, mode=0o700)
    receipt = SourceAttemptCleanupReceipt(
        job_id=job_id,
        attempt_number=attempt_number,
        attempt_token=attempt_token,
        supervisor_identity="a" * 64,
        supervisor_pid=999_991,
        supervisor_start_ticks=101,
        scanner_pid=999_992,
        scanner_pgid=999_992,
        scanner_start_ticks=102,
        cleanup_outcome=AttemptContainmentOutcome.CLEAN,
        process_tree_empty=True,
    )
    path = directory / f"{job_id}-{attempt_number}-{attempt_token}.json"
    path.write_bytes(receipt.canonical_json())
    path.chmod(0o600)


def test_active_expired_attempt_recovers_exact_receipt_and_retry_accepts_once(
    tmp_path: Path,
) -> None:
    environment = _Environment(tmp_path)
    try:
        node, job, first = environment.start_attempt(SourceAuthority.GITLEAKS, clean=False)
        _prepare_product_submission(environment)
        _expire_job(environment, job.job_id)
        receipt_root = tmp_path / "local-receipts"
        _write_clean_receipt(receipt_root, job.job_id, 1, first.attempt_token)
        recovered = SourceScannerLeaseReconciliationService(
            environment.factory, local_receipt_root=receipt_root
        ).quarantine_expired()
        assert len(recovered) == 1
        assert recovered[0].containment_state is OrchestrationContainmentState.CLEAN
        with pytest.raises(SourceScannerResultRejectedError):
            environment.attempts.accept_result(
                environment.native_result(node, job),
                lease_token=_LEASE_TOKEN,
                execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
                return_code=0,
                duration_ms=1,
            )
        with environment.factory.begin() as session:
            first_row = session.get(SourceOrchestrationAttemptRow, (job.job_id, 1))
            assert first_row is not None
            first_row.finished_at = datetime.now(UTC) - timedelta(seconds=10)
        coordinator = SourceOrchestrationCoordinatorService(
            environment.factory,
            environment.store,
            frozen_source_v1_authority_roster(),
            environment.projections,
        )
        assert coordinator._promote_due_retries(str(_RUN_ID)) == [job.job_id]
        leased = SourceMappedJobLeasingService(environment.factory).lease_next(
            worker_id="retry-worker"
        )
        assert leased is not None and leased.id == job.job_id
        assert leased.lease_token is not None
        started = JobExecutionService(environment.factory).start_job(
            leased.id, "retry-worker", leased.lease_token
        )
        environment.attempts = SourceScannerAttemptService(
            environment.factory,
            environment.store,
            environment.projections,
            token_factory=lambda: UUID("55555555-5555-4555-8555-555555555555"),
        )
        second = environment.attempts.register_attempt(
            job_id=started.id,
            worker_id="retry-worker",
            lease_token=leased.lease_token,
        )
        environment.attempts.register_supervisor(
            job_id=started.id,
            attempt_number=2,
            attempt_token=second.attempt_token,
            supervisor_identity="a" * 64,
            supervisor_pid=999_991,
            supervisor_start_ticks=101,
            scanner_pid=999_992,
            scanner_pgid=999_992,
            scanner_start_ticks=102,
        )
        receipt_root = tmp_path / "retry-receipts"
        _write_clean_receipt(receipt_root, started.id, 2, second.attempt_token)
        receipt_path = (
            receipt_root / started.id / "2" / f"{started.id}-2-{second.attempt_token}.json"
        )
        environment.attempts.record_cleanup(
            SourceAttemptCleanupReceipt.from_json(receipt_path.read_bytes())
        )
        accepted = environment.attempts.accept_result(
            replace(environment.native_result(node, job), attempt_number=2),
            lease_token=leased.lease_token,
            execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            return_code=0,
            duration_ms=1,
        )
        assert accepted.attempt_number == 2
        with pytest.raises(SourceScannerResultRejectedError):
            environment.attempts.accept_result(
                environment.native_result(node, job),
                lease_token=_LEASE_TOKEN,
                execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
                return_code=0,
                duration_ms=1,
            )
        with environment.factory() as session:
            mapping = session.get(SourceOrchestrationScannerJobRow, job.job_id)
            first_row = session.get(SourceOrchestrationAttemptRow, (job.job_id, 1))
            second_row = session.get(SourceOrchestrationAttemptRow, (job.job_id, 2))
            assert mapping is not None and mapping.selected_attempt_number == 2
            assert first_row is not None and first_row.acceptance_state == "REJECTED"
            assert second_row is not None and second_row.acceptance_state == "ACCEPTED"
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(ToolExecutionRow)
                    .where(ToolExecutionRow.job_id == job.job_id)
                )
                == 2
            )
    finally:
        environment.close()


@pytest.mark.parametrize("receipt_variant", ["missing", "contradictory"])
def test_active_expired_attempt_without_valid_receipt_stays_quarantined(
    tmp_path: Path, receipt_variant: str
) -> None:
    environment = _Environment(tmp_path)
    try:
        _node, job, attempt = environment.start_attempt(SourceAuthority.GITLEAKS, clean=False)
        _prepare_product_submission(environment)
        _expire_job(environment, job.job_id)
        receipt_root = tmp_path / "missing-local-receipts"
        if receipt_variant == "contradictory":
            _write_clean_receipt(receipt_root, job.job_id, 1, attempt.attempt_token)
            path = receipt_root / job.job_id / "1" / f"{job.job_id}-1-{attempt.attempt_token}.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["attempt_token"] = "55555555-5555-4555-8555-555555555555"
            path.write_text(json.dumps(payload), encoding="utf-8")
        recovered = SourceScannerLeaseReconciliationService(
            environment.factory, local_receipt_root=receipt_root
        ).quarantine_expired()
        assert len(recovered) == 1
        assert (
            recovered[0].containment_state is OrchestrationContainmentState.RECONCILIATION_REQUIRED
        )
        assert (
            SourceScannerLeaseReconciliationService(
                environment.factory, local_receipt_root=receipt_root
            ).quarantine_expired()
            == ()
        )
        with environment.factory() as session:
            durable_job = session.get(JobRow, job.job_id)
            attempt = session.get(SourceOrchestrationAttemptRow, (job.job_id, 1))
            assert durable_job is not None and durable_job.status == JobStatus.RUNNING.value
            assert attempt is not None and attempt.acceptance_state == "PENDING"
            assert attempt.tool_execution_id is None
    finally:
        environment.close()


@pytest.mark.parametrize("cleanup_proven", [False, True])
def test_expired_semgrep_attempt_requires_sandbox_cleanup_proof(
    tmp_path: Path, cleanup_proven: bool
) -> None:
    environment = _Environment(tmp_path)
    try:
        _node, job, _attempt = environment.start_attempt(SourceAuthority.SEMGREP, clean=False)
        _prepare_product_submission(environment)
        _expire_job(environment, job.job_id)
        # The shared S6B fixture registers local-process identity for every
        # authority; real Semgrep Docker attempts have no local supervisor.
        with environment.factory.begin() as session:
            durable_attempt = session.get(SourceOrchestrationAttemptRow, (job.job_id, 1))
            assert durable_attempt is not None
            durable_attempt.supervisor_identity = None
            durable_attempt.supervisor_pid = None
            durable_attempt.supervisor_start_ticks = None
            durable_attempt.scanner_pid = None
            durable_attempt.scanner_pgid = None
            durable_attempt.scanner_start_ticks = None

        def reconcile(attempt):
            if not cleanup_proven:
                raise OSError("sandbox inspection unavailable")
            return environment.attempts.record_sandbox_cleanup(
                SourceSandboxCleanupReceipt(
                    job_id=attempt.job_id,
                    attempt_number=attempt.attempt_number,
                    attempt_token=attempt.attempt_token,
                    execution_backend="docker-sandbox",
                    execution_id=attempt.job_id,
                    sandbox_identity=source_sandbox_execution_identity(
                        attempt.job_id, attempt.attempt_number, attempt.attempt_token
                    ),
                    cleanup_outcome=AttemptContainmentOutcome.CLEAN,
                    execution_removed=True,
                )
            )

        recovered = SourceScannerLeaseReconciliationService(
            environment.factory, sandbox_reconcile=reconcile
        ).quarantine_expired()
        assert len(recovered) == 1
        with environment.factory() as session:
            durable_job = session.get(JobRow, job.job_id)
            durable_attempt = session.get(SourceOrchestrationAttemptRow, (job.job_id, 1))
            assert durable_job is not None and durable_attempt is not None
            if cleanup_proven:
                assert durable_job.status == JobStatus.RETRY_PENDING.value
                assert durable_attempt.acceptance_state == "REJECTED"
            else:
                assert durable_job.status == JobStatus.RUNNING.value
                assert durable_attempt.acceptance_state == "PENDING"
                assert (
                    durable_attempt.containment_state
                    == OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
                )
    finally:
        environment.close()


def test_expired_clean_attempt_at_retry_limit_terminalizes_once(tmp_path: Path) -> None:
    environment = _Environment(tmp_path)
    try:
        node, job, _attempt = environment.start_attempt(SourceAuthority.GITLEAKS)
        _prepare_product_submission(environment)
        with environment.factory.begin() as session:
            durable_job = session.get(JobRow, job.job_id)
            assert durable_job is not None
            durable_job.max_attempts = 1
        _expire_job(environment, job.job_id)
        reconciler = SourceScannerLeaseReconciliationService(environment.factory)
        assert len(reconciler.quarantine_expired()) == 1
        assert reconciler.quarantine_expired() == ()
        with environment.factory() as session:
            durable_job = session.get(JobRow, job.job_id)
            durable_node = session.get(SourceOrchestrationNodeRow, node.node_id)
            assert durable_job is not None and durable_job.status == JobStatus.FAILED.value
            assert durable_node is not None
            assert durable_node.lifecycle_state == OrchestrationNodeLifecycleState.TERMINAL.value
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(ToolExecutionRow)
                    .where(ToolExecutionRow.job_id == job.job_id)
                )
                == 1
            )
    finally:
        environment.close()


def test_cancellation_before_clean_recovery_never_schedules_retry(tmp_path: Path) -> None:
    environment = _Environment(tmp_path)
    try:
        node, job, _attempt = environment.start_attempt(SourceAuthority.GITLEAKS)
        _prepare_product_submission(environment)
        _expire_job(environment, job.job_id)
        with environment.factory() as session:
            parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
            assert parent is not None
            expected_version = parent.state_version
        environment.orchestrations.request_cancellation(str(_RUN_ID), expected_version)
        assert (
            len(SourceScannerLeaseReconciliationService(environment.factory).quarantine_expired())
            == 1
        )
        with environment.factory() as session:
            durable_job = session.get(JobRow, job.job_id)
            durable_node = session.get(SourceOrchestrationNodeRow, node.node_id)
            assert durable_job is not None and durable_job.status == JobStatus.CANCELLED.value
            assert durable_node is not None
            assert durable_node.lifecycle_state == OrchestrationNodeLifecycleState.TERMINAL.value
    finally:
        environment.close()

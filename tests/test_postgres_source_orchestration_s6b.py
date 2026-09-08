from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from postgres_test_guard import validated_postgres_test_url
from sqlalchemy import create_engine, select, text
from test_source_orchestration_s6a import _DEADLINE, _NOW, _RUN_ID
from test_source_orchestration_s6b import _LEASE_TOKEN, _Environment

from securescan.domain.enums import ExecutionOutcome
from securescan.jobs.lease_recovery import JobLeaseRecoveryService
from securescan.orchestration.execution import (
    SourceScannerAttemptBlockedError,
    SourceScannerAttemptService,
    SourceScannerLeaseReconciliationService,
    SourceScannerResultRejectedError,
)
from securescan.orchestration.execution_models import SafeSourceNativeResult
from securescan.orchestration.models import SourceAuthority
from securescan.persistence.database import (
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationScannerJobRow,
)
from securescan.scanners.gitleaks import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
    GitleaksDetectionKind,
    GitleaksParseResult,
    NormalizedGitleaksFinding,
)
from securescan.source.execution_context import SourceExecutionContext

pytestmark = pytest.mark.postgres


def _reset(database_url: str) -> None:
    engine = create_engine(database_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


@pytest.fixture
def postgres_s6b(tmp_path: Path):
    database_url = validated_postgres_test_url()
    _reset(database_url)
    environment = _Environment(tmp_path, database_url=database_url)
    try:
        yield environment
    finally:
        environment.close()
        _reset(database_url)


def test_concurrent_duplicate_job_creation_is_one_identity(postgres_s6b: _Environment) -> None:
    node = next(
        item for item in postgres_s6b.snapshot.nodes if item.authority is SourceAuthority.GITLEAKS
    )
    barrier = threading.Barrier(2)

    def create():
        barrier.wait()
        return postgres_s6b.jobs.create_job(
            run_id=str(_RUN_ID),
            node_id=node.node_id,
            workspace=postgres_s6b.workspace,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _value: create(), range(2)))
    assert {item.job_id for item in results} == {results[0].job_id}
    assert sorted(item.created for item in results) == [False, True]


def test_concurrent_duplicate_result_acceptance_is_idempotent(
    postgres_s6b: _Environment,
) -> None:
    node, job, _attempt = postgres_s6b.start_attempt()
    native = postgres_s6b.native_result(node, job)
    barrier = threading.Barrier(2)

    def accept():
        barrier.wait()
        return postgres_s6b.attempts.accept_result(
            native,
            lease_token=_LEASE_TOKEN,
            execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            return_code=0,
            duration_ms=1,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _value: accept(), range(2)))
    assert sorted(item.created for item in results) == [False, True]
    assert {item.artifact_sha256 for item in results} == {native.sha256()}


def _finding_result(environment: _Environment, native: SafeSourceNativeResult):
    with environment.factory() as session:
        mapping = session.get(SourceOrchestrationScannerJobRow, native.job_id)
        assert mapping is not None
        payload = environment.store.read_by_sha256(
            mapping.context_artifact_sha256,
            expected_size_bytes=mapping.context_artifact_size_bytes,
        )
    context = SourceExecutionContext.from_json(payload)
    finding = NormalizedGitleaksFinding(
        scanner_id=GITLEAKS_SCANNER_ID,
        scanner_version=GITLEAKS_VERSION,
        rule_id="github-pat",
        file_path="app.py",
        detection_kind=GitleaksDetectionKind.CONTENT,
        start_line=1,
        end_line=1,
        start_column=1,
        end_column=4,
        projection_id=native.projection_id,
        context_digest=native.context_digest,
        projection_digest=native.projection_digest,
    )
    parsed = GitleaksParseResult(
        scanner_id=GITLEAKS_SCANNER_ID,
        scanner_version=GITLEAKS_VERSION,
        binding_digest=native.binding_digest,
        projection_id=native.projection_id,
        context_digest=native.context_digest,
        projection_digest=native.projection_digest,
        findings=(finding,),
        finding_count=1,
    )
    return SafeSourceNativeResult.from_parse_result(
        result=parsed,
        node_id=native.node_id,
        job_id=native.job_id,
        attempt_number=native.attempt_number,
        authority=native.authority,
        analyzer_id=native.analyzer_id,
        context=context,
    )


def test_concurrent_conflicting_artifacts_select_exactly_one(
    postgres_s6b: _Environment,
) -> None:
    node, job, _attempt = postgres_s6b.start_attempt()
    empty = postgres_s6b.native_result(node, job)
    finding = _finding_result(postgres_s6b, empty)
    barrier = threading.Barrier(2)

    def accept(native: SafeSourceNativeResult):
        barrier.wait()
        try:
            return postgres_s6b.attempts.accept_result(
                native,
                lease_token=_LEASE_TOKEN,
                execution_outcome=(
                    ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
                    if native is finding
                    else ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS
                ),
                return_code=0,
                duration_ms=1,
            )
        except SourceScannerResultRejectedError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(accept, (empty, finding)))
    assert sum(item is not None for item in results) == 1
    with postgres_s6b.factory() as session:
        mapping = session.get(SourceOrchestrationScannerJobRow, job.job_id)
        attempts = tuple(
            session.scalars(
                select(SourceOrchestrationAttemptRow).where(
                    SourceOrchestrationAttemptRow.job_id == job.job_id,
                    SourceOrchestrationAttemptRow.acceptance_state == "ACCEPTED",
                )
            )
        )
        assert mapping is not None and mapping.selected_attempt_number == 1
        assert len(attempts) == 1


def test_result_acceptance_vs_parent_cancellation_is_serializable(
    postgres_s6b: _Environment,
) -> None:
    node, job, _attempt = postgres_s6b.start_attempt()
    native = postgres_s6b.native_result(node, job)
    barrier = threading.Barrier(2)

    def accept() -> bool:
        barrier.wait()
        try:
            postgres_s6b.attempts.accept_result(
                native,
                lease_token=_LEASE_TOKEN,
                execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
                return_code=0,
                duration_ms=1,
            )
            return True
        except SourceScannerResultRejectedError:
            return False

    def cancel() -> None:
        barrier.wait()
        postgres_s6b.orchestrations.request_cancellation(str(_RUN_ID), 2)

    with ThreadPoolExecutor(max_workers=2) as pool:
        accepted_future = pool.submit(accept)
        cancelled_future = pool.submit(cancel)
        accepted = accepted_future.result()
        cancelled_future.result()
    with postgres_s6b.factory() as session:
        mapping = session.get(SourceOrchestrationScannerJobRow, job.job_id)
        assert mapping is not None
        assert (mapping.selected_attempt_number == 1) is accepted


def test_generic_lease_recovery_cannot_bypass_reconciliation(
    postgres_s6b: _Environment,
) -> None:
    _node, job, _attempt = postgres_s6b.start_attempt(clean=False)
    with postgres_s6b.factory.begin() as session:
        durable = session.get(JobRow, job.job_id)
        assert durable is not None
        durable.lease_expires_at = _NOW
    generic = JobLeaseRecoveryService(postgres_s6b.factory, clock=lambda: _DEADLINE)
    assert generic.recover_expired_jobs() == []
    quarantined = SourceScannerLeaseReconciliationService(
        postgres_s6b.factory, clock=lambda: _DEADLINE
    ).quarantine_expired()
    assert len(quarantined) == 1


def test_result_acceptance_vs_lease_reconciliation_fails_closed(
    postgres_s6b: _Environment,
) -> None:
    node, job, _attempt = postgres_s6b.start_attempt(clean=False)
    native = postgres_s6b.native_result(node, job)
    with postgres_s6b.factory.begin() as session:
        durable = session.get(JobRow, job.job_id)
        assert durable is not None
        durable.lease_expires_at = _NOW
    barrier = threading.Barrier(2)

    def accept() -> bool:
        barrier.wait()
        try:
            postgres_s6b.attempts.accept_result(
                native,
                lease_token=_LEASE_TOKEN,
                execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
                return_code=0,
                duration_ms=1,
            )
            return True
        except SourceScannerResultRejectedError:
            return False

    def reconcile() -> int:
        barrier.wait()
        return len(
            SourceScannerLeaseReconciliationService(
                postgres_s6b.factory, clock=lambda: _DEADLINE
            ).quarantine_expired()
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        accepted_future = pool.submit(accept)
        reconciled_future = pool.submit(reconcile)
        assert accepted_future.result() is False
        assert reconciled_future.result() == 1
    with postgres_s6b.factory() as session:
        mapping = session.get(SourceOrchestrationScannerJobRow, job.job_id)
        attempt = session.get(SourceOrchestrationAttemptRow, (job.job_id, 1))
        assert mapping is not None and mapping.selected_attempt_number is None
        assert attempt is not None
        assert attempt.containment_state == "RECONCILIATION_REQUIRED"


def test_two_workers_cannot_register_the_same_attempt(postgres_s6b: _Environment) -> None:
    _node, job = postgres_s6b.create()
    with postgres_s6b.factory.begin() as session:
        durable = session.get(JobRow, job.job_id)
        assert durable is not None
        durable.status = "running"
        durable.attempt_count = 1
        durable.leased_by = "winner"
        durable.lease_token = _LEASE_TOKEN
        durable.lease_expires_at = _DEADLINE
    service = SourceScannerAttemptService(
        postgres_s6b.factory,
        postgres_s6b.store,
        postgres_s6b.projections,
        clock=lambda: _NOW,
    )
    barrier = threading.Barrier(2)

    def register(worker: str) -> bool:
        barrier.wait()
        try:
            service.register_attempt(job_id=job.job_id, worker_id=worker, lease_token=_LEASE_TOKEN)
            return True
        except SourceScannerAttemptBlockedError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(register, ("winner", "loser")))
    assert sorted(results) == [False, True]

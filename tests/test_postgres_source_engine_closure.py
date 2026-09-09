from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from postgres_test_guard import validated_postgres_test_url
from sqlalchemy import create_engine, func, select, text
from test_source_assembly_s6d import _accept_local_nodes
from test_source_orchestration_s6a import _NOW, _RUN_ID
from test_source_orchestration_s6b import _LEASE_TOKEN as _LOCAL_LEASE
from test_source_orchestration_s6b import _Environment
from test_source_osv_execution_s6cb import (
    _LEASE,
    _clean,
    _runnable,
    _start_osv_attempt,
    _zero_analysis,
)

from securescan.domain.enums import ExecutionOutcome, JobFailureCategory
from securescan.orchestration.assembly import SourceResultAssemblyService
from securescan.orchestration.coordinator import SourceOrchestrationCoordinatorService
from securescan.orchestration.execution import SourceScannerAttemptService
from securescan.orchestration.execution_models import SourceScannerFailureCode
from securescan.orchestration.models import (
    SourceAuthority,
    frozen_source_v1_authority_roster,
    orchestration_request_digest,
)
from securescan.orchestration.osv_execution import (
    OsvRequestOperation,
    SafeSourceOsvResult,
    SourceOsvAttemptService,
    SourceOsvExecutionConflictError,
    SourceOsvFailureCode,
    SourceOsvRequestPermitService,
)
from securescan.orchestration.worker import SourceMappedJobLeasingService
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    SourceOsvRequestPermitRow,
    ToolExecutionRow,
)

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
def postgres_engine_closure(tmp_path: Path):
    database_url = validated_postgres_test_url()
    _reset(database_url)
    environment = _Environment(tmp_path, database_url=database_url)
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert parent is not None and run is not None
        parent.deadline_at = datetime(2099, 1, 1, tzinfo=UTC)
        parent.creation_request_digest = orchestration_request_digest(
            target_id=run.target_id,
            idempotency_key=parent.idempotency_key,
            deadline_iso=parent.deadline_at.isoformat(),
            profile_digest=parent.profile_digest,
            plan_digest=parent.plan_digest,
            roster_digest=parent.roster_digest,
        )
    tokens = iter(
        UUID(f"77777777-7777-4777-8777-{value:012d}") for value in range(1, 20)
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
        _reset(database_url)


def _coordinator(environment: _Environment) -> SourceOrchestrationCoordinatorService:
    return SourceOrchestrationCoordinatorService(
        environment.factory,
        environment.store,
        frozen_source_v1_authority_roster(),
        environment.projections,
    )


def _create_initial_jobs(environment: _Environment) -> None:
    _coordinator(environment).advance(
        run_id=str(_RUN_ID), workspace=environment.workspace
    )


def _race_leases(environment: _Environment, workers: int) -> tuple[object, ...]:
    barrier = threading.Barrier(workers)

    def lease(value: int):
        barrier.wait()
        return SourceMappedJobLeasingService(
            environment.factory,
            token_factory=lambda: UUID(
                f"88888888-8888-4888-8888-{value + 1:012d}"
            ),
        ).lease_next(worker_id=f"ceiling-worker-{value}")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return tuple(pool.map(lease, range(workers)))


def _free_lease(environment: _Environment, job_id: str) -> None:
    with environment.factory.begin() as session:
        job = session.get(JobRow, job_id)
        assert job is not None
        job.status = "succeeded"
        job.leased_by = None
        job.lease_token = None
        job.lease_expires_at = None


def _lease_one(environment: _Environment, worker: str):
    return SourceMappedJobLeasingService(environment.factory).lease_next(
        worker_id=worker
    )


def test_per_run_ceiling_is_atomic_and_one_completion_opens_one_slot(
    postgres_engine_closure: _Environment,
) -> None:
    _create_initial_jobs(postgres_engine_closure)
    first = _lease_one(postgres_engine_closure, "first-worker")
    assert first is not None
    raced = tuple(
        item for item in _race_leases(postgres_engine_closure, 4) if item is not None
    )
    assert len(raced) == 1
    with postgres_engine_closure.factory() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None and parent.max_active_jobs == 2

    _free_lease(postgres_engine_closure, first.id)
    second = _race_leases(postgres_engine_closure, 2)
    assert sum(item is not None for item in second) == 1


def test_cancellation_and_deadline_prevent_new_lease_after_slot_opens(
    postgres_engine_closure: _Environment,
) -> None:
    _create_initial_jobs(postgres_engine_closure)
    active = tuple(
        _lease_one(postgres_engine_closure, f"worker-{value}") for value in range(2)
    )
    assert all(item is not None for item in active)
    assert active[0] is not None
    _free_lease(postgres_engine_closure, active[0].id)
    _coordinator(postgres_engine_closure).request_cancellation(str(_RUN_ID))
    assert _race_leases(postgres_engine_closure, 2) == (None, None)


def test_expired_deadline_prevents_new_lease_with_capacity(
    postgres_engine_closure: _Environment,
) -> None:
    _create_initial_jobs(postgres_engine_closure)
    with postgres_engine_closure.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None
        parent.deadline_at = datetime(2000, 1, 1, tzinfo=UTC)
    assert _race_leases(postgres_engine_closure, 2) == (None, None)


def test_promoted_retry_respects_same_active_ceiling(
    postgres_engine_closure: _Environment,
) -> None:
    _node, retry_job, retry_attempt = postgres_engine_closure.start_attempt(
        SourceAuthority.GITLEAKS
    )
    postgres_engine_closure.attempts.record_failure(
        job_id=retry_job.job_id,
        attempt_number=retry_attempt.attempt_number,
        attempt_token=retry_attempt.attempt_token,
        lease_token=_LOCAL_LEASE,
        failure_code=SourceScannerFailureCode.EXECUTION_FAILURE,
        failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
        execution_outcome=ExecutionOutcome.INTERNAL_ERROR,
        return_code=None,
        duration_ms=1,
        retryable=True,
    )
    with postgres_engine_closure.factory.begin() as session:
        attempt = session.get(SourceOrchestrationAttemptRow, (retry_job.job_id, 1))
        assert attempt is not None
        attempt.finished_at = datetime(2000, 1, 1, tzinfo=UTC)
    for authority in (SourceAuthority.SEMGREP, SourceAuthority.SYFT):
        postgres_engine_closure.create(authority)
    active = tuple(
        _lease_one(postgres_engine_closure, f"active-worker-{value}")
        for value in range(2)
    )
    assert all(item is not None for item in active)
    assert active[0] is not None
    result = _coordinator(postgres_engine_closure).advance(run_id=str(_RUN_ID))
    assert retry_job.job_id in result.retries_promoted
    assert SourceMappedJobLeasingService(
        postgres_engine_closure.factory
    ).lease_next(worker_id="retry-worker") is None
    _free_lease(postgres_engine_closure, active[0].id)
    leased = SourceMappedJobLeasingService(
        postgres_engine_closure.factory
    ).lease_next(worker_id="retry-worker")
    assert leased is not None and leased.id == retry_job.job_id


def test_two_coordinators_create_one_initial_job_per_node(
    postgres_engine_closure: _Environment,
) -> None:
    barrier = threading.Barrier(2)

    def advance(_value: int):
        barrier.wait()
        return _coordinator(postgres_engine_closure).advance(
            run_id=str(_RUN_ID), workspace=postgres_engine_closure.workspace
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        tuple(pool.map(advance, range(2)))
    with postgres_engine_closure.factory() as session:
        assert (
            session.scalar(
                select(func.count()).select_from(SourceOrchestrationScannerJobRow)
            )
            == 4
        )


def test_osv_permit_and_cancellation_have_one_serial_order(
    postgres_engine_closure: _Environment,
) -> None:
    _osv, _evaluation, _jobs, created = _runnable(postgres_engine_closure)
    attempt = _start_osv_attempt(postgres_engine_closure, created)
    barrier = threading.Barrier(2)

    def permit():
        barrier.wait()
        try:
            SourceOsvRequestPermitService(postgres_engine_closure.factory).authorize(
                job_id=created.job_id,
                attempt_number=1,
                attempt_token=attempt.attempt_token,
                helper_identity="b" * 64,
                request_sequence=1,
                operation_kind=OsvRequestOperation.QUERY_BATCH,
                logical_request_digest="c" * 64,
                transport_attempt_number=1,
            )
            return True
        except SourceOsvExecutionConflictError:
            return False

    def cancel():
        barrier.wait()
        _coordinator(postgres_engine_closure).request_cancellation(str(_RUN_ID))

    with ThreadPoolExecutor(max_workers=2) as pool:
        permit_future = pool.submit(permit)
        cancel_future = pool.submit(cancel)
        permitted = permit_future.result()
        cancel_future.result()
    with postgres_engine_closure.factory() as session:
        permit_count = session.scalar(
            select(func.count()).select_from(SourceOsvRequestPermitRow)
        )
        assert permit_count == int(permitted)
        assert session.get(AnalysisRunRow, str(_RUN_ID)).report_json is None


def test_osv_acceptance_and_cancellation_never_double_commit(
    postgres_engine_closure: _Environment,
) -> None:
    _osv, _evaluation, jobs, created = _runnable(postgres_engine_closure)
    attempt = _start_osv_attempt(postgres_engine_closure, created)
    _clean(postgres_engine_closure, attempt)
    execution_input = jobs.load_input(job_id=created.job_id)
    result = SafeSourceOsvResult.from_analysis(
        execution_input,
        attempt_number=1,
        analysis=_zero_analysis(execution_input),
    )
    barrier = threading.Barrier(2)

    def accept():
        barrier.wait()
        try:
            return SourceOsvAttemptService(
                postgres_engine_closure.factory,
                postgres_engine_closure.store,
                jobs,
            ).accept_result(result, lease_token=_LEASE, duration_ms=1)
        except SourceOsvExecutionConflictError:
            return False

    def cancel():
        barrier.wait()
        _coordinator(postgres_engine_closure).request_cancellation(str(_RUN_ID))

    with ThreadPoolExecutor(max_workers=2) as pool:
        accepted_future = pool.submit(accept)
        cancel_future = pool.submit(cancel)
        accepted = accepted_future.result()
        cancel_future.result()
    with postgres_engine_closure.factory() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(ToolExecutionRow)
                .where(ToolExecutionRow.adapter_id == "osv.dev")
            )
            == int(accepted)
        )
        assert session.get(AnalysisRunRow, str(_RUN_ID)).report_json is None


def test_two_assemblers_publish_one_identical_report(
    postgres_engine_closure: _Environment,
) -> None:
    _accept_local_nodes(postgres_engine_closure)
    assert _coordinator(postgres_engine_closure).advance(
        run_id=str(_RUN_ID)
    ).lifecycle_state.value == "ASSEMBLY_READY"
    barrier = threading.Barrier(2)

    def assemble(_value: int):
        barrier.wait()
        return SourceResultAssemblyService(
            postgres_engine_closure.factory, postgres_engine_closure.store
        ).assemble_and_publish(str(_RUN_ID))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(assemble, range(2)))
    assert {item.artifact_sha256 for item in results} == {results[0].artifact_sha256}
    with postgres_engine_closure.factory() as session:
        report = session.get(AnalysisRunRow, str(_RUN_ID)).report_json
        assert report is not None


def test_two_workers_competing_for_osv_job_issue_one_lease(
    postgres_engine_closure: _Environment,
) -> None:
    _osv, _evaluation, _jobs, created = _runnable(postgres_engine_closure)
    barrier = threading.Barrier(2)

    def lease(value: int):
        barrier.wait()
        return SourceMappedJobLeasingService(
            postgres_engine_closure.factory,
            token_factory=lambda: UUID(
                f"66666666-6666-4666-8666-{value + 1:012d}"
            ),
        ).lease_next(worker_id=f"osv-worker-{value}")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lease, range(2)))
    leased = tuple(item for item in results if item is not None)
    assert len(leased) == 1
    assert leased[0].id == created.job_id
    with postgres_engine_closure.factory() as session:
        job = session.get(JobRow, created.job_id)
        assert job is not None
        assert job.status == "leased"
        assert job.attempt_count == 1


def test_osv_retry_and_cancellation_cannot_overlap(
    postgres_engine_closure: _Environment,
) -> None:
    _osv, _evaluation, jobs, created = _runnable(postgres_engine_closure)
    attempt = _start_osv_attempt(postgres_engine_closure, created)
    _clean(postgres_engine_closure, attempt)
    SourceOsvAttemptService(
        postgres_engine_closure.factory,
        postgres_engine_closure.store,
        jobs,
    ).record_failure(
        job_id=created.job_id,
        attempt_number=1,
        attempt_token=attempt.attempt_token,
        lease_token=_LEASE,
        failure_code=SourceOsvFailureCode.NETWORK_FAILURE,
        duration_ms=1,
    )
    with postgres_engine_closure.factory.begin() as session:
        durable_attempt = session.get(
            SourceOrchestrationAttemptRow, (created.job_id, 1)
        )
        assert durable_attempt is not None
        durable_attempt.finished_at = datetime(2000, 1, 1, tzinfo=UTC)
    barrier = threading.Barrier(2)

    def promote() -> None:
        barrier.wait()
        _coordinator(postgres_engine_closure).advance(run_id=str(_RUN_ID))

    def cancel() -> None:
        barrier.wait()
        _coordinator(postgres_engine_closure).request_cancellation(str(_RUN_ID))

    with ThreadPoolExecutor(max_workers=2) as pool:
        promote_future = pool.submit(promote)
        cancel_future = pool.submit(cancel)
        promote_future.result()
        cancel_future.result()
    with postgres_engine_closure.factory() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        job = session.get(JobRow, created.job_id)
        assert parent is not None and parent.cancel_requested is True
        assert job is not None and job.status == "cancelled"
        assert job.attempt_count == 1


def test_two_coordinators_converge_on_one_assembly_ready_transition(
    postgres_engine_closure: _Environment,
) -> None:
    _accept_local_nodes(postgres_engine_closure)
    barrier = threading.Barrier(2)

    def advance(_value: int):
        barrier.wait()
        return _coordinator(postgres_engine_closure).advance(run_id=str(_RUN_ID))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(advance, range(2)))
    assert {item.lifecycle_state.value for item in results} == {"ASSEMBLY_READY"}
    with postgres_engine_closure.factory() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None
        assert parent.lifecycle_state == "ASSEMBLY_READY"
        assert parent.assembly_artifact_sha256 is None


def test_osv_permit_and_expired_deadline_converge_without_late_authorization(
    postgres_engine_closure: _Environment,
) -> None:
    _osv, _evaluation, _jobs, created = _runnable(postgres_engine_closure)
    attempt = _start_osv_attempt(postgres_engine_closure, created)
    with postgres_engine_closure.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None
        parent.deadline_at = datetime(2000, 1, 1, tzinfo=UTC)
    barrier = threading.Barrier(2)

    def permit() -> bool:
        barrier.wait()
        try:
            SourceOsvRequestPermitService(postgres_engine_closure.factory).authorize(
                job_id=created.job_id,
                attempt_number=1,
                attempt_token=attempt.attempt_token,
                helper_identity="b" * 64,
                request_sequence=1,
                operation_kind=OsvRequestOperation.QUERY_BATCH,
                logical_request_digest="d" * 64,
                transport_attempt_number=1,
            )
            return True
        except SourceOsvExecutionConflictError:
            return False

    def enforce_deadline() -> None:
        barrier.wait()
        _coordinator(postgres_engine_closure).advance(run_id=str(_RUN_ID))

    with ThreadPoolExecutor(max_workers=2) as pool:
        permit_future = pool.submit(permit)
        deadline_future = pool.submit(enforce_deadline)
        assert permit_future.result() is False
        deadline_future.result()
    with postgres_engine_closure.factory() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None and parent.deadline_exceeded_at is not None
        assert session.scalar(select(func.count()).select_from(SourceOsvRequestPermitRow)) == 0


def test_osv_acceptance_and_expired_deadline_converge_without_late_result(
    postgres_engine_closure: _Environment,
) -> None:
    _osv, _evaluation, jobs, created = _runnable(postgres_engine_closure)
    attempt = _start_osv_attempt(postgres_engine_closure, created)
    _clean(postgres_engine_closure, attempt)
    execution_input = jobs.load_input(job_id=created.job_id)
    result = SafeSourceOsvResult.from_analysis(
        execution_input,
        attempt_number=1,
        analysis=_zero_analysis(execution_input),
    )
    with postgres_engine_closure.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None
        parent.deadline_at = datetime(2000, 1, 1, tzinfo=UTC)
    barrier = threading.Barrier(2)

    def accept() -> bool:
        barrier.wait()
        try:
            SourceOsvAttemptService(
                postgres_engine_closure.factory,
                postgres_engine_closure.store,
                jobs,
            ).accept_result(result, lease_token=_LEASE, duration_ms=1)
            return True
        except SourceOsvExecutionConflictError:
            return False

    def enforce_deadline() -> None:
        barrier.wait()
        _coordinator(postgres_engine_closure).advance(run_id=str(_RUN_ID))

    with ThreadPoolExecutor(max_workers=2) as pool:
        accept_future = pool.submit(accept)
        deadline_future = pool.submit(enforce_deadline)
        assert accept_future.result() is False
        deadline_future.result()
    with postgres_engine_closure.factory() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None and parent.deadline_exceeded_at is not None
        assert (
            session.scalar(
                select(func.count())
                .select_from(ToolExecutionRow)
                .where(ToolExecutionRow.adapter_id == "osv.dev")
            )
            == 0
        )

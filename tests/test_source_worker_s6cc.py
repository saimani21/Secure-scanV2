from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from securescan.domain.enums import ExecutionOutcome
from securescan.jobs.execution import JobExecutionService
from securescan.orchestration.dependency_evaluation import (
    SourceDependencyEvaluationService,
)
from securescan.orchestration.execution import SourceScannerExecutionConflictError
from securescan.orchestration.execution_models import (
    AttemptContainmentOutcome,
    SourceAttemptCleanupReceipt,
)
from securescan.orchestration.local_execution import SourceLocalBridgeExecutionService
from securescan.orchestration.models import (
    SourceAuthority,
    SourceOrchestrationIntegrityError,
    frozen_source_v1_authority_roster,
    orchestration_request_digest,
)
from securescan.orchestration.osv_execution import (
    SourceOsvAttemptService,
    SourceOsvJobService,
    SourceOsvRequestPermitService,
)
from securescan.orchestration.osv_runtime import SourceOsvHelperExecutionService
from securescan.orchestration.production import (
    SourceProductionDispatcherDependencies,
    create_source_production_authority_dispatcher,
)
from securescan.orchestration.service import SourceOrchestrationService
from securescan.orchestration.worker import (
    SourceAuthorityDispatcher,
    SourceMappedJobLeasingService,
    SourceOrchestrationWorkerCycle,
    SourceWorkerDisposition,
    SourceWorkerError,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
)
from securescan.scanners.checkov import create_default_checkov_binding
from securescan.scanners.gitleaks import create_default_gitleaks_binding
from securescan.scanners.semgrep import load_source_ruleset
from securescan.scanners.syft import create_default_syft_binding
from tests.test_source_orchestration_s6b import (
    _LEASE_TOKEN,
    _NOW,
    _RUN_ID,
    _SEMGREP_FIXTURE,
    _Environment,
    _register_running_attempt,
    _SandboxRunner,
    _semgrep_docker_contract,
)
from tests.test_source_osv_execution_s6cb import _runnable, _start_osv_attempt


@pytest.fixture
def worker_environment(tmp_path):
    environment = _Environment(tmp_path)
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
    try:
        yield environment
    finally:
        environment.close()


def test_dispatcher_requires_exact_five_authorities() -> None:
    with pytest.raises(SourceWorkerError):
        SourceAuthorityDispatcher({})


def test_worker_refuses_unmapped_source_job(
    worker_environment: _Environment,
) -> None:
    environment = worker_environment
    with environment.factory.begin() as session:
        session.add(
            JobRow(
                id="88888888-8888-4888-8888-888888888888",
                run_id=str(_RUN_ID),
                adapter_id="gitleaks",
                status="queued",
                available_at=_NOW,
                idempotency_key="8" * 64,
                payload_json={},
            )
        )

    leasing = SourceMappedJobLeasingService(
        environment.factory,
        clock=lambda: _NOW,
        token_factory=lambda: __import__("uuid").UUID(_LEASE_TOKEN),
    )
    assert leasing.lease_next(worker_id="source-worker") is None
    with environment.factory() as session:
        unmapped = session.get(JobRow, "88888888-8888-4888-8888-888888888888")
        assert unmapped is not None
        assert unmapped.status == "queued"
        assert unmapped.lease_token is None


def test_per_run_default_allows_only_two_active_leases(
    worker_environment: _Environment,
) -> None:
    environment = worker_environment
    for authority in (
        SourceAuthority.SEMGREP,
        SourceAuthority.GITLEAKS,
        SourceAuthority.SYFT,
        SourceAuthority.CHECKOV,
    ):
        environment.create(authority)
    tokens = iter(
        __import__("uuid").UUID(f"99999999-9999-4999-8999-{value:012d}") for value in range(1, 5)
    )
    leasing = SourceMappedJobLeasingService(
        environment.factory,
        clock=lambda: _NOW,
        token_factory=lambda: next(tokens),
    )

    first = leasing.lease_next(worker_id="worker-one")
    second = leasing.lease_next(worker_id="worker-two")
    assert first is not None and second is not None
    assert leasing.lease_next(worker_id="worker-three") is None
    with environment.factory.begin() as session:
        completed = session.get(JobRow, first.id)
        assert completed is not None
        completed.status = "succeeded"
        completed.leased_by = None
        completed.lease_token = None
        completed.lease_expires_at = None
    third = leasing.lease_next(worker_id="worker-three")
    assert third is not None
    with environment.factory() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None and parent.max_active_jobs == 2


@pytest.mark.parametrize("ceiling", [0, 5, True])
def test_server_rejects_concurrency_ceiling_outside_frozen_range(
    worker_environment: _Environment, ceiling: object
) -> None:
    with pytest.raises(SourceOrchestrationIntegrityError):
        SourceOrchestrationService(
            worker_environment.factory,
            worker_environment.store,
            frozen_source_v1_authority_roster(),
            max_active_jobs=ceiling,  # type: ignore[arg-type]
        )


def test_reconciliation_required_attempt_retains_a_concurrency_slot(
    worker_environment: _Environment,
) -> None:
    environment = worker_environment
    first_node, _first = environment.create(SourceAuthority.GITLEAKS)
    environment.create(SourceAuthority.SYFT)
    environment.create(SourceAuthority.CHECKOV)
    leasing = SourceMappedJobLeasingService(
        environment.factory,
        clock=lambda: _NOW,
        token_factory=lambda: __import__("uuid").UUID(_LEASE_TOKEN),
    )
    leased = leasing.lease_next(worker_id="reconciliation-worker")
    assert leased is not None and leased.lease_token is not None
    running = JobExecutionService(environment.factory, clock=lambda: _NOW).start_job(
        leased.id, "reconciliation-worker", leased.lease_token
    )
    attempt = environment.attempts.register_attempt(
        job_id=running.id,
        worker_id="reconciliation-worker",
        lease_token=leased.lease_token,
    )
    with environment.factory.begin() as session:
        job = session.get(JobRow, leased.id)
        durable_attempt = session.get(
            SourceOrchestrationAttemptRow, (leased.id, attempt.attempt_number)
        )
        node = session.get(SourceOrchestrationNodeRow, first_node.node_id)
        assert job is not None and durable_attempt is not None and node is not None
        job.status = "failed"
        job.leased_by = None
        job.lease_token = None
        job.lease_expires_at = None
        durable_attempt.containment_state = "RECONCILIATION_REQUIRED"
        node.lifecycle_state = "RECONCILIATION_REQUIRED"
        node.containment_state = "RECONCILIATION_REQUIRED"
    assert leasing.lease_next(worker_id="second-worker") is not None
    assert leasing.lease_next(worker_id="third-worker") is None


def _production_dispatcher(
    environment: _Environment,
    tmp_path: Path,
    *,
    docker_runner=None,
    semgrep_image: str | None = None,
):
    evaluations = SourceDependencyEvaluationService(environment.factory, environment.store)
    osv_jobs = SourceOsvJobService(environment.factory, environment.store, evaluations)
    osv_helper = SourceOsvHelperExecutionService(
        environment.factory,
        osv_jobs,
        environment.attempts,
        SourceOsvAttemptService(environment.factory, environment.store, osv_jobs),
        SourceOsvRequestPermitService(environment.factory),
        tmp_path / "osv-receipts",
    )
    semgrep_options = {} if semgrep_image is None else {"image_reference": semgrep_image}
    _definition, semgrep_binding = _semgrep_docker_contract(
        environment, tmp_path, **semgrep_options
    )
    return create_source_production_authority_dispatcher(
        SourceProductionDispatcherDependencies(
            session_factory=environment.factory,
            artifact_store=environment.store,
            projection_manager=environment.projections,
            attempt_service=environment.attempts,
            local_bridge=SourceLocalBridgeExecutionService(
                environment.store,
                environment.projections,
                environment.attempts,
                tmp_path / "local-receipts",
            ),
            osv_helper=osv_helper,
            semgrep_binding=semgrep_binding,
            semgrep_ruleset=load_source_ruleset(),
            gitleaks_binding=create_default_gitleaks_binding(
                Path.home() / ".local/securescan-tools/gitleaks/8.30.1/gitleaks"
            ),
            syft_binding=create_default_syft_binding(
                Path(".venv-syft-1.51/bin/syft").resolve(strict=True)
            ),
            checkov_binding=create_default_checkov_binding(
                Path(".venv-checkov-3.3.16/bin/checkov").resolve(strict=True)
            ),
            semgrep_workspace_root=(tmp_path / "semgrep-production").resolve(),
            semgrep_docker_runner=docker_runner,
        )
    )


def test_production_composition_binds_all_five_frozen_execution_paths(
    worker_environment: _Environment,
    tmp_path: Path,
) -> None:
    dispatcher = _production_dispatcher(worker_environment, tmp_path)

    assert {
        authority: type(runner).__name__ for authority, runner in dispatcher._runners.items()
    } == {
        SourceAuthority.SEMGREP: "_SemgrepRunner",
        SourceAuthority.GITLEAKS: "_LocalBridgeRunner",
        SourceAuthority.SYFT: "_LocalBridgeRunner",
        SourceAuthority.OSV: "_OsvRunner",
        SourceAuthority.CHECKOV: "_LocalBridgeRunner",
    }
    assert dispatcher._runners[SourceAuthority.GITLEAKS]._bridge.start_gitleaks
    assert dispatcher._runners[SourceAuthority.SYFT]._bridge.start_syft
    assert dispatcher._runners[SourceAuthority.CHECKOV]._bridge.start_checkov
    assert dispatcher._runners[SourceAuthority.OSV]._service.execute
    assert dispatcher._runners[SourceAuthority.SEMGREP]._binding.core_adapter_id == "semgrep-ce"
    assert dispatcher._runners[SourceAuthority.SEMGREP]._ruleset == load_source_ruleset()


def test_production_dispatcher_rejects_old_placeholder_semgrep_binding(
    worker_environment: _Environment,
    tmp_path: Path,
) -> None:
    old_placeholder = "registry.example/securescan/semgrep@sha256:" + "4" * 64
    with pytest.raises(SourceScannerExecutionConflictError):
        _production_dispatcher(
            worker_environment,
            tmp_path,
            semgrep_image=old_placeholder,
        )


@pytest.mark.parametrize(
    ("authority", "bridge_method"),
    [
        (SourceAuthority.GITLEAKS, "start_gitleaks"),
        (SourceAuthority.SYFT, "start_syft"),
        (SourceAuthority.CHECKOV, "start_checkov"),
    ],
)
def test_production_local_handlers_use_existing_job_attempt_and_guarded_acceptance(
    worker_environment: _Environment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority: SourceAuthority,
    bridge_method: str,
) -> None:
    environment = worker_environment
    node, created, attempt = _register_running_attempt(environment, authority)
    native = environment.native_result(node, created)

    class Handle:
        def poll(self):
            return native

        def close(self) -> None:
            environment.attempts.register_supervisor(
                job_id=created.job_id,
                attempt_number=attempt.attempt_number,
                attempt_token=attempt.attempt_token,
                supervisor_identity="a" * 64,
                supervisor_pid=999_991,
                supervisor_start_ticks=101,
                scanner_pid=999_992,
                scanner_pgid=999_992,
                scanner_start_ticks=102,
            )
            environment.attempts.record_cleanup(
                SourceAttemptCleanupReceipt(
                    job_id=created.job_id,
                    attempt_number=attempt.attempt_number,
                    attempt_token=attempt.attempt_token,
                    supervisor_identity="a" * 64,
                    supervisor_pid=999_991,
                    supervisor_start_ticks=101,
                    scanner_pid=999_992,
                    scanner_pgid=999_992,
                    scanner_start_ticks=102,
                    cleanup_outcome=AttemptContainmentOutcome.CLEAN,
                    process_tree_empty=True,
                )
            )

    calls: list[tuple[str, int]] = []

    def start_bridge(_service, *, job, attempt, binding):
        del binding
        calls.append((job.id, attempt.attempt_number))
        return Handle()

    monkeypatch.setattr(SourceLocalBridgeExecutionService, bridge_method, start_bridge)
    dispatcher = _production_dispatcher(environment, tmp_path)
    with environment.factory() as session:
        from securescan.jobs.mappers import job_record_from_row

        row = session.get(JobRow, created.job_id)
        assert row is not None
        job = job_record_from_row(row)
        before = session.query(SourceOrchestrationScannerJobRow).count()
    dispatcher.dispatch(authority, job, attempt)

    with environment.factory() as session:
        durable = session.get(JobRow, created.job_id)
        mapping = session.get(SourceOrchestrationScannerJobRow, created.job_id)
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert durable is not None and durable.status == "succeeded"
        assert mapping is not None and mapping.selected_attempt_number == 1
        assert session.query(SourceOrchestrationScannerJobRow).count() == before == 1
        assert run is not None and run.report_json is None
    assert calls == [(created.job_id, 1)]


def test_production_semgrep_handler_uses_attempt_bound_frozen_docker_adapter(
    worker_environment: _Environment,
    tmp_path: Path,
) -> None:
    environment = worker_environment
    _node, created, attempt = _register_running_attempt(environment, SourceAuthority.SEMGREP)
    docker_runner = _SandboxRunner(semgrep_result=_SEMGREP_FIXTURE.read_bytes())
    dispatcher = _production_dispatcher(environment, tmp_path, docker_runner=docker_runner)
    with environment.factory() as session:
        from securescan.jobs.mappers import job_record_from_row

        row = session.get(JobRow, created.job_id)
        assert row is not None
        job = job_record_from_row(row)
    dispatcher.dispatch(SourceAuthority.SEMGREP, job, attempt)

    with environment.factory() as session:
        mapping = session.get(SourceOrchestrationScannerJobRow, created.job_id)
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert mapping is not None and mapping.selected_attempt_number == 1
        assert run is not None and run.report_json is None
        assert session.query(SourceOrchestrationScannerJobRow).count() == 1
    assert [command[1] for command in docker_runner.commands] == [
        "version",
        "image",
        "create",
        "start",
        "inspect",
        "rm",
        "inspect",
    ]


def test_production_osv_handler_invokes_helper_for_dependency_gated_job(
    worker_environment: _Environment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = worker_environment
    _osv, _evaluation, _jobs, created = _runnable(environment)
    attempt = _start_osv_attempt(environment, created)
    calls: list[tuple[str, int, str]] = []

    def execute(_service, *, job, attempt, lease_token):
        calls.append((job.id, attempt.attempt_number, lease_token))

    monkeypatch.setattr(SourceOsvHelperExecutionService, "execute", execute)
    dispatcher = _production_dispatcher(environment, tmp_path)
    with environment.factory() as session:
        from securescan.jobs.mappers import job_record_from_row

        row = session.get(JobRow, created.job_id)
        assert row is not None
        job = job_record_from_row(row)
        before = session.query(SourceOrchestrationScannerJobRow).count()
    dispatcher.dispatch(SourceAuthority.OSV, job, attempt)
    with environment.factory() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert session.query(SourceOrchestrationScannerJobRow).count() == before
        assert run is not None and run.report_json is None
    assert calls == [(created.job_id, 1, job.lease_token)]


@pytest.mark.parametrize("boundary", ["cancellation", "deadline"])
def test_production_handler_rejects_parent_boundary_before_bridge_dispatch(
    worker_environment: _Environment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    environment = worker_environment
    _node, created, attempt = _register_running_attempt(environment, SourceAuthority.GITLEAKS)
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None
        if boundary == "cancellation":
            parent.cancel_requested = True
            parent.lifecycle_state = "CANCELLATION_REQUESTED"
        else:
            parent.deadline_at = datetime(2000, 1, 1, tzinfo=UTC)
    monkeypatch.setattr(
        SourceLocalBridgeExecutionService,
        "start_gitleaks",
        lambda *_args, **_kwargs: pytest.fail("bridge must not start"),
    )
    dispatcher = _production_dispatcher(environment, tmp_path)
    with environment.factory() as session:
        from securescan.jobs.mappers import job_record_from_row

        row = session.get(JobRow, created.job_id)
        assert row is not None
        job = job_record_from_row(row)
    with pytest.raises(SourceScannerExecutionConflictError):
        dispatcher.dispatch(SourceAuthority.GITLEAKS, job, attempt)


def test_production_handler_rejects_wrong_authority_and_node_identity(
    worker_environment: _Environment,
    tmp_path: Path,
) -> None:
    environment = worker_environment
    _node, created, attempt = _register_running_attempt(environment, SourceAuthority.GITLEAKS)
    dispatcher = _production_dispatcher(environment, tmp_path)
    with environment.factory() as session:
        from securescan.jobs.mappers import job_record_from_row

        row = session.get(JobRow, created.job_id)
        assert row is not None
        job = job_record_from_row(row)
    with pytest.raises(SourceScannerExecutionConflictError):
        dispatcher.dispatch(SourceAuthority.SYFT, job, attempt)
    with pytest.raises(SourceScannerExecutionConflictError):
        dispatcher.dispatch(
            SourceAuthority.GITLEAKS,
            job,
            replace(attempt, node_id="f" * 64),
        )


def test_worker_leases_only_mapped_job_and_dispatches_exact_authority(
    worker_environment: _Environment,
) -> None:
    environment = worker_environment
    node, _created = environment.create(SourceAuthority.GITLEAKS)
    called = []

    def gitleaks_runner(job, attempt) -> None:
        called.append(SourceAuthority.GITLEAKS)
        environment.attempts.register_supervisor(
            job_id=job.id,
            attempt_number=attempt.attempt_number,
            attempt_token=attempt.attempt_token,
            supervisor_identity="a" * 64,
            supervisor_pid=999_991,
            supervisor_start_ticks=101,
            scanner_pid=999_992,
            scanner_pgid=999_992,
            scanner_start_ticks=102,
        )
        environment.attempts.record_cleanup(
            SourceAttemptCleanupReceipt(
                job_id=job.id,
                attempt_number=attempt.attempt_number,
                attempt_token=attempt.attempt_token,
                supervisor_identity="a" * 64,
                supervisor_pid=999_991,
                supervisor_start_ticks=101,
                scanner_pid=999_992,
                scanner_pgid=999_992,
                scanner_start_ticks=102,
                cleanup_outcome=AttemptContainmentOutcome.CLEAN,
                process_tree_empty=True,
            )
        )
        bound = environment.jobs.create_job(
            run_id=str(_RUN_ID), node_id=node.node_id, workspace=environment.workspace
        )
        environment.attempts.accept_result(
            environment.native_result(node, bound),
            lease_token=job.lease_token or _LEASE_TOKEN,
            execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            return_code=0,
            duration_ms=1,
        )

    def unexpected(_job, _attempt) -> None:
        raise AssertionError

    dispatcher = SourceAuthorityDispatcher(
        {
            SourceAuthority.SEMGREP: unexpected,
            SourceAuthority.GITLEAKS: gitleaks_runner,
            SourceAuthority.SYFT: unexpected,
            SourceAuthority.OSV: unexpected,
            SourceAuthority.CHECKOV: unexpected,
        }
    )
    leasing = SourceMappedJobLeasingService(
        environment.factory,
        clock=lambda: _NOW,
        token_factory=lambda: __import__("uuid").UUID(_LEASE_TOKEN),
    )
    cycle = SourceOrchestrationWorkerCycle(
        environment.factory,
        leasing,
        environment.attempts,
        dispatcher,
        worker_id="source-worker",
        clock=lambda: _NOW,
    )

    result = cycle.run_one()
    assert result.disposition is SourceWorkerDisposition.DISPATCHED
    assert result.authority is SourceAuthority.GITLEAKS
    assert called == [SourceAuthority.GITLEAKS]
    assert cycle.run_one().disposition is SourceWorkerDisposition.IDLE

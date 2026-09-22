from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy import func, select
from typer.testing import CliRunner

from securescan.cli.main import app
from securescan.config import Settings
from securescan.domain.enums import ExecutionOutcome
from securescan.orchestration.assembly import (
    SourceAssemblyFailureRecord,
    SourceResultAssemblyService,
)
from securescan.orchestration.coordinator import SourceOrchestrationCoordinatorService
from securescan.orchestration.execution import (
    SourceScannerAttemptService,
    SourceScannerLeaseReconciliationService,
)
from securescan.orchestration.models import (
    OrchestrationNodeDisposition,
    SourceAuthority,
    frozen_source_v1_authority_roster,
    orchestration_request_digest,
)
from securescan.orchestration.worker import (
    SourceAuthorityDispatcher,
    SourceMappedJobLeasingService,
    SourceOrchestrationWorkerCycle,
    SourceWorkerDisposition,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    SourceScanSubmissionRow,
    TargetRow,
)
from securescan.product_core import (
    ProductFinalizationBatchResult,
    SourceProductFinalizationRunner,
    SourceScanSubmissionService,
)
from securescan.runtime_storage import initialize_source_runtime_storage
from securescan.source_runtime import (
    SourceRuntimeCandidate,
    SourceRuntimeCandidateState,
    SourceRuntimeCycleSummary,
    SourceRuntimeError,
    SourceRuntimeLimits,
    SourceRuntimeService,
    SourceRuntimeWorkDiscovery,
    create_source_runtime,
)
from tests.test_source_dependency_evaluation_s6ca import (
    _finish_existing_syft,
    _observation,
)
from tests.test_source_engine_closure import _record_local_cleanup
from tests.test_source_orchestration_s6b import _LEASE_TOKEN, _RUN_ID, _Environment

_DEFAULT_TEST_LIMITS = SourceRuntimeLimits()


class _Discovery:
    def __init__(
        self,
        candidates: tuple[SourceRuntimeCandidate, ...] = (),
        assemblies: tuple[str, ...] = (),
    ) -> None:
        self.candidates = candidates
        self.assemblies = assemblies
        self.orchestration_limits: list[int] = []
        self.assembly_limits: list[int] = []

    def orchestration_candidates(self, *, limit: int) -> tuple[SourceRuntimeCandidate, ...]:
        self.orchestration_limits.append(limit)
        return self.candidates[:limit]

    def assembly_candidates(self, *, limit: int) -> tuple[str, ...]:
        self.assembly_limits.append(limit)
        return self.assemblies[:limit]


class _Workspaces:
    def __init__(self, *, reject: frozenset[str] = frozenset()) -> None:
        self.reject = reject
        self.calls: list[str] = []
        self.workspace = SimpleNamespace()

    def resolve_workspace(self, *, run_id: str):
        self.calls.append(run_id)
        if run_id in self.reject:
            raise RuntimeError("private workspace failure")
        return self.workspace


class _Coordinator:
    def __init__(self, *, changed: bool = True) -> None:
        self.changed = changed
        self.calls: list[tuple[str, object | None]] = []

    def advance(self, *, run_id: str, workspace=None):
        self.calls.append((run_id, workspace))
        return SimpleNamespace(state_changed=self.changed)


class _Worker:
    def __init__(self, dispositions: list[SourceWorkerDisposition] | None = None) -> None:
        self.dispositions = dispositions or []
        self.calls = 0

    def run_one(self):
        self.calls += 1
        disposition = (
            self.dispositions.pop(0) if self.dispositions else SourceWorkerDisposition.IDLE
        )
        return SimpleNamespace(disposition=disposition)


class _Reconciliation:
    def __init__(self, count: int = 0) -> None:
        self.count = count
        self.limits: list[int] = []

    def quarantine_expired(self, *, limit: int) -> tuple[object, ...]:
        self.limits.append(limit)
        return tuple(object() for _ in range(min(limit, self.count)))


class _Assembly:
    def __init__(self, *, failing: frozenset[str] = frozenset()) -> None:
        self.failing = failing
        self.calls: list[str] = []
        self.failures: list[tuple[str, str]] = []

    def assemble_and_publish(self, run_id: str):
        self.calls.append(run_id)
        if run_id in self.failing:
            raise RuntimeError("private assembly failure")
        return SimpleNamespace(published=True)

    def record_failure(self, run_id, failure):
        self.failures.append((run_id, failure.reason_code))
        return SourceAssemblyFailureRecord(
            run_id=run_id,
            attempt_count=1,
            reason_code=failure.reason_code,
            retryable=failure.retryable,
            terminalized=True,
        )


class _Finalizer:
    def __init__(
        self,
        *,
        examined: int = 0,
        finalized: int = 0,
        already: int = 0,
        not_ready: int = 0,
        failed: int = 0,
    ) -> None:
        self.result = ProductFinalizationBatchResult(
            examined_count=examined,
            finalized_count=finalized,
            already_finalized_count=already,
            not_ready_count=not_ready,
            failed_count=failed,
            outcomes=(),
        )
        self.limits: list[int] = []

    def finalize_ready(self, *, limit: int) -> ProductFinalizationBatchResult:
        self.limits.append(limit)
        return self.result


@dataclass
class _RuntimeHarness:
    runtime: SourceRuntimeService
    discovery: _Discovery
    workspaces: _Workspaces
    coordinator: _Coordinator
    worker: _Worker
    reconciliation: _Reconciliation
    assembly: _Assembly
    finalizer: _Finalizer


def _runtime(
    *,
    candidates: tuple[SourceRuntimeCandidate, ...] = (),
    assemblies: tuple[str, ...] = (),
    worker_dispositions: list[SourceWorkerDisposition] | None = None,
    reject_workspaces: frozenset[str] = frozenset(),
    reconciliation_count: int = 0,
    finalizer: _Finalizer | None = None,
    limits: SourceRuntimeLimits = _DEFAULT_TEST_LIMITS,
) -> _RuntimeHarness:
    discovery = _Discovery(candidates, assemblies)
    workspaces = _Workspaces(reject=reject_workspaces)
    coordinator = _Coordinator()
    worker = _Worker(worker_dispositions)
    reconciliation = _Reconciliation(reconciliation_count)
    assembly = _Assembly()
    trusted_finalizer = finalizer or _Finalizer()
    runtime = SourceRuntimeService(
        discovery=discovery,
        workspace_resolver=workspaces,
        coordinator=coordinator,
        worker=worker,
        reconciliation=reconciliation,
        assembly=assembly,
        finalizer=trusted_finalizer,
        limits=limits,
    )
    return _RuntimeHarness(
        runtime,
        discovery,
        workspaces,
        coordinator,
        worker,
        reconciliation,
        assembly,
        trusted_finalizer,
    )


def _candidate(run_id: str, *, cancelled: bool = False) -> SourceRuntimeCandidate:
    return SourceRuntimeCandidate(
        run_id=run_id,
        lifecycle_state=(
            SourceRuntimeCandidateState.CANCELLATION_REQUESTED
            if cancelled
            else SourceRuntimeCandidateState.ACTIVE
        ),
    )


def test_no_work_run_once_is_bounded_and_successful() -> None:
    harness = _runtime()

    summary = harness.runtime.run_once()

    assert summary.canonical_data() == {
        "already_finalized_count": 0,
        "assembly_examined_count": 0,
        "assembly_failed_count": 0,
        "assembly_published_count": 0,
        "finalization_examined_count": 0,
        "finalization_failed_count": 0,
        "finalization_not_ready_count": 0,
        "finalized_count": 0,
        "jobs_dispatched_count": 0,
        "post_advance_attempted_count": 0,
        "post_advance_changed_count": 0,
        "post_advance_examined_count": 0,
        "post_advance_failed_count": 0,
        "pre_advance_attempted_count": 0,
        "pre_advance_changed_count": 0,
        "pre_advance_examined_count": 0,
        "pre_advance_failed_count": 0,
        "reconciled_attempt_count": 0,
    }
    assert harness.worker.calls == 1


def test_cycle_obeys_every_server_owned_bound() -> None:
    limits = SourceRuntimeLimits(
        max_orchestration_advances_per_cycle=2,
        max_jobs_per_cycle=2,
        max_reconciliations_per_cycle=2,
        max_assemblies_per_cycle=2,
        max_finalizations_per_cycle=2,
    )
    harness = _runtime(
        candidates=tuple(_candidate(f"run-{number}") for number in range(3)),
        assemblies=("assembly-a", "assembly-b", "assembly-c"),
        worker_dispositions=[
            SourceWorkerDisposition.DISPATCHED,
            SourceWorkerDisposition.DISPATCHED,
            SourceWorkerDisposition.DISPATCHED,
        ],
        reconciliation_count=3,
        limits=limits,
    )

    summary = harness.runtime.run_once()

    assert summary.reconciled_attempt_count == 2
    assert summary.pre_advance_examined_count == 2
    assert summary.pre_advance_attempted_count == 2
    assert summary.jobs_dispatched_count == 2
    assert summary.post_advance_examined_count == 0
    assert summary.post_advance_attempted_count == 0
    assert summary.assembly_examined_count == 2
    assert harness.worker.calls == 2
    assert harness.discovery.orchestration_limits == [200]
    assert harness.discovery.assembly_limits == [2]


def test_active_candidate_uses_only_trusted_workspace_resolver() -> None:
    harness = _runtime(candidates=(_candidate("run-a"),))

    harness.runtime.run_once()

    assert harness.workspaces.calls == ["run-a", "run-a"]
    assert harness.coordinator.calls == [
        ("run-a", harness.workspaces.workspace),
        ("run-a", harness.workspaces.workspace),
    ]


def test_missing_managed_workspace_fails_closed_without_a_workspace() -> None:
    harness = _runtime(
        candidates=(_candidate("run-a"),),
        reject_workspaces=frozenset({"run-a"}),
    )

    with pytest.raises(SourceRuntimeError, match="Source runtime cycle failed"):
        harness.runtime.run_once()

    assert harness.coordinator.calls == []
    assert harness.worker.calls == 0


def test_invalid_candidate_stops_before_later_work_or_worker_dispatch() -> None:
    harness = _runtime(
        candidates=(_candidate("invalid"), _candidate("valid")),
        reject_workspaces=frozenset({"invalid"}),
        limits=SourceRuntimeLimits(max_orchestration_advances_per_cycle=2),
    )

    with pytest.raises(SourceRuntimeError, match="Source runtime cycle failed"):
        harness.runtime.run_once()

    assert harness.coordinator.calls == []
    assert harness.worker.calls == 0


def test_cancellation_never_resolves_or_supplies_workspace() -> None:
    harness = _runtime(candidates=(_candidate("run-a", cancelled=True),))

    harness.runtime.run_once()

    assert harness.workspaces.calls == []
    assert harness.coordinator.calls == [("run-a", None), ("run-a", None)]


def test_ready_assembly_and_published_finalization_delegate_once() -> None:
    finalizer = _Finalizer(examined=2, finalized=1, already=1)
    harness = _runtime(assemblies=("run-a",), finalizer=finalizer)

    summary = harness.runtime.run_once()

    assert harness.assembly.calls == ["run-a"]
    assert summary.assembly_published_count == 1
    assert summary.finalization_examined_count == 2
    assert summary.finalized_count == 1
    assert summary.already_finalized_count == 1
    assert finalizer.limits == [25]


def test_blocked_predecessor_remains_not_ready_for_authoritative_finalizer() -> None:
    finalizer = _Finalizer(examined=1, not_ready=1)
    harness = _runtime(finalizer=finalizer)

    summary = harness.runtime.run_once()

    assert summary.finalization_examined_count == 1
    assert summary.finalization_not_ready_count == 1
    assert summary.finalized_count == 0
    assert summary.finalization_failed_count == 0


def test_assembly_failure_is_isolated_recorded_and_safely_logged(caplog) -> None:
    harness = _runtime(assemblies=("run-a", "run-b"))
    harness.assembly.failing = frozenset({"run-a"})

    with caplog.at_level("ERROR", logger="securescan.source_runtime"):
        summary = harness.runtime.run_once()

    assert summary.assembly_examined_count == 2
    assert summary.assembly_failed_count == 1
    assert summary.assembly_published_count == 1
    assert harness.assembly.failures == [("run-a", "ASSEMBLY_UNEXPECTED_FAILURE")]
    assert "private assembly failure" not in caplog.text
    assert "run_id=run-a" in caplog.text
    assert "exception_class=RuntimeError" in caplog.text
    assert "reason_code=ASSEMBLY_UNEXPECTED_FAILURE" in caplog.text


def test_fresh_runtime_instances_resume_bounded_durable_worker_queue() -> None:
    worker = _Worker([SourceWorkerDisposition.DISPATCHED, SourceWorkerDisposition.DISPATCHED])
    limits = SourceRuntimeLimits(max_jobs_per_cycle=1)

    def fresh() -> SourceRuntimeService:
        return SourceRuntimeService(
            discovery=_Discovery(),
            workspace_resolver=_Workspaces(),
            coordinator=_Coordinator(),
            worker=worker,
            reconciliation=_Reconciliation(),
            assembly=_Assembly(),
            finalizer=_Finalizer(),
            limits=limits,
        )

    assert fresh().run_once().jobs_dispatched_count == 1
    assert fresh().run_once().jobs_dispatched_count == 1
    assert worker.calls == 2


def test_reconciliation_required_work_is_counted_and_not_dispatched_when_idle() -> None:
    harness = _runtime(reconciliation_count=1)

    summary = harness.runtime.run_once()

    assert summary.reconciled_attempt_count == 1
    assert summary.jobs_dispatched_count == 0


def test_unknown_worker_disposition_fails_closed() -> None:
    harness = _runtime()
    harness.worker.run_one = lambda: SimpleNamespace(disposition="UNTRUSTED")  # type: ignore[method-assign]

    with pytest.raises(SourceRuntimeError, match="Source runtime cycle failed"):
        harness.runtime.run_once()


def test_summary_cannot_expose_paths_tokens_or_raw_streams() -> None:
    raw_secret = "RAW_RUNTIME_SECRET"
    path = "/private/source/repository"
    harness = _runtime(
        candidates=(_candidate(raw_secret),),
        assemblies=(path,),
    )

    rendered = repr(harness.runtime.run_once())

    assert raw_secret not in rendered
    assert path not in rendered
    assert "stdout" not in rendered
    assert "stderr" not in rendered
    assert "token" not in rendered


def test_invalid_limits_fail_closed() -> None:
    with pytest.raises(SourceRuntimeError):
        SourceRuntimeLimits(max_jobs_per_cycle=0)
    with pytest.raises(SourceRuntimeError):
        SourceRuntimeLimits(max_jobs_per_cycle=201)


def test_cli_worker_once_prints_only_canonical_safe_summary(monkeypatch) -> None:
    summary = SourceRuntimeCycleSummary(*(0 for _ in range(18)))

    class _Composition:
        runtime = SimpleNamespace(run_once=lambda: summary)

    class _Context:
        def __enter__(self):
            return _Composition()

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr("securescan.cli.main.create_source_runtime", _Context)

    result = CliRunner().invoke(app, ["worker", "--once"])

    assert result.exit_code == 0
    assert result.stdout == (
        '{"already_finalized_count":0,"assembly_examined_count":0,'
        '"assembly_failed_count":0,"assembly_published_count":0,'
        '"finalization_examined_count":0,"finalization_failed_count":0,'
        '"finalization_not_ready_count":0,"finalized_count":0,'
        '"jobs_dispatched_count":0,"post_advance_attempted_count":0,'
        '"post_advance_changed_count":0,'
        '"post_advance_examined_count":0,"post_advance_failed_count":0,'
        '"pre_advance_attempted_count":0,"pre_advance_changed_count":0,'
        '"pre_advance_examined_count":0,'
        '"pre_advance_failed_count":0,"reconciled_attempt_count":0}\n'
    )


def test_cli_worker_returns_nonzero_when_authoritative_stage_failed(monkeypatch) -> None:
    summary = replace(
        SourceRuntimeCycleSummary(*(0 for _ in range(18))),
        assembly_failed_count=1,
    )

    class _Composition:
        runtime = SimpleNamespace(run_once=lambda: summary)

    class _Context:
        def __enter__(self):
            return _Composition()

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr("securescan.cli.main.create_source_runtime", _Context)

    result = CliRunner().invoke(app, ["worker", "--once"])

    assert result.exit_code == 5
    assert result.stdout == ""
    assert '"assembly_failed_count":1' in result.stderr


def test_cli_worker_composition_failure_is_sanitized(monkeypatch) -> None:
    def fail():
        raise SourceRuntimeError

    monkeypatch.setattr("securescan.cli.main.create_source_runtime", fail)

    result = CliRunner().invoke(app, ["worker", "--once"])

    assert result.exit_code == 5
    assert result.stdout == ""
    assert result.stderr == ("Error [RUNTIME_UNAVAILABLE]: Source runtime cycle is unavailable\n")
    assert "Traceback" not in result.stderr


def test_runtime_receipt_root_is_normalized(tmp_path: Path) -> None:
    settings = Settings(source_runtime_receipt_root=tmp_path / "receipts" / ".." / "safe")

    assert settings.source_runtime_receipt_root == (tmp_path / "safe").resolve()


def _prepare_product_submission(environment: _Environment, *, expired: bool = False):
    deadline = datetime(2020, 1, 1, tzinfo=UTC) if expired else datetime(2099, 1, 1, tzinfo=UTC)
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert parent is not None and run is not None
        target = session.get(TargetRow, run.target_id)
        assert target is not None
        target.source_path = environment.workspace.workspace_id
        parent.deadline_at = deadline
        parent.creation_request_digest = orchestration_request_digest(
            target_id=run.target_id,
            idempotency_key=parent.idempotency_key,
            deadline_iso=deadline.isoformat(),
            profile_digest=parent.profile_digest,
            plan_digest=parent.plan_digest,
            roster_digest=parent.roster_digest,
        )
        project_id = target.project_id
    submissions = SourceScanSubmissionService(
        environment.factory,
        environment.store,
        environment.workspace_manager,
    )
    lineage = submissions.create_lineage(project_id=project_id)
    submissions.reserve(
        run_id=str(_RUN_ID),
        lineage_id=lineage.lineage_id,
        intake_ref=environment.workspace.workspace_id,
    )
    return submissions


def _local_accepting_dispatcher(environment: _Environment) -> SourceAuthorityDispatcher:
    def runner(authority: SourceAuthority):
        def accept(job, attempt) -> None:
            node = next(item for item in environment.snapshot.nodes if item.authority is authority)
            _record_local_cleanup(environment, authority, attempt)
            bound = environment.jobs.create_job(
                run_id=str(_RUN_ID),
                node_id=node.node_id,
                workspace=environment.workspace,
            )
            environment.attempts.accept_result(
                environment.native_result(node, bound),
                lease_token=job.lease_token or _LEASE_TOKEN,
                execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
                return_code=0,
                duration_ms=1,
            )

        return accept

    def unexpected_osv(_job, _attempt) -> None:
        raise AssertionError("zero-package flow attempted OSV execution")

    return SourceAuthorityDispatcher(
        {
            SourceAuthority.SEMGREP: runner(SourceAuthority.SEMGREP),
            SourceAuthority.GITLEAKS: runner(SourceAuthority.GITLEAKS),
            SourceAuthority.SYFT: runner(SourceAuthority.SYFT),
            SourceAuthority.CHECKOV: runner(SourceAuthority.CHECKOV),
            SourceAuthority.OSV: unexpected_osv,
        }
    )


def _durable_runtime(
    environment: _Environment,
    submissions: SourceScanSubmissionService,
    *,
    worker,
    max_jobs: int = 1,
) -> SourceRuntimeService:
    return SourceRuntimeService(
        discovery=SourceRuntimeWorkDiscovery(environment.factory),
        workspace_resolver=submissions,
        coordinator=SourceOrchestrationCoordinatorService(
            environment.factory,
            environment.store,
            frozen_source_v1_authority_roster(),
            environment.projections,
        ),
        worker=worker,
        reconciliation=SourceScannerLeaseReconciliationService(environment.factory),
        assembly=SourceResultAssemblyService(environment.factory, environment.store),
        finalizer=SourceProductFinalizationRunner(environment.factory, submissions),
        limits=SourceRuntimeLimits(max_jobs_per_cycle=max_jobs),
    )


def test_fresh_runtime_cycles_complete_zero_package_graph_without_osv_request(
    tmp_path: Path,
) -> None:
    environment = _Environment(tmp_path)
    submissions = _prepare_product_submission(environment)
    attempt_tokens = iter(UUID(f"77777777-7777-4777-8777-{number:012d}") for number in range(1, 10))
    lease_tokens = iter(UUID(f"66666666-6666-4666-8666-{number:012d}") for number in range(1, 10))
    environment.attempts = SourceScannerAttemptService(
        environment.factory,
        environment.store,
        environment.projections,
        token_factory=lambda: next(attempt_tokens),
    )
    dispatcher = _local_accepting_dispatcher(environment)
    try:
        summaries = []
        for cycle_number in range(1, 7):
            worker = SourceOrchestrationWorkerCycle(
                environment.factory,
                SourceMappedJobLeasingService(
                    environment.factory,
                    token_factory=lambda: next(lease_tokens),
                ),
                environment.attempts,
                dispatcher,
                worker_id=f"restart-worker-{cycle_number}",
            )
            summary = _durable_runtime(environment, submissions, worker=worker).run_once()
            summaries.append(summary)
            with environment.factory() as session:
                submission = session.get(SourceScanSubmissionRow, str(_RUN_ID))
                assert submission is not None
                if submission.finalized_at is not None:
                    break

        with environment.factory() as session:
            submission = session.get(SourceScanSubmissionRow, str(_RUN_ID))
            run = session.get(AnalysisRunRow, str(_RUN_ID))
            osv_node = session.scalar(
                select(SourceOrchestrationNodeRow).where(
                    SourceOrchestrationNodeRow.run_id == str(_RUN_ID),
                    SourceOrchestrationNodeRow.authority == SourceAuthority.OSV.value,
                )
            )
            assert submission is not None and submission.finalized_at is not None
            assert run is not None and run.report_json is not None
            assert osv_node is not None
            assert (
                osv_node.terminal_disposition == OrchestrationNodeDisposition.NOT_APPLICABLE.value
            )
            assert session.scalar(select(func.count()).select_from(JobRow)) == 4
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(SourceOrchestrationScannerJobRow)
                    .where(SourceOrchestrationScannerJobRow.authority == SourceAuthority.OSV.value)
                )
                == 0
            )
        assert sum(item.jobs_dispatched_count for item in summaries) == 4
        assert sum(item.assembly_published_count for item in summaries) == 1
        assert sum(item.finalized_count for item in summaries) == 1
    finally:
        environment.close()


def test_repeated_runtime_coordination_creates_only_one_osv_job(tmp_path: Path) -> None:
    environment = _Environment(tmp_path)
    submissions = _prepare_product_submission(environment)
    try:
        syft_node, syft_job, _attempt = environment.start_attempt(SourceAuthority.SYFT)
        _finish_existing_syft(
            environment,
            syft_node,
            syft_job,
            (_observation(syft_job, syft_node, ("requirements.lock",)),),
        )
        idle_worker = _Worker()

        _durable_runtime(environment, submissions, worker=idle_worker).run_once()
        _durable_runtime(environment, submissions, worker=idle_worker).run_once()

        with environment.factory() as session:
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(SourceOrchestrationScannerJobRow)
                    .where(SourceOrchestrationScannerJobRow.authority == SourceAuthority.OSV.value)
                )
                == 1
            )
    finally:
        environment.close()


def test_queued_noop_run_leaves_bounded_coordinator_discovery(tmp_path: Path) -> None:
    environment = _Environment(tmp_path)
    _prepare_product_submission(environment)
    discovery = SourceRuntimeWorkDiscovery(environment.factory)
    coordinator = SourceOrchestrationCoordinatorService(
        environment.factory,
        environment.store,
        frozen_source_v1_authority_roster(),
        environment.projections,
    )
    try:
        assert tuple(item.run_id for item in discovery.orchestration_candidates(limit=1)) == (
            str(_RUN_ID),
        )

        coordinator.advance(run_id=str(_RUN_ID), workspace=environment.workspace)

        assert discovery.orchestration_candidates(limit=1) == ()
    finally:
        environment.close()


def test_expired_parent_creates_no_scanner_job(tmp_path: Path) -> None:
    environment = _Environment(tmp_path)
    submissions = _prepare_product_submission(environment, expired=True)
    try:
        _durable_runtime(environment, submissions, worker=_Worker()).run_once()

        with environment.factory() as session:
            assert session.scalar(select(func.count()).select_from(JobRow)) == 0
            parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
            assert parent is not None and parent.deadline_exceeded_at is not None
    finally:
        environment.close()


def test_deleted_managed_workspace_cannot_create_or_release_work(tmp_path: Path) -> None:
    environment = _Environment(tmp_path)
    submissions = _prepare_product_submission(environment)
    environment.workspace_manager.cleanup_workspace(environment.workspace)
    try:
        worker = _Worker()
        with pytest.raises(SourceRuntimeError, match="Source runtime cycle failed"):
            _durable_runtime(environment, submissions, worker=worker).run_once()

        assert worker.calls == 0
        with environment.factory() as session:
            assert session.scalar(select(func.count()).select_from(JobRow)) == 0
            parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
            assert parent is not None
            assert parent.lifecycle_state == "ACTIVE"
    finally:
        environment.close()


def test_production_factory_constructs_without_scanner_or_network_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'runtime.db'}",
        artifact_root=tmp_path / "artifacts",
        source_projection_root=tmp_path / "projections",
        source_workspace_root=tmp_path / "workspaces",
        source_runtime_receipt_root=tmp_path / "receipts",
    )
    initialize_source_runtime_storage(settings)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("runtime construction attempted process or network execution")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr(
        "securescan.source_runtime.create_default_gitleaks_binding",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        "securescan.source_runtime.create_default_syft_binding",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        "securescan.source_runtime.create_default_checkov_binding",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        "securescan.source_runtime.SourceProductionDispatcherDependencies",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        "securescan.source_runtime.create_source_production_authority_dispatcher",
        lambda _dependencies: SimpleNamespace(dispatch=lambda *_args: None),
    )

    with (
        create_source_runtime(settings) as composition,
        composition.session_factory() as session,
    ):
        assert session.scalar(select(func.count()).select_from(JobRow)) == 0
        assert session.scalar(select(func.count()).select_from(AnalysisRunRow)) == 0

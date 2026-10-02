from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from sqlalchemy import and_, exists, func, or_, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import Settings, get_settings
from securescan.execution.docker_sandbox import DockerSandboxExecutor
from securescan.observability.readiness import _bootstrap_database_schema
from securescan.orchestration.assembly import (
    SourceAssemblyFailureRecord,
    SourceResultAssemblyError,
    SourceResultAssemblyService,
)
from securescan.orchestration.coordinator import SourceOrchestrationCoordinatorService
from securescan.orchestration.dependency_evaluation import (
    SourceDependencyEvaluationService,
)
from securescan.orchestration.execution import (
    SourceScannerAttemptService,
    SourceScannerLeaseReconciliationService,
)
from securescan.orchestration.local_execution import SourceLocalBridgeExecutionService
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    OrchestrationNodeLifecycleState,
    SourceAuthority,
    frozen_source_v1_authority_roster,
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
from securescan.orchestration.sandbox_execution import (
    SourceSandboxReconciliationService,
)
from securescan.orchestration.worker import (
    SourceMappedJobLeasingService,
    SourceOrchestrationWorkerCycle,
    SourceWorkerDisposition,
)
from securescan.persistence.database import (
    JobRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    SourceScanSubmissionRow,
    create_session_factory,
)
from securescan.product_core import (
    ProductFinalizationBatchResult,
    SourceIntakeKind,
    SourceProductFinalizationRunner,
    SourceScanSubmissionService,
)
from securescan.runtime_storage import (
    RuntimeStorageInitializationError,
    initialize_source_runtime_storage,
)
from securescan.scanners.checkov import create_default_checkov_binding
from securescan.scanners.gitleaks import create_default_gitleaks_binding
from securescan.scanners.semgrep import (
    DECLARED_SEMGREP_TOOL_VERSION,
    PRODUCTION_SEMGREP_IMAGE_REFERENCE,
    create_production_semgrep_source_binding,
    create_semgrep_trusted_definition,
    load_source_ruleset,
)
from securescan.scanners.syft import create_default_syft_binding
from securescan.source.projection import SourceProjectionManager
from securescan.workspaces import PreparedRepositoryWorkspace, RepositoryWorkspaceManager

SOURCE_RUNTIME_WORKER_ID = "source-runtime-v1"
SOURCE_RUNTIME_DISCOVERY_LIMIT = 200
_LOGGER = logging.getLogger(__name__)


class SourceRuntimeError(RuntimeError):
    def __init__(
        self,
        code: str = "RUNTIME_UNAVAILABLE",
        message: str = "Source runtime cycle failed",
        *,
        phase: str = "runtime_cycle",
        remediation: str = "Review the worker logs and runtime configuration",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.phase = phase
        self.remediation = remediation


class SourceRuntimeCandidateState(StrEnum):
    ACTIVE = OrchestrationLifecycleState.ACTIVE.value
    CANCELLATION_REQUESTED = OrchestrationLifecycleState.CANCELLATION_REQUESTED.value


@dataclass(frozen=True, slots=True)
class SourceRuntimeLimits:
    max_orchestration_advances_per_cycle: int = 25
    max_jobs_per_cycle: int = 4
    max_reconciliations_per_cycle: int = 25
    max_assemblies_per_cycle: int = 10
    max_finalizations_per_cycle: int = 25

    def __post_init__(self) -> None:
        values = (
            self.max_orchestration_advances_per_cycle,
            self.max_jobs_per_cycle,
            self.max_reconciliations_per_cycle,
            self.max_assemblies_per_cycle,
            self.max_finalizations_per_cycle,
        )
        if any(type(value) is not int or not 1 <= value <= 200 for value in values):
            raise SourceRuntimeError


_DEFAULT_RUNTIME_LIMITS = SourceRuntimeLimits()


@dataclass(frozen=True, slots=True)
class SourceRuntimeCandidate:
    run_id: str = field(repr=False)
    lifecycle_state: SourceRuntimeCandidateState


@dataclass(frozen=True, slots=True)
class SourceRuntimeCycleSummary:
    reconciled_attempt_count: int
    pre_advance_examined_count: int
    pre_advance_attempted_count: int
    pre_advance_changed_count: int
    pre_advance_failed_count: int
    jobs_dispatched_count: int
    post_advance_examined_count: int
    post_advance_attempted_count: int
    post_advance_changed_count: int
    post_advance_failed_count: int
    assembly_examined_count: int
    assembly_published_count: int
    assembly_failed_count: int
    finalization_examined_count: int
    finalized_count: int
    already_finalized_count: int
    finalization_not_ready_count: int
    finalization_failed_count: int

    def canonical_data(self) -> dict[str, int]:
        return {
            "already_finalized_count": self.already_finalized_count,
            "assembly_examined_count": self.assembly_examined_count,
            "assembly_failed_count": self.assembly_failed_count,
            "assembly_published_count": self.assembly_published_count,
            "finalization_examined_count": self.finalization_examined_count,
            "finalization_failed_count": self.finalization_failed_count,
            "finalization_not_ready_count": self.finalization_not_ready_count,
            "finalized_count": self.finalized_count,
            "jobs_dispatched_count": self.jobs_dispatched_count,
            "post_advance_changed_count": self.post_advance_changed_count,
            "post_advance_examined_count": self.post_advance_examined_count,
            "post_advance_attempted_count": self.post_advance_attempted_count,
            "post_advance_failed_count": self.post_advance_failed_count,
            "pre_advance_changed_count": self.pre_advance_changed_count,
            "pre_advance_examined_count": self.pre_advance_examined_count,
            "pre_advance_attempted_count": self.pre_advance_attempted_count,
            "pre_advance_failed_count": self.pre_advance_failed_count,
            "reconciled_attempt_count": self.reconciled_attempt_count,
        }


class _RuntimeDiscovery(Protocol):
    def orchestration_candidates(self, *, limit: int) -> tuple[SourceRuntimeCandidate, ...]: ...

    def assembly_candidates(self, *, limit: int) -> tuple[str, ...]: ...


class _WorkspaceResolver(Protocol):
    def resolve_workspace(self, *, run_id: str) -> PreparedRepositoryWorkspace: ...


class _Coordinator(Protocol):
    def advance(
        self, *, run_id: str, workspace: PreparedRepositoryWorkspace | None = None
    ) -> object: ...


class _Worker(Protocol):
    def run_one(self) -> object: ...


class _Reconciliation(Protocol):
    def quarantine_expired(self, *, limit: int) -> tuple[object, ...]: ...


class _Assembly(Protocol):
    def assemble_and_publish(self, run_id: str) -> object: ...

    def record_failure(
        self, run_id: str, failure: SourceResultAssemblyError
    ) -> SourceAssemblyFailureRecord: ...


class _Finalizer(Protocol):
    def finalize_ready(self, *, limit: int) -> ProductFinalizationBatchResult: ...


class _RuntimeCycle(Protocol):
    def run_once(self) -> SourceRuntimeCycleSummary: ...


class SourceRuntimeLoop:
    """Run bounded Source runtime cycles until graceful shutdown is requested."""

    def __init__(
        self,
        runtime: _RuntimeCycle,
        stop_event: threading.Event,
        *,
        poll_seconds: float,
        on_cycle: Callable[[SourceRuntimeCycleSummary], None],
        waiter: Callable[[float], bool] | None = None,
    ) -> None:
        if not hasattr(runtime, "run_once") or not callable(runtime.run_once):
            raise SourceRuntimeError
        if not isinstance(stop_event, threading.Event):
            raise SourceRuntimeError
        if (
            isinstance(poll_seconds, bool)
            or not isinstance(poll_seconds, (int, float))
            or not 0.1 <= poll_seconds <= 60
            or not callable(on_cycle)
            or (waiter is not None and not callable(waiter))
        ):
            raise SourceRuntimeError
        self._runtime = runtime
        self._stop_event = stop_event
        self._poll_seconds = float(poll_seconds)
        self._on_cycle = on_cycle
        self._waiter = waiter or stop_event.wait

    def run(self) -> int:
        completed_cycles = 0
        while not self._stop_event.is_set():
            summary = self._runtime.run_once()
            if not isinstance(summary, SourceRuntimeCycleSummary):
                raise SourceRuntimeError
            self._on_cycle(summary)
            completed_cycles += 1
            if self._stop_event.is_set() or self._waiter(self._poll_seconds):
                break
        return completed_cycles


class SourceRuntimeWorkDiscovery:
    """Read bounded Product Core work identities from durable database state."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def orchestration_candidates(self, *, limit: int) -> tuple[SourceRuntimeCandidate, ...]:
        self._validate_limit(limit)
        try:
            with self._sessions() as session:
                ready_node = exists().where(
                    SourceOrchestrationNodeRow.run_id == SourceOrchestrationRow.run_id,
                    SourceOrchestrationNodeRow.lifecycle_state
                    == OrchestrationNodeLifecycleState.READY.value,
                )
                due_retry = exists().where(
                    SourceOrchestrationNodeRow.run_id == SourceOrchestrationRow.run_id,
                    SourceOrchestrationNodeRow.lifecycle_state
                    == OrchestrationNodeLifecycleState.RETRY_PENDING.value,
                    SourceOrchestrationScannerJobRow.node_id == SourceOrchestrationNodeRow.node_id,
                    SourceOrchestrationScannerJobRow.run_id == SourceOrchestrationRow.run_id,
                    JobRow.id == SourceOrchestrationScannerJobRow.job_id,
                    JobRow.available_at <= func.now(),
                )
                syft_terminal = exists().where(
                    SourceOrchestrationNodeRow.run_id == SourceOrchestrationRow.run_id,
                    SourceOrchestrationNodeRow.authority == SourceAuthority.SYFT.value,
                    SourceOrchestrationNodeRow.lifecycle_state
                    == OrchestrationNodeLifecycleState.TERMINAL.value,
                    SourceOrchestrationNodeRow.terminal_disposition.is_not(None),
                )
                waiting_osv = exists().where(
                    SourceOrchestrationNodeRow.run_id == SourceOrchestrationRow.run_id,
                    SourceOrchestrationNodeRow.authority == SourceAuthority.OSV.value,
                    SourceOrchestrationNodeRow.lifecycle_state
                    == OrchestrationNodeLifecycleState.WAITING_DEPENDENCY.value,
                )
                all_nodes_terminal = ~exists().where(
                    SourceOrchestrationNodeRow.run_id == SourceOrchestrationRow.run_id,
                    SourceOrchestrationNodeRow.lifecycle_state
                    != OrchestrationNodeLifecycleState.TERMINAL.value,
                )
                rows = session.execute(
                    select(
                        SourceOrchestrationRow.run_id,
                        SourceOrchestrationRow.lifecycle_state,
                    )
                    .join(
                        SourceScanSubmissionRow,
                        SourceScanSubmissionRow.run_id == SourceOrchestrationRow.run_id,
                    )
                    .where(
                        SourceScanSubmissionRow.intake_kind
                        == SourceIntakeKind.MANAGED_WORKSPACE_V1.value,
                        SourceOrchestrationRow.lifecycle_state.in_(
                            (
                                OrchestrationLifecycleState.ACTIVE.value,
                                OrchestrationLifecycleState.CANCELLATION_REQUESTED.value,
                            )
                        ),
                        or_(
                            SourceOrchestrationRow.lifecycle_state
                            == OrchestrationLifecycleState.CANCELLATION_REQUESTED.value,
                            SourceOrchestrationRow.cancel_requested.is_(True),
                            SourceOrchestrationRow.deadline_at <= func.now(),
                            ready_node,
                            due_retry,
                            and_(waiting_osv, syft_terminal),
                            all_nodes_terminal,
                        ),
                    )
                    .order_by(
                        SourceOrchestrationRow.updated_at,
                        SourceOrchestrationRow.created_at,
                        SourceOrchestrationRow.run_id,
                    )
                    .limit(limit)
                )
                return tuple(
                    SourceRuntimeCandidate(
                        run_id=run_id,
                        lifecycle_state=SourceRuntimeCandidateState(lifecycle_state),
                    )
                    for run_id, lifecycle_state in rows
                )
        except (SQLAlchemyError, ValueError):
            raise SourceRuntimeError from None

    def assembly_candidates(self, *, limit: int) -> tuple[str, ...]:
        self._validate_limit(limit)
        try:
            with self._sessions() as session:
                return tuple(
                    session.scalars(
                        select(SourceOrchestrationRow.run_id)
                        .join(
                            SourceScanSubmissionRow,
                            SourceScanSubmissionRow.run_id == SourceOrchestrationRow.run_id,
                        )
                        .where(
                            SourceScanSubmissionRow.intake_kind
                            == SourceIntakeKind.MANAGED_WORKSPACE_V1.value,
                            SourceOrchestrationRow.lifecycle_state.in_(
                                (
                                    OrchestrationLifecycleState.ASSEMBLY_READY.value,
                                    OrchestrationLifecycleState.COMMITTING.value,
                                )
                            ),
                        )
                        .order_by(
                            SourceOrchestrationRow.updated_at,
                            SourceOrchestrationRow.created_at,
                            SourceOrchestrationRow.run_id,
                        )
                        .limit(limit)
                    )
                )
        except SQLAlchemyError:
            raise SourceRuntimeError from None

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if type(limit) is not int or not 1 <= limit <= 200:
            raise SourceRuntimeError


class SourceRuntimeService:
    """Perform one bounded, restartable pass over authoritative durable services."""

    def __init__(
        self,
        *,
        discovery: _RuntimeDiscovery,
        workspace_resolver: _WorkspaceResolver,
        coordinator: _Coordinator,
        worker: _Worker,
        reconciliation: _Reconciliation,
        assembly: _Assembly,
        finalizer: _Finalizer,
        limits: SourceRuntimeLimits = _DEFAULT_RUNTIME_LIMITS,
    ) -> None:
        self._discovery = discovery
        self._workspaces = workspace_resolver
        self._coordinator = coordinator
        self._worker = worker
        self._reconciliation = reconciliation
        self._assembly = assembly
        self._finalizer = finalizer
        if not isinstance(limits, SourceRuntimeLimits):
            raise SourceRuntimeError
        self._limits = limits

    def run_once(self) -> SourceRuntimeCycleSummary:
        try:
            reconciled = self._reconciliation.quarantine_expired(
                limit=self._limits.max_reconciliations_per_cycle
            )
            pre = self._advance_phase(
                max_advances=self._limits.max_orchestration_advances_per_cycle
            )
            dispatched = self._dispatch_jobs()
            post = self._advance_phase(
                max_advances=(self._limits.max_orchestration_advances_per_cycle - pre[1])
            )
            assemblies = self._publish_ready()
            finalization = self._finalizer.finalize_ready(
                limit=self._limits.max_finalizations_per_cycle
            )
        except SourceRuntimeError:
            raise
        except Exception:
            raise SourceRuntimeError from None
        return SourceRuntimeCycleSummary(
            reconciled_attempt_count=len(reconciled),
            pre_advance_examined_count=pre[0],
            pre_advance_attempted_count=pre[1],
            pre_advance_changed_count=pre[2],
            pre_advance_failed_count=pre[3],
            jobs_dispatched_count=dispatched,
            post_advance_examined_count=post[0],
            post_advance_attempted_count=post[1],
            post_advance_changed_count=post[2],
            post_advance_failed_count=post[3],
            assembly_examined_count=assemblies[0],
            assembly_published_count=assemblies[1],
            assembly_failed_count=assemblies[2],
            finalization_examined_count=finalization.examined_count,
            finalized_count=finalization.finalized_count,
            already_finalized_count=finalization.already_finalized_count,
            finalization_not_ready_count=finalization.not_ready_count,
            finalization_failed_count=finalization.failed_count,
        )

    def _advance_phase(self, *, max_advances: int) -> tuple[int, int, int, int]:
        if max_advances == 0:
            return 0, 0, 0, 0
        candidates = self._discovery.orchestration_candidates(limit=SOURCE_RUNTIME_DISCOVERY_LIMIT)
        examined = 0
        attempted = 0
        changed = 0
        for candidate in candidates:
            if attempted >= max_advances:
                break
            examined += 1
            workspace: PreparedRepositoryWorkspace | None = None
            if candidate.lifecycle_state is SourceRuntimeCandidateState.ACTIVE:
                try:
                    workspace = self._workspaces.resolve_workspace(run_id=candidate.run_id)
                except Exception:
                    # Nothing for this active run may advance without re-establishing
                    # its managed-workspace identity through PC3A.
                    raise SourceRuntimeError from None
            attempted += 1
            try:
                result = self._coordinator.advance(run_id=candidate.run_id, workspace=workspace)
            except Exception:
                raise SourceRuntimeError from None
            changed += int(bool(getattr(result, "state_changed", False)))
        return examined, attempted, changed, 0

    def _dispatch_jobs(self) -> int:
        dispatched = 0
        for _ in range(self._limits.max_jobs_per_cycle):
            result = self._worker.run_one()
            disposition = getattr(result, "disposition", None)
            if disposition is SourceWorkerDisposition.IDLE:
                break
            if disposition is not SourceWorkerDisposition.DISPATCHED:
                raise SourceRuntimeError
            dispatched += 1
        return dispatched

    def _publish_ready(self) -> tuple[int, int, int]:
        run_ids = self._discovery.assembly_candidates(limit=self._limits.max_assemblies_per_cycle)
        published = 0
        failed = 0
        for run_id in run_ids:
            try:
                record = self._assembly.assemble_and_publish(run_id)
            except Exception as exc:
                failure = (
                    exc
                    if isinstance(exc, SourceResultAssemblyError)
                    else SourceResultAssemblyError("ASSEMBLY_UNEXPECTED_FAILURE")
                )
                try:
                    resolution = self._assembly.record_failure(run_id, failure)
                except Exception:
                    raise SourceRuntimeError from None
                _LOGGER.error(
                    "Source assembly failed run_id=%s phase=%s exception_class=%s "
                    "reason_code=%s attempt=%d retryable=%s terminalized=%s",
                    run_id,
                    failure.phase,
                    type(exc).__name__,
                    resolution.reason_code,
                    resolution.attempt_count,
                    resolution.retryable,
                    resolution.terminalized,
                )
                failed += 1
                continue
            published += int(bool(getattr(record, "published", False)))
        return len(run_ids), published, failed


@dataclass(frozen=True, slots=True)
class SourceRuntimeComposition:
    runtime: SourceRuntimeService
    session_factory: sessionmaker[Session] = field(repr=False)
    workspace_manager: RepositoryWorkspaceManager = field(repr=False)


@contextmanager
def create_source_runtime(
    settings: Settings | None = None,
    *,
    limits: SourceRuntimeLimits = _DEFAULT_RUNTIME_LIMITS,
) -> Iterator[SourceRuntimeComposition]:
    """Construct the single production Source runtime stack without running work."""

    trusted_settings = get_settings() if settings is None else settings
    if not isinstance(trusted_settings, Settings):
        raise SourceRuntimeError
    engine = None
    phase = "runtime_storage"
    try:
        initialize_source_runtime_storage(
            trusted_settings,
            allow_empty_projection=False,
        )
        phase = "database_connection"
        engine, sessions = create_session_factory(trusted_settings)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        phase = "database_schema"
        _bootstrap_database_schema(
            engine,
            allow_sqlite_schema_bootstrap=trusted_settings.allow_sqlite_schema_bootstrap,
        )
        phase = "runtime_services"
        artifacts = ContentAddressedArtifactStore(trusted_settings.artifact_root)
        workspaces = RepositoryWorkspaceManager(trusted_settings.source_workspace_root)
        projections = SourceProjectionManager(trusted_settings.source_projection_root)
        roster = frozen_source_v1_authority_roster()
        submissions = SourceScanSubmissionService(sessions, artifacts, workspaces)
        coordinator = SourceOrchestrationCoordinatorService(
            sessions, artifacts, roster, projections
        )
        attempts = SourceScannerAttemptService(sessions, artifacts, projections)
        evaluations = SourceDependencyEvaluationService(sessions, artifacts)
        osv_jobs = SourceOsvJobService(sessions, artifacts, evaluations)
        local_bridge = SourceLocalBridgeExecutionService(
            artifacts,
            projections,
            attempts,
            trusted_settings.source_runtime_receipt_root / "local",
        )
        osv_helper = SourceOsvHelperExecutionService(
            sessions,
            osv_jobs,
            attempts,
            SourceOsvAttemptService(sessions, artifacts, osv_jobs),
            SourceOsvRequestPermitService(sessions),
            trusted_settings.source_runtime_receipt_root / "osv",
        )
        phase = "scanner_configuration"
        ruleset = load_source_ruleset()
        definition = create_semgrep_trusted_definition(
            image_reference=PRODUCTION_SEMGREP_IMAGE_REFERENCE,
            tool_version=DECLARED_SEMGREP_TOOL_VERSION,
            docker_executor=DockerSandboxExecutor(),
            workspace_manager=workspaces,
            ruleset=ruleset,
            artifact_store=artifacts,
            source_resolver=lambda _run_id: workspaces.base_directory,
        )
        semgrep_binding = create_production_semgrep_source_binding(
            definition=definition, ruleset=ruleset
        )
        sandbox_reconciliation = SourceSandboxReconciliationService(
            attempt_persistence=attempts,
            binding=semgrep_binding,
            definition=definition,
        )
        dispatcher = create_source_production_authority_dispatcher(
            SourceProductionDispatcherDependencies(
                session_factory=sessions,
                artifact_store=artifacts,
                projection_manager=projections,
                attempt_service=attempts,
                local_bridge=local_bridge,
                osv_helper=osv_helper,
                semgrep_binding=semgrep_binding,
                semgrep_ruleset=ruleset,
                gitleaks_binding=create_default_gitleaks_binding(
                    trusted_settings.source_gitleaks_executable_path
                ),
                syft_binding=create_default_syft_binding(
                    trusted_settings.source_syft_executable_path
                ),
                checkov_binding=create_default_checkov_binding(
                    trusted_settings.source_checkov_executable_path
                ),
                semgrep_workspace_root=trusted_settings.source_workspace_root,
            )
        )
        worker = SourceOrchestrationWorkerCycle(
            sessions,
            SourceMappedJobLeasingService(sessions),
            attempts,
            dispatcher,
            worker_id=SOURCE_RUNTIME_WORKER_ID,
        )
        phase = "runtime_composition"
        runtime = SourceRuntimeService(
            discovery=SourceRuntimeWorkDiscovery(sessions),
            workspace_resolver=submissions,
            coordinator=coordinator,
            worker=worker,
            reconciliation=SourceScannerLeaseReconciliationService(
                sessions,
                local_receipt_root=trusted_settings.source_runtime_receipt_root / "local",
                sandbox_reconcile=sandbox_reconciliation.reconcile,
            ),
            assembly=SourceResultAssemblyService(sessions, artifacts),
            finalizer=SourceProductFinalizationRunner(sessions, submissions),
            limits=limits,
        )
        yield SourceRuntimeComposition(runtime, sessions, workspaces)
    except RuntimeStorageInitializationError as exc:
        phase_codes = {
            "artifact_storage": "ARTIFACT_ROOT_UNAVAILABLE",
            "workspace_storage": "WORKSPACE_ROOT_UNAVAILABLE",
            "runtime_receipt_storage": "RUNTIME_RECEIPT_ROOT_UNAVAILABLE",
        }
        raise SourceRuntimeError(
            phase_codes.get(exc.phase, exc.code),
            str(exc),
            phase=exc.phase,
            remediation="Run 'securescan init' with the worker configuration",
        ) from None
    except SourceRuntimeError:
        raise
    except Exception as exc:
        _LOGGER.error(
            "Source runtime construction failed phase=%s exception_class=%s",
            phase,
            type(exc).__name__,
        )
        phase_codes = {
            "database_connection": "DATABASE_UNAVAILABLE",
            "database_schema": "DATABASE_SCHEMA_UNAVAILABLE",
            "scanner_configuration": "SCANNER_CONFIGURATION_INVALID",
        }
        raise SourceRuntimeError(
            phase_codes.get(phase, "RUNTIME_COMPOSITION_FAILED"),
            "Source runtime could not be constructed",
            phase=phase,
            remediation="Review the safe worker log category and trusted configuration",
        ) from None
    finally:
        if engine is not None:
            engine.dispose()

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic, sleep

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import ExecutionOutcome, JobFailureCategory, JobStatus
from securescan.execution.docker_sandbox import DockerCommandRunner
from securescan.jobs.models import JobRecord
from securescan.persistence.database import (
    JobRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
)
from securescan.scanners.checkov import TrustedCheckovBinding
from securescan.scanners.gitleaks import TrustedGitleaksBinding
from securescan.scanners.semgrep import (
    SourceExecutionEnvelope,
    SourceSemgrepExecutionContextResolver,
    TrustedSemgrepRuleset,
    TrustedSemgrepSourceBinding,
)
from securescan.scanners.semgrep.factory import (
    create_source_aware_semgrep_trusted_definition,
)
from securescan.scanners.syft import TrustedSyftBinding
from securescan.source.projection import SourceProjectionManager
from securescan.worker.models import WorkerFailedExecution, WorkerSuccessfulExecution
from securescan.workspaces.intake import RepositoryWorkspaceManager

from .execution import (
    SourceScannerAttemptRecord,
    SourceScannerAttemptService,
    SourceScannerExecutionConflictError,
)
from .execution_models import SafeSourceNativeResult, SourceScannerFailureCode
from .local_execution import SourceLocalBridgeExecutionService
from .models import (
    OrchestrationLifecycleState,
    SourceAuthority,
    frozen_source_v1_authority_roster,
)
from .osv_runtime import SourceOsvHelperExecutionService
from .sandbox_execution import AttemptBoundDockerExecutor
from .worker import SourceAuthorityDispatcher, SourceAuthorityRunner


def _duration_ms(started: float) -> int:
    return max(0, int((monotonic() - started) * 1000))


class _ProductionRunner:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        attempts: SourceScannerAttemptService,
        authority: SourceAuthority,
    ) -> None:
        self._sessions = session_factory
        self._attempts = attempts
        self._authority = authority

    def _guard(self, job: JobRecord, attempt: SourceScannerAttemptRecord) -> None:
        try:
            with self._sessions() as session:
                durable_job = session.get(JobRow, job.id)
                mapping = session.get(SourceOrchestrationScannerJobRow, job.id)
                parent = session.get(SourceOrchestrationRow, job.run_id)
                database_now = session.scalar(select(func.now()))
                if (
                    durable_job is None
                    or mapping is None
                    or parent is None
                    or not isinstance(database_now, datetime)
                    or durable_job.status != JobStatus.RUNNING.value
                    or durable_job.cancel_requested
                    or mapping.run_id != job.run_id
                    or mapping.node_id != attempt.node_id
                    or mapping.authority != self._authority.value
                    or attempt.job_id != job.id
                    or attempt.run_id != job.run_id
                    or attempt.attempt_number != job.attempt_count
                    or parent.lifecycle_state
                    != OrchestrationLifecycleState.ACTIVE.value
                    or parent.cancel_requested
                    or _utc(database_now) >= _utc(parent.deadline_at)
                ):
                    raise SourceScannerExecutionConflictError
        except SourceScannerExecutionConflictError:
            raise
        except Exception:
            raise SourceScannerExecutionConflictError from None


class _LocalBridgeRunner(_ProductionRunner):
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        attempts: SourceScannerAttemptService,
        authority: SourceAuthority,
        bridge: SourceLocalBridgeExecutionService,
        binding: TrustedGitleaksBinding | TrustedSyftBinding | TrustedCheckovBinding,
    ) -> None:
        super().__init__(session_factory, attempts, authority)
        self._bridge = bridge
        self._binding = binding

    def __call__(self, job: JobRecord, attempt: SourceScannerAttemptRecord) -> None:
        self._guard(job, attempt)
        started = monotonic()
        starter = {
            SourceAuthority.GITLEAKS: self._bridge.start_gitleaks,
            SourceAuthority.SYFT: self._bridge.start_syft,
            SourceAuthority.CHECKOV: self._bridge.start_checkov,
        }.get(self._authority)
        if starter is None:
            raise SourceScannerExecutionConflictError
        handle = starter(job=job, attempt=attempt, binding=self._binding)
        failed = False
        try:
            try:
                native = handle.poll()
                while native is None:
                    try:
                        self._guard(job, attempt)
                    except SourceScannerExecutionConflictError:
                        handle.terminate()
                        raise
                    sleep(0.02)
                    native = handle.poll()
            except SourceScannerExecutionConflictError:
                raise
            except Exception:
                native = None
                failed = True
        finally:
            handle.close()
        if failed:
            self._attempts.record_failure(
                job_id=job.id,
                attempt_number=attempt.attempt_number,
                attempt_token=attempt.attempt_token,
                lease_token=_lease_token(job),
                failure_code=SourceScannerFailureCode.EXECUTION_FAILURE,
                failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
                execution_outcome=ExecutionOutcome.INTERNAL_ERROR,
                return_code=None,
                duration_ms=_duration_ms(started),
                retryable=True,
            )
            return
        if native is None or native.authority != self._authority.value:
            raise SourceScannerExecutionConflictError
        outcome, return_code = _local_success_metadata(native)
        self._attempts.accept_result(
            native,
            lease_token=_lease_token(job),
            execution_outcome=outcome,
            return_code=return_code,
            duration_ms=_duration_ms(started),
        )


class _SemgrepRunner(_ProductionRunner):
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        attempts: SourceScannerAttemptService,
        artifacts: ContentAddressedArtifactStore,
        projections: SourceProjectionManager,
        binding: TrustedSemgrepSourceBinding,
        ruleset: TrustedSemgrepRuleset,
        workspace_root: Path,
        docker_runner: DockerCommandRunner | None,
    ) -> None:
        super().__init__(session_factory, attempts, SourceAuthority.SEMGREP)
        self._artifacts = artifacts
        self._projections = projections
        self._binding = binding
        self._ruleset = ruleset
        self._workspace_root = workspace_root
        self._docker_runner = docker_runner

    def __call__(self, job: JobRecord, attempt: SourceScannerAttemptRecord) -> None:
        self._guard(job, attempt)
        docker = AttemptBoundDockerExecutor(
            attempt=attempt,
            attempt_persistence=self._attempts,
            binding=self._binding,
            runner=self._docker_runner,
        )
        definition = create_source_aware_semgrep_trusted_definition(
            image_reference=self._binding.image_reference,
            tool_version=self._binding.declared_tool_version,
            docker_executor=docker,
            workspace_manager=RepositoryWorkspaceManager(self._workspace_root),
            ruleset=self._ruleset,
            artifact_store=self._artifacts,
            source_resolver=lambda _run_id: self._workspace_root,
            projection_manager=self._projections,
            binding=self._binding,
        )
        handle = definition.factory().start(job)
        try:
            outcome = handle.poll()
            while outcome is None:
                try:
                    self._guard(job, attempt)
                except SourceScannerExecutionConflictError:
                    handle.terminate()
                    raise
                sleep(0.02)
                outcome = handle.poll()
        finally:
            handle.close()
        if isinstance(outcome, WorkerFailedExecution):
            failure = outcome.tool_execution
            self._attempts.record_failure(
                job_id=job.id,
                attempt_number=attempt.attempt_number,
                attempt_token=attempt.attempt_token,
                lease_token=_lease_token(job),
                failure_code=SourceScannerFailureCode.EXECUTION_FAILURE,
                failure_category=failure.failure_category,
                execution_outcome=ExecutionOutcome(failure.outcome),
                return_code=failure.exit_code,
                duration_ms=failure.duration_ms,
                retryable=failure.retryable,
            )
            return
        if not isinstance(outcome, WorkerSuccessfulExecution):
            raise SourceScannerExecutionConflictError
        execution = _single_semgrep_execution(outcome)
        artifact = execution["artifacts"][0]
        payload = self._artifacts.read_by_sha256(
            artifact["sha256"], expected_size_bytes=artifact["size_bytes"]
        )
        context = SourceSemgrepExecutionContextResolver(
            self._artifacts, self._binding
        ).resolve(job)
        envelope = SourceExecutionEnvelope.from_payload_json(job.payload_json)
        native = SafeSourceNativeResult.from_semgrep_sanitized(
            payload=payload,
            node_id=attempt.node_id,
            job_id=job.id,
            attempt_number=attempt.attempt_number,
            scanner_version=self._binding.declared_tool_version,
            analyzer_id=self._binding.source_analyzer_id,
            context=context,
            projection_id=envelope.projection_reference.projection_id,
            projection_digest=envelope.projection_reference.projection_digest,
        )
        self._attempts.accept_result(
            native,
            lease_token=_lease_token(job),
            execution_outcome=ExecutionOutcome(execution["outcome"]),
            return_code=execution["exit_code"],
            duration_ms=execution["duration_ms"],
        )


class _OsvRunner(_ProductionRunner):
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        attempts: SourceScannerAttemptService,
        service: SourceOsvHelperExecutionService,
    ) -> None:
        super().__init__(session_factory, attempts, SourceAuthority.OSV)
        self._service = service

    def __call__(self, job: JobRecord, attempt: SourceScannerAttemptRecord) -> None:
        self._guard(job, attempt)
        self._service.execute(
            job=job, attempt=attempt, lease_token=_lease_token(job)
        )


@dataclass(frozen=True, slots=True)
class SourceProductionDispatcherDependencies:
    session_factory: sessionmaker[Session]
    artifact_store: ContentAddressedArtifactStore
    projection_manager: SourceProjectionManager
    attempt_service: SourceScannerAttemptService
    local_bridge: SourceLocalBridgeExecutionService
    osv_helper: SourceOsvHelperExecutionService
    semgrep_binding: TrustedSemgrepSourceBinding
    semgrep_ruleset: TrustedSemgrepRuleset
    gitleaks_binding: TrustedGitleaksBinding
    syft_binding: TrustedSyftBinding
    checkov_binding: TrustedCheckovBinding
    semgrep_workspace_root: Path
    semgrep_docker_runner: DockerCommandRunner | None = None

    def __post_init__(self) -> None:
        try:
            valid_types = (
                isinstance(self.artifact_store, ContentAddressedArtifactStore)
                and isinstance(self.projection_manager, SourceProjectionManager)
                and isinstance(self.attempt_service, SourceScannerAttemptService)
                and isinstance(self.local_bridge, SourceLocalBridgeExecutionService)
                and isinstance(self.osv_helper, SourceOsvHelperExecutionService)
                and isinstance(self.semgrep_binding, TrustedSemgrepSourceBinding)
                and isinstance(self.semgrep_ruleset, TrustedSemgrepRuleset)
                and isinstance(self.gitleaks_binding, TrustedGitleaksBinding)
                and isinstance(self.syft_binding, TrustedSyftBinding)
                and isinstance(self.checkov_binding, TrustedCheckovBinding)
                and isinstance(self.semgrep_workspace_root, Path)
                and self.semgrep_workspace_root.is_absolute()
            )
            self.semgrep_binding._validate_state()
            identities = {
                SourceAuthority.SEMGREP: self.semgrep_binding.binding_digest(),
                SourceAuthority.GITLEAKS: self.gitleaks_binding.binding_digest(),
                SourceAuthority.SYFT: self.syft_binding.binding_digest(),
                SourceAuthority.CHECKOV: self.checkov_binding.binding_digest(),
            }
            expected = {
                item.authority: item.contract_digest
                for item in frozen_source_v1_authority_roster().authorities
            }
        except Exception:
            raise SourceScannerExecutionConflictError from None
        if (
            not valid_types
            or self.semgrep_ruleset.ruleset_id != self.semgrep_binding.ruleset_id
            or self.semgrep_ruleset.version != self.semgrep_binding.ruleset_version
            or self.semgrep_ruleset.sha256 != self.semgrep_binding.ruleset_sha256
            or any(expected[authority] != digest for authority, digest in identities.items())
        ):
            raise SourceScannerExecutionConflictError


def create_source_production_authority_dispatcher(
    dependencies: SourceProductionDispatcherDependencies,
) -> SourceAuthorityDispatcher:
    """Compose the five frozen execution paths behind the Source worker."""
    if not isinstance(dependencies, SourceProductionDispatcherDependencies):
        raise SourceScannerExecutionConflictError
    common = (dependencies.session_factory, dependencies.attempt_service)
    runners: dict[SourceAuthority, SourceAuthorityRunner] = {
        SourceAuthority.SEMGREP: _SemgrepRunner(
            *common,
            dependencies.artifact_store,
            dependencies.projection_manager,
            dependencies.semgrep_binding,
            dependencies.semgrep_ruleset,
            dependencies.semgrep_workspace_root,
            dependencies.semgrep_docker_runner,
        ),
        SourceAuthority.GITLEAKS: _LocalBridgeRunner(
            *common,
            SourceAuthority.GITLEAKS,
            dependencies.local_bridge,
            dependencies.gitleaks_binding,
        ),
        SourceAuthority.SYFT: _LocalBridgeRunner(
            *common,
            SourceAuthority.SYFT,
            dependencies.local_bridge,
            dependencies.syft_binding,
        ),
        SourceAuthority.CHECKOV: _LocalBridgeRunner(
            *common,
            SourceAuthority.CHECKOV,
            dependencies.local_bridge,
            dependencies.checkov_binding,
        ),
        SourceAuthority.OSV: _OsvRunner(
            *common, dependencies.osv_helper
        ),
    }
    return SourceAuthorityDispatcher(runners)


def _lease_token(job: JobRecord) -> str:
    if not isinstance(job.lease_token, str):
        raise SourceScannerExecutionConflictError
    return job.lease_token


def _local_success_metadata(
    result: SafeSourceNativeResult,
) -> tuple[ExecutionOutcome, int]:
    data = result.native_data
    if result.authority == SourceAuthority.GITLEAKS.value:
        count = data.get("finding_count")
        if type(count) is not int:
            raise SourceScannerExecutionConflictError
        return (
            ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
            if count
            else ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            1 if count else 0,
        )
    if result.authority == SourceAuthority.SYFT.value:
        count = data.get("package_count")
        if type(count) is not int:
            raise SourceScannerExecutionConflictError
        return (
            ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
            if count
            else ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            0,
        )
    if result.authority == SourceAuthority.CHECKOV.value:
        count = data.get("observation_count")
        gaps = data.get("gaps")
        if type(count) is not int or not isinstance(gaps, tuple):
            raise SourceScannerExecutionConflictError
        if gaps:
            return ExecutionOutcome.PARTIAL_ANALYSIS, 0
        return (
            ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
            if count
            else ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            0,
        )
    raise SourceScannerExecutionConflictError


def _single_semgrep_execution(outcome: WorkerSuccessfulExecution) -> dict[str, object]:
    executions = outcome.report_json.get("executions")
    if (
        not isinstance(executions, list)
        or len(executions) != 1
        or not isinstance(executions[0], dict)
        or executions[0].get("adapter_id") != SourceAuthority.SEMGREP.value
    ):
        raise SourceScannerExecutionConflictError
    execution = executions[0]
    artifacts = execution.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise SourceScannerExecutionConflictError
    return execution


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

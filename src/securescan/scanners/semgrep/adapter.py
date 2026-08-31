from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from uuid import UUID

from securescan.adapters.trusted_registry import TrustedAdapterDefinition
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import (
    ArtifactKind,
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    RunStatus,
    TargetType,
)
from securescan.domain.models import ScanReport, TargetProfile, ToolExecutionRecord
from securescan.execution.cancellable_process import CancellableProcessResult
from securescan.execution.docker_sandbox import (
    DockerSandboxExecutionRequest,
    DockerSandboxTimeoutError,
)
from securescan.jobs.failure_commit import FailedToolExecutionCommit
from securescan.jobs.models import RESERVED_INTERNAL_JOB_PAYLOAD_PREFIX, JobRecord
from securescan.jobs.result_commit import ToolExecutionCommit
from securescan.scanners.semgrep.models import (
    SemgrepAdapterError,
    SemgrepExecutionAuthorizationError,
    SemgrepExecutionError,
    SemgrepExecutionInfrastructureError,
    SemgrepOutputMalformedError,
    SemgrepOutputMissingError,
    SemgrepOutputTooLargeError,
    SemgrepScanPlan,
    SemgrepWorkspaceCleanupError,
)
from securescan.scanners.semgrep.parser import (
    parse_semgrep_output,
    read_semgrep_result,
)
from securescan.scanners.semgrep.ruleset import (
    SEMGREP_RULES_FILENAME,
    TrustedSemgrepRuleset,
)
from securescan.scanners.semgrep.sanitizer import build_sanitized_semgrep_evidence
from securescan.worker.models import (
    WorkerExecutionOutcome,
    WorkerFailedExecution,
    WorkerSuccessfulExecution,
)
from securescan.workspaces.intake import (
    RepositoryWorkspaceError,
    RepositoryWorkspaceManager,
)
from securescan.workspaces.models import PreparedRepositoryWorkspace, RepositoryManifest

_SEMGREP_ARGUMENTS = (
    "scan",
    "--json",
    "--metrics=off",
    "--disable-version-check",
    "--quiet",
    "--no-git-ignore",
    "--jobs=1",
    "--no-rewrite-rule-ids",
    f"--config=/workspace/output/{SEMGREP_RULES_FILENAME}",
    "--output=/workspace/output/semgrep-results.json",
    "/workspace/source",
)
_SOURCE_EXECUTION_PAYLOAD_KEY = (
    f"{RESERVED_INTERNAL_JOB_PAYLOAD_PREFIX}source_execution__"
)
_SEMGREP_ENVIRONMENT = (("HOME", "/tmp"),)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class SemgrepSourceResolver(Protocol):
    def __call__(self, run_id: str) -> Path: ...


@dataclass(frozen=True, slots=True)
class SemgrepExecutionInput:
    source_directory: Path
    authorized_manifest: RepositoryManifest | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source_directory, Path) or (
            self.authorized_manifest is not None
            and not isinstance(self.authorized_manifest, RepositoryManifest)
        ):
            raise SemgrepExecutionAuthorizationError


class SemgrepJobInputResolver(Protocol):
    def __call__(
        self,
        job: JobRecord,
        definition: TrustedAdapterDefinition,
    ) -> SemgrepExecutionInput: ...


class SemgrepDockerExecutionHandle(Protocol):
    def poll(self) -> CancellableProcessResult | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def close(self) -> None: ...


class SemgrepDockerExecutor(Protocol):
    def start(
        self,
        request: DockerSandboxExecutionRequest,
    ) -> SemgrepDockerExecutionHandle: ...

    def execute(
        self,
        request: DockerSandboxExecutionRequest,
    ) -> CancellableProcessResult: ...


@dataclass(frozen=True, slots=True)
class _PreparedSemgrepExecution:
    job: JobRecord
    workspace: PreparedRepositoryWorkspace
    request: DockerSandboxExecutionRequest
    started_at: datetime
    authorized_manifest: RepositoryManifest | None = None


class _CompletedSemgrepFailureHandle:
    def __init__(self, outcome: WorkerFailedExecution) -> None:
        self._outcome = outcome

    def poll(self) -> WorkerFailedExecution:
        return self._outcome

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass

    def close(self) -> None:
        pass


class _SemgrepWorkerExecutionHandle:
    def __init__(
        self,
        adapter: SemgrepScannerAdapter,
        prepared: _PreparedSemgrepExecution,
        docker_handle: SemgrepDockerExecutionHandle,
    ) -> None:
        self._adapter = adapter
        self._prepared = prepared
        self._docker_handle = docker_handle
        self._outcome: WorkerExecutionOutcome | None = None
        self._closed = False
        self._workspace_cleaned = False

    def _cleanup_workspace(self, *, suppress_error: bool) -> None:
        if self._workspace_cleaned:
            return
        try:
            self._adapter._workspace_manager.cleanup_workspace(self._prepared.workspace)
            self._workspace_cleaned = True
        except RepositoryWorkspaceError as exc:
            if not suppress_error:
                raise SemgrepWorkspaceCleanupError from exc

    def poll(self) -> WorkerExecutionOutcome | None:
        if self._outcome is not None:
            return self._outcome
        try:
            process_result = self._docker_handle.poll()
        except DockerSandboxTimeoutError:
            self._cleanup_workspace(suppress_error=True)
            self._outcome = self._adapter._failed_outcome(
                ExecutionOutcome.TIMEOUT,
                JobFailureCategory.TIMEOUT,
                "Semgrep sandbox execution timed out",
                retryable=True,
            )
            return self._outcome
        except Exception:
            self._cleanup_workspace(suppress_error=True)
            self._outcome = self._adapter._failed_from_exception(
                SemgrepExecutionError(),
            )
            return self._outcome
        if process_result is None:
            return None
        try:
            self._outcome = self._adapter._finish(self._prepared, process_result)
        except Exception as exc:
            self._cleanup_workspace(suppress_error=True)
            self._outcome = self._adapter._failed_from_exception(
                exc,
                process_result=process_result,
            )
            return self._outcome
        try:
            self._cleanup_workspace(suppress_error=False)
        except SemgrepWorkspaceCleanupError as exc:
            self._outcome = self._adapter._failed_from_exception(exc)
        return self._outcome

    def terminate(self) -> None:
        self._docker_handle.terminate()

    def kill(self) -> None:
        self._docker_handle.kill()

    def close(self) -> None:
        if self._closed:
            return
        primary_error: Exception | None = None
        try:
            self._docker_handle.close()
        except Exception as exc:
            primary_error = exc
        try:
            self._cleanup_workspace(suppress_error=primary_error is not None)
        except Exception as exc:
            primary_error = exc
        self._closed = True
        if primary_error is not None:
            if isinstance(primary_error, SemgrepAdapterError):
                raise primary_error
            raise SemgrepExecutionError from primary_error


class SemgrepScannerAdapter:
    adapter_id = "semgrep-ce"
    adapter_version = "1.0.0"

    def __init__(
        self,
        *,
        definition: TrustedAdapterDefinition,
        docker_executor: SemgrepDockerExecutor,
        workspace_manager: RepositoryWorkspaceManager,
        ruleset: TrustedSemgrepRuleset,
        artifact_store: ContentAddressedArtifactStore,
        source_resolver: SemgrepSourceResolver,
        job_input_resolver: SemgrepJobInputResolver | None = None,
        plan: SemgrepScanPlan | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        trusted_plan = plan or SemgrepScanPlan(ruleset=ruleset)
        if (
            not isinstance(definition, TrustedAdapterDefinition)
            or definition.adapter_id != self.adapter_id
            or definition.command_prefix != ("semgrep",)
            or not isinstance(workspace_manager, RepositoryWorkspaceManager)
            or not isinstance(ruleset, TrustedSemgrepRuleset)
            or not isinstance(artifact_store, ContentAddressedArtifactStore)
            or not callable(source_resolver)
            or (
                job_input_resolver is not None
                and not callable(job_input_resolver)
            )
            or not isinstance(trusted_plan, SemgrepScanPlan)
            or trusted_plan.ruleset != ruleset
            or not callable(clock)
        ):
            raise SemgrepExecutionError
        self.tool_version = definition.tool_version
        self._definition = definition
        self._docker_executor = docker_executor
        self._workspace_manager = workspace_manager
        self._ruleset = ruleset
        self._artifact_store = artifact_store
        self._source_resolver = source_resolver
        self._job_input_resolver = job_input_resolver
        self._plan = trusted_plan
        self._clock = clock

    @property
    def trusted_definition(self) -> TrustedAdapterDefinition:
        return self._definition

    @property
    def scan_plan(self) -> SemgrepScanPlan:
        return self._plan

    def _prepare(self, job: JobRecord) -> _PreparedSemgrepExecution:
        if not isinstance(job, JobRecord):
            raise SemgrepExecutionError
        is_source_execution = (
            isinstance(job.payload_json, dict)
            and _SOURCE_EXECUTION_PAYLOAD_KEY in job.payload_json
        )
        if job.adapter_id != self.adapter_id:
            if is_source_execution:
                raise SemgrepExecutionAuthorizationError
            raise SemgrepExecutionError
        if is_source_execution and self._job_input_resolver is None:
            raise SemgrepExecutionAuthorizationError
        try:
            if self._job_input_resolver is None:
                source_directory = self._source_resolver(job.run_id)
                if not isinstance(source_directory, Path):
                    raise TypeError
                execution_input = SemgrepExecutionInput(
                    source_directory=source_directory,
                )
            else:
                execution_input = self._job_input_resolver(job, self._definition)
            if not isinstance(execution_input, SemgrepExecutionInput):
                raise TypeError
        except Exception as exc:
            if isinstance(
                exc,
                (
                    SemgrepExecutionAuthorizationError,
                    SemgrepExecutionInfrastructureError,
                ),
            ):
                raise
            raise SemgrepExecutionError from exc

        workspace: PreparedRepositoryWorkspace | None = None
        try:
            workspace = self._workspace_manager.prepare_repository(
                execution_input.source_directory
            )
            authorized_manifest = execution_input.authorized_manifest
            if authorized_manifest is not None:
                authorized_manifest = replace(
                    authorized_manifest,
                    entries=tuple(
                        replace(entry) for entry in authorized_manifest.entries
                    ),
                )
                if workspace.manifest != authorized_manifest:
                    raise SemgrepExecutionAuthorizationError
            self._ruleset.materialize(workspace.output_directory)
            request = DockerSandboxExecutionRequest(
                definition=self._definition,
                source_directory=workspace.source_directory,
                output_directory=workspace.output_directory,
                arguments=_SEMGREP_ARGUMENTS,
                environment=_SEMGREP_ENVIRONMENT,
                execution_id=job.id,
            )
            return _PreparedSemgrepExecution(
                job=job,
                workspace=workspace,
                request=request,
                started_at=self._clock(),
                authorized_manifest=authorized_manifest,
            )
        except Exception as exc:
            if workspace is not None:
                with suppress(RepositoryWorkspaceError):
                    self._workspace_manager.cleanup_workspace(workspace)
            if isinstance(exc, SemgrepAdapterError):
                raise
            raise SemgrepExecutionError from exc

    def start(
        self,
        job: JobRecord,
    ) -> _SemgrepWorkerExecutionHandle | _CompletedSemgrepFailureHandle:
        try:
            prepared = self._prepare(job)
        except Exception as exc:
            return _CompletedSemgrepFailureHandle(self._failed_from_exception(exc))
        try:
            docker_handle = self._docker_executor.start(prepared.request)
        except Exception as exc:
            with suppress(RepositoryWorkspaceError):
                self._workspace_manager.cleanup_workspace(prepared.workspace)
            return _CompletedSemgrepFailureHandle(self._failed_from_exception(exc))
        return _SemgrepWorkerExecutionHandle(self, prepared, docker_handle)

    def execute(self, job: JobRecord) -> WorkerExecutionOutcome:
        prepared = self._prepare(job)
        primary_error: Exception | None = None
        try:
            try:
                result = self._docker_executor.execute(prepared.request)
            except Exception as exc:
                raise SemgrepExecutionError from exc
            return self._finish(prepared, result)
        except Exception as exc:
            primary_error = exc
            raise
        finally:
            try:
                self._workspace_manager.cleanup_workspace(prepared.workspace)
            except RepositoryWorkspaceError as exc:
                if primary_error is None:
                    raise SemgrepWorkspaceCleanupError from exc

    def _finish(
        self,
        prepared: _PreparedSemgrepExecution,
        process_result: CancellableProcessResult,
    ) -> WorkerSuccessfulExecution:
        if (
            not isinstance(process_result, CancellableProcessResult)
            or process_result.return_code != 0
            or process_result.timed_out
            or process_result.output_limit_exceeded
            or process_result.termination_requested
        ):
            raise SemgrepExecutionError
        raw_json = read_semgrep_result(prepared.workspace.output_directory, self._plan)
        parsed = parse_semgrep_output(
            raw_json,
            prepared.workspace.manifest,
            scanner_id=self.adapter_id,
            scanner_version=self.tool_version,
            maximum_findings=self._plan.maximum_findings,
        )
        if prepared.authorized_manifest is not None:
            authorized_paths = {
                entry.relative_path
                for entry in prepared.authorized_manifest.entries
            }
            if (
                prepared.workspace.manifest != prepared.authorized_manifest
                or any(finding.path not in authorized_paths for finding in parsed.findings)
            ):
                raise SemgrepExecutionAuthorizationError
        sanitized_evidence = build_sanitized_semgrep_evidence(
            parsed,
            scanner_id=self.adapter_id,
            ruleset=self._ruleset,
        )
        artifact = self._artifact_store.put(
            sanitized_evidence,
            kind=ArtifactKind.SANITIZED_NATIVE_REPORT,
            media_type="application/json",
            sanitized=True,
        )
        finished_at = self._clock()
        has_gaps = bool(parsed.analysis_gaps)
        if has_gaps:
            execution_outcome = ExecutionOutcome.PARTIAL_ANALYSIS
        elif parsed.findings:
            execution_outcome = ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
        else:
            execution_outcome = ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS
        run_id = UUID(prepared.job.run_id)
        target = TargetProfile(
            target_type=TargetType.SOURCE_REPOSITORY,
            path=Path("."),
            content_digest=prepared.workspace.manifest.content_digest,
            metadata={
                "file_count": prepared.workspace.manifest.file_count,
                "ruleset_id": self._ruleset.ruleset_id,
                "ruleset_version": self._ruleset.version,
            },
        )
        execution = ToolExecutionRecord(
            run_id=run_id,
            adapter_id=self.adapter_id,
            tool_version=self.tool_version,
            adapter_version=self.adapter_version,
            status=RunStatus.PARTIAL if has_gaps else RunStatus.COMPLETED,
            outcome=execution_outcome,
            exit_code=process_result.return_code,
            started_at=prepared.started_at,
            finished_at=finished_at,
            duration_ms=process_result.duration_ms,
            warnings=[gap.message for gap in parsed.analysis_gaps],
            artifacts=[artifact],
            observations=list(parsed.findings),
        )
        report = ScanReport(
            run_id=run_id,
            target=target,
            status=RunStatus.PARTIAL if has_gaps else RunStatus.COMPLETED,
            executions=[execution],
            observations=list(parsed.findings),
            analysis_gaps=list(parsed.analysis_gaps),
            generated_at=finished_at,
        )
        return WorkerSuccessfulExecution(
            final_status=JobStatus.PARTIAL if has_gaps else JobStatus.SUCCEEDED,
            report_json=report.model_dump(mode="json"),
            tool_execution=ToolExecutionCommit(
                tool_version=self.tool_version,
                adapter_version=self.adapter_version,
                outcome=execution_outcome.value,
                exit_code=process_result.return_code,
                duration_ms=process_result.duration_ms,
                warning_json=[
                    gap.model_dump(mode="json") for gap in parsed.analysis_gaps
                ],
            ),
        )

    def _failed_outcome(
        self,
        outcome: ExecutionOutcome,
        category: JobFailureCategory,
        error: str,
        *,
        retryable: bool,
        exit_code: int | None = None,
        duration_ms: int = 0,
    ) -> WorkerFailedExecution:
        return WorkerFailedExecution(
            tool_execution=FailedToolExecutionCommit(
                tool_version=self.tool_version,
                adapter_version=self.adapter_version,
                outcome=outcome.value,
                exit_code=exit_code,
                duration_ms=duration_ms,
                warning_json=[],
                error=error,
                failure_category=category,
                retryable=retryable,
            )
        )

    def _failed_from_exception(
        self,
        error: Exception,
        *,
        process_result: CancellableProcessResult | None = None,
    ) -> WorkerFailedExecution:
        exit_code = process_result.return_code if process_result is not None else None
        duration_ms = process_result.duration_ms if process_result is not None else 0
        if process_result is not None and process_result.timed_out:
            return self._failed_outcome(
                ExecutionOutcome.TIMEOUT,
                JobFailureCategory.TIMEOUT,
                "Semgrep sandbox execution timed out",
                retryable=True,
                exit_code=exit_code,
                duration_ms=duration_ms,
            )
        if process_result is not None and process_result.output_limit_exceeded:
            return self._failed_outcome(
                ExecutionOutcome.OUTPUT_LIMIT_EXCEEDED,
                JobFailureCategory.OUTPUT_LIMIT,
                "Semgrep sandbox output exceeded its size limit",
                retryable=False,
                exit_code=exit_code,
                duration_ms=duration_ms,
            )
        if process_result is not None and process_result.termination_requested:
            return self._failed_outcome(
                ExecutionOutcome.CANCELLED,
                JobFailureCategory.CANCELLED,
                "Semgrep sandbox execution was cancelled",
                retryable=False,
                exit_code=exit_code,
                duration_ms=duration_ms,
            )
        if isinstance(error, SemgrepOutputTooLargeError):
            return self._failed_outcome(
                ExecutionOutcome.OUTPUT_LIMIT_EXCEEDED,
                JobFailureCategory.OUTPUT_LIMIT,
                "Semgrep result output exceeded its size limit",
                retryable=False,
                exit_code=exit_code,
                duration_ms=duration_ms,
            )
        if isinstance(error, SemgrepOutputMalformedError):
            return self._failed_outcome(
                ExecutionOutcome.INVALID_OUTPUT,
                JobFailureCategory.NON_RETRYABLE_PARSER,
                "Semgrep result output is malformed",
                retryable=False,
                exit_code=exit_code,
                duration_ms=duration_ms,
            )
        if isinstance(error, SemgrepOutputMissingError):
            return self._failed_outcome(
                ExecutionOutcome.INVALID_OUTPUT,
                JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
                "Semgrep result output is missing",
                retryable=True,
                exit_code=exit_code,
                duration_ms=duration_ms,
            )
        if isinstance(error, SemgrepExecutionAuthorizationError):
            return self._failed_outcome(
                ExecutionOutcome.INTERNAL_ERROR,
                JobFailureCategory.NON_RETRYABLE_POLICY,
                "Source Semgrep execution authorization failed",
                retryable=False,
                exit_code=exit_code,
                duration_ms=duration_ms,
            )
        if isinstance(error, SemgrepExecutionInfrastructureError):
            return self._failed_outcome(
                ExecutionOutcome.INTERNAL_ERROR,
                JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
                "Source Semgrep execution input is unavailable",
                retryable=True,
                exit_code=exit_code,
                duration_ms=duration_ms,
            )
        return self._failed_outcome(
            ExecutionOutcome.INTERNAL_ERROR,
            JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
            "Semgrep sandbox execution failed",
            retryable=True,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )


SEMGREP_ARGUMENTS = _SEMGREP_ARGUMENTS

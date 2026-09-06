from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Protocol, runtime_checkable

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import JobStatus
from securescan.execution import (
    CancellableProcessExecutor,
    CancellableProcessHandle,
    CancellableProcessResult,
)
from securescan.jobs.models import JobRecord
from securescan.scanners.checkov.binding import (
    CHECKOV_SCANNER_ID,
    CHECKOV_SOURCE_ANALYZER_ID,
    CHECKOV_VERSION,
    CheckovConfigurationIntegrityError,
    CheckovExecutableIntegrityError,
    CheckovToolchainIntegrityError,
    CheckovVersionVerificationError,
    InvalidCheckovExecutionRequestError,
    TrustedCheckovBinding,
)
from securescan.scanners.semgrep.source_execution import (
    SourceExecutionEnvelope,
    SourceSemgrepExecutionContextError,
    SourceSemgrepExecutionContextIntegrityResolver,
)
from securescan.source.enums import AnalysisCapability
from securescan.source.execution_context import SourceExecutionContext, SourceExecutionSelectedFile
from securescan.source.models import RepositoryProfile
from securescan.source.planning import SourceAnalysisPlan, SourceAnalysisPlanEntry, SourcePlanAction
from securescan.source.projection import (
    PreparedSourceProjection,
    SourceProjectionError,
    SourceProjectionManager,
)
from securescan.workspaces.models import RepositoryManifest, repository_content_digest

_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PROJECTION_ID = re.compile(r"securescan-source-projection-[0-9a-f]{16,48}\Z", re.ASCII)
_STDOUT_LIMIT_BYTES = 64 * 1024 * 1024
_STDERR_LIMIT_BYTES = 64 * 1024
_COMBINED_LIMIT_BYTES = _STDOUT_LIMIT_BYTES + _STDERR_LIMIT_BYTES


class CheckovExecutionStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"


class CheckovFailureCode(StrEnum):
    NOT_APPLICABLE = "CHECKOV_NOT_APPLICABLE"
    UNSUPPORTED_FRAMEWORK = "CHECKOV_UNSUPPORTED_FRAMEWORK"
    PARSE_GAP = "CHECKOV_PARSE_GAP"
    OUTPUT_INVALID = "CHECKOV_OUTPUT_INVALID"
    OUTPUT_LIMIT = "CHECKOV_OUTPUT_LIMIT"
    TIMEOUT = "CHECKOV_TIMEOUT"
    PROCESS_FAILURE = "CHECKOV_PROCESS_FAILURE"
    VERSION_MISMATCH = "CHECKOV_VERSION_MISMATCH"
    CONFIG_IDENTITY_MISMATCH = "CHECKOV_CONFIG_IDENTITY_MISMATCH"
    TOOLCHAIN_IDENTITY_MISMATCH = "CHECKOV_TOOLCHAIN_IDENTITY_MISMATCH"
    PATH_INVALID = "CHECKOV_PATH_INVALID"
    RESULT_INCONSISTENT = "CHECKOV_RESULT_INCONSISTENT"
    EXECUTABLE_INVALID = "CHECKOV_EXECUTABLE_INVALID"
    CONTEXT_INVALID = "CHECKOV_CONTEXT_INVALID"
    PROJECTION_INVALID = "CHECKOV_PROJECTION_INVALID"
    CANCELLED = "CHECKOV_CANCELLED"


class CheckovSourceExecutionError(RuntimeError):
    def __init__(self, code: CheckovFailureCode) -> None:
        self.code = code
        super().__init__("Checkov Source execution failed")


def build_checkov_source_execution_context(
    *,
    source_run_id: str,
    job_id: str,
    profile: RepositoryProfile,
    plan: SourceAnalysisPlan,
    entry: SourceAnalysisPlanEntry,
    binding: TrustedCheckovBinding,
) -> SourceExecutionContext:
    try:
        if (
            not isinstance(profile, RepositoryProfile)
            or not isinstance(plan, SourceAnalysisPlan)
            or not isinstance(entry, SourceAnalysisPlanEntry)
            or not isinstance(binding, TrustedCheckovBinding)
            or plan.repository_digest != profile.repository_digest
            or plan.profile_digest != profile.profile_digest()
            or entry not in plan.entries
            or entry.action is not SourcePlanAction.RUN
            or entry.capability is not AnalysisCapability.CONFIGURATION_SECURITY
            or entry.analyzer_id != CHECKOV_SOURCE_ANALYZER_ID
            or entry.component_id is not None
            or not entry.selected_paths
        ):
            raise ValueError
        files = {item.relative_path: item for item in profile.files}
        selected = tuple(
            SourceExecutionSelectedFile(entry=replace(files[path].entry), component_id=None)
            for path in entry.selected_paths
        )
        return SourceExecutionContext(
            source_run_id=source_run_id,
            job_id=job_id,
            repository_digest=profile.repository_digest,
            profile_digest=profile.profile_digest(),
            plan_digest=plan.plan_digest(),
            source_analyzer_id=CHECKOV_SOURCE_ANALYZER_ID,
            capability=AnalysisCapability.CONFIGURATION_SECURITY,
            component_id=None,
            selected_files=selected,
            binding_digest=binding.binding_digest(),
            core_adapter_id=CHECKOV_SCANNER_ID,
        )
    except (KeyError, TypeError, ValueError):
        raise CheckovSourceExecutionError(CheckovFailureCode.CONTEXT_INVALID) from None


@dataclass(frozen=True, slots=True)
class CheckovExecutionResultEnvelope:
    scanner_id: str
    scanner_version: str
    binding_digest: str
    execution_status: CheckovExecutionStatus
    failure_code: CheckovFailureCode | None
    return_code: int
    stdout_bytes: bytes = field(repr=False)
    stderr_bytes: bytes = field(repr=False)
    duration_ms: int
    timed_out: bool
    output_limit_exceeded: bool
    termination_requested: bool
    force_killed: bool
    cancellation_requested: bool
    projection_id: str
    context_digest: str
    projection_digest: str

    def __post_init__(self) -> None:
        if (
            self.scanner_id != CHECKOV_SCANNER_ID
            or self.scanner_version != CHECKOV_VERSION
            or _SHA256.fullmatch(self.binding_digest) is None
            or not isinstance(self.execution_status, CheckovExecutionStatus)
            or (
                self.failure_code is not None
                and not isinstance(self.failure_code, CheckovFailureCode)
            )
            or type(self.return_code) is not int
            or not isinstance(self.stdout_bytes, bytes)
            or not isinstance(self.stderr_bytes, bytes)
            or len(self.stdout_bytes) > _STDOUT_LIMIT_BYTES
            or len(self.stderr_bytes) > _STDERR_LIMIT_BYTES
            or len(self.stdout_bytes) + len(self.stderr_bytes) > _COMBINED_LIMIT_BYTES
            or type(self.duration_ms) is not int
            or self.duration_ms < 0
            or any(
                type(value) is not bool
                for value in (
                    self.timed_out,
                    self.output_limit_exceeded,
                    self.termination_requested,
                    self.force_killed,
                    self.cancellation_requested,
                )
            )
            or _PROJECTION_ID.fullmatch(self.projection_id) is None
            or _SHA256.fullmatch(self.context_digest) is None
            or _SHA256.fullmatch(self.projection_digest) is None
            or (self.execution_status, self.failure_code) != self._expected_outcome()
        ):
            raise ValueError("Checkov execution result envelope is invalid")

    def _expected_outcome(self) -> tuple[CheckovExecutionStatus, CheckovFailureCode | None]:
        if self.timed_out:
            return CheckovExecutionStatus.TIMED_OUT, CheckovFailureCode.TIMEOUT
        if self.output_limit_exceeded:
            return CheckovExecutionStatus.OUTPUT_LIMIT_EXCEEDED, CheckovFailureCode.OUTPUT_LIMIT
        if self.cancellation_requested:
            return CheckovExecutionStatus.CANCELLED, CheckovFailureCode.CANCELLED
        if self.termination_requested or self.force_killed:
            return CheckovExecutionStatus.FAILED, CheckovFailureCode.PROCESS_FAILURE
        if self.return_code == 0:
            return CheckovExecutionStatus.COMPLETED, None
        return CheckovExecutionStatus.FAILED, CheckovFailureCode.PROCESS_FAILURE

    @classmethod
    def from_process_result(
        cls,
        result: CancellableProcessResult,
        *,
        binding: TrustedCheckovBinding,
        projection: PreparedSourceProjection,
        cancellation_requested: bool,
    ) -> CheckovExecutionResultEnvelope:
        if result.timed_out:
            status, failure = CheckovExecutionStatus.TIMED_OUT, CheckovFailureCode.TIMEOUT
        elif result.output_limit_exceeded:
            status, failure = (
                CheckovExecutionStatus.OUTPUT_LIMIT_EXCEEDED,
                CheckovFailureCode.OUTPUT_LIMIT,
            )
        elif cancellation_requested:
            status, failure = CheckovExecutionStatus.CANCELLED, CheckovFailureCode.CANCELLED
        elif result.termination_requested or result.force_killed:
            status, failure = CheckovExecutionStatus.FAILED, CheckovFailureCode.PROCESS_FAILURE
        elif result.return_code == 0:
            status, failure = CheckovExecutionStatus.COMPLETED, None
        else:
            status, failure = CheckovExecutionStatus.FAILED, CheckovFailureCode.PROCESS_FAILURE
        return cls(
            scanner_id=binding.scanner_id,
            scanner_version=binding.scanner_version,
            binding_digest=binding.binding_digest(),
            execution_status=status,
            failure_code=failure,
            return_code=result.return_code,
            stdout_bytes=bytes(result.stdout),
            stderr_bytes=bytes(result.stderr),
            duration_ms=result.duration_ms,
            timed_out=result.timed_out,
            output_limit_exceeded=result.output_limit_exceeded,
            termination_requested=result.termination_requested,
            force_killed=result.force_killed,
            cancellation_requested=cancellation_requested,
            projection_id=projection.projection_id,
            context_digest=projection.context_digest,
            projection_digest=projection.projection_digest,
        )


class CheckovSourceExecutionContextResolver:
    def __init__(
        self, artifact_store: ContentAddressedArtifactStore, binding: TrustedCheckovBinding
    ) -> None:
        if not isinstance(binding, TrustedCheckovBinding):
            raise TypeError("Checkov Source context resolver is invalid")
        self._integrity_resolver = SourceSemgrepExecutionContextIntegrityResolver(artifact_store)
        self._binding = binding

    def resolve(self, job: JobRecord) -> SourceExecutionContext:
        context = self._integrity_resolver.resolve(job)
        if (
            job.adapter_id != CHECKOV_SCANNER_ID
            or context.binding_digest != self._binding.binding_digest()
            or context.source_analyzer_id != CHECKOV_SOURCE_ANALYZER_ID
            or context.capability is not AnalysisCapability.CONFIGURATION_SECURITY
            or context.core_adapter_id != CHECKOV_SCANNER_ID
        ):
            raise CheckovSourceExecutionError(CheckovFailureCode.CONTEXT_INVALID)
        return context


@dataclass(frozen=True, slots=True)
class CheckovSourceExecutionAuthorization:
    projection: PreparedSourceProjection


class CheckovSourceExecutionResolver:
    def __init__(
        self,
        context_resolver: CheckovSourceExecutionContextResolver,
        projection_manager: SourceProjectionManager,
    ) -> None:
        self._context_resolver = context_resolver
        self._projection_manager = projection_manager

    def resolve(self, job: JobRecord) -> CheckovSourceExecutionAuthorization:
        if (
            not isinstance(job, JobRecord)
            or job.status is not JobStatus.RUNNING
            or job.cancel_requested
        ):
            raise CheckovSourceExecutionError(CheckovFailureCode.CONTEXT_INVALID)
        envelope = SourceExecutionEnvelope.from_payload_json(job.payload_json)
        context = self._context_resolver.resolve(job)
        reference = envelope.projection_reference
        projection = self._projection_manager.reopen_projection(
            reference.projection_id,
            expected_context_digest=reference.context_digest,
            expected_projection_digest=reference.projection_digest,
        )
        entries = tuple(replace(item.entry) for item in context.selected_files)
        manifest = RepositoryManifest(
            entries=entries,
            file_count=len(entries),
            total_bytes=sum(item.size_bytes for item in entries),
            content_digest=repository_content_digest(entries),
        )
        if (
            reference.context_digest != context.context_digest()
            or projection.context_digest != reference.context_digest
            or projection.projection_digest != manifest.content_digest
            or projection.manifest != manifest
        ):
            raise CheckovSourceExecutionError(CheckovFailureCode.PROJECTION_INVALID)
        return CheckovSourceExecutionAuthorization(projection)


@runtime_checkable
class _ProcessExecutor(Protocol):
    def start(self, request: object) -> CancellableProcessHandle: ...


class CheckovSourceExecutionHandle:
    def __init__(
        self,
        process_handle: CancellableProcessHandle,
        binding: TrustedCheckovBinding,
        authorization: CheckovSourceExecutionAuthorization,
    ) -> None:
        self._process_handle = process_handle
        self._binding = binding
        self._authorization = authorization
        self._cancellation_requested = False
        self._result: CheckovExecutionResultEnvelope | None = None

    def __enter__(self) -> CheckovSourceExecutionHandle:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def _wrap(self, result: CancellableProcessResult) -> CheckovExecutionResultEnvelope:
        if self._result is None:
            self._result = CheckovExecutionResultEnvelope.from_process_result(
                result,
                binding=self._binding,
                projection=self._authorization.projection,
                cancellation_requested=self._cancellation_requested,
            )
        return self._result

    def poll(self) -> CheckovExecutionResultEnvelope | None:
        try:
            result = self._process_handle.poll()
        except Exception:
            raise CheckovSourceExecutionError(CheckovFailureCode.PROCESS_FAILURE) from None
        return None if result is None else self._wrap(result)

    def wait(self, timeout_seconds: float | None = None) -> CheckovExecutionResultEnvelope | None:
        try:
            result = self._process_handle.wait(timeout_seconds)
        except Exception:
            raise CheckovSourceExecutionError(CheckovFailureCode.PROCESS_FAILURE) from None
        return None if result is None else self._wrap(result)

    def terminate(self) -> None:
        self._cancellation_requested = True
        self._process_handle.terminate()

    def kill(self) -> None:
        self._cancellation_requested = True
        self._process_handle.kill()

    def close(self) -> None:
        self._process_handle.close()


class CheckovSourceExecutionBridge:
    def __init__(
        self,
        execution_resolver: CheckovSourceExecutionResolver,
        binding: TrustedCheckovBinding,
        process_executor: CancellableProcessExecutor | _ProcessExecutor | None = None,
    ) -> None:
        executor = CancellableProcessExecutor() if process_executor is None else process_executor
        if not isinstance(executor, _ProcessExecutor):
            raise TypeError("Checkov Source execution bridge is invalid")
        self._execution_resolver = execution_resolver
        self._binding = binding
        self._process_executor = executor

    def start(self, job: JobRecord) -> CheckovSourceExecutionHandle:
        try:
            authorization = self._execution_resolver.resolve(job)
            handle = self._binding.start_directory_execution(
                authorization.projection.source_directory,
                self._process_executor,
            )
        except CheckovExecutableIntegrityError:
            raise CheckovSourceExecutionError(CheckovFailureCode.EXECUTABLE_INVALID) from None
        except CheckovVersionVerificationError:
            raise CheckovSourceExecutionError(CheckovFailureCode.VERSION_MISMATCH) from None
        except CheckovConfigurationIntegrityError:
            raise CheckovSourceExecutionError(CheckovFailureCode.CONFIG_IDENTITY_MISMATCH) from None
        except CheckovToolchainIntegrityError:
            raise CheckovSourceExecutionError(
                CheckovFailureCode.TOOLCHAIN_IDENTITY_MISMATCH
            ) from None
        except InvalidCheckovExecutionRequestError:
            raise CheckovSourceExecutionError(CheckovFailureCode.PROCESS_FAILURE) from None
        except (SourceSemgrepExecutionContextError, SourceProjectionError):
            raise CheckovSourceExecutionError(CheckovFailureCode.PROJECTION_INVALID) from None
        return CheckovSourceExecutionHandle(handle, self._binding, authorization)

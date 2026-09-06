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
from securescan.scanners.semgrep.source_execution import (
    SourceExecutionEnvelope,
    SourceSemgrepExecutionContextError,
    SourceSemgrepExecutionContextIntegrityResolver,
)
from securescan.scanners.syft.binding import (
    SYFT_SCANNER_ID,
    SYFT_SOURCE_ANALYZER_ID,
    SYFT_VERSION,
    InvalidSyftExecutionRequestError,
    SyftConfigurationIntegrityError,
    SyftExecutableIntegrityError,
    SyftVersionVerificationError,
    TrustedSyftBinding,
)
from securescan.source.enums import AnalysisCapability
from securescan.source.execution_context import SourceExecutionContext, SourceExecutionSelectedFile
from securescan.source.models import RepositoryProfile
from securescan.source.planning import (
    SourceAnalysisPlan,
    SourceAnalysisPlanEntry,
    SourcePlanAction,
)
from securescan.source.projection import (
    PreparedSourceProjection,
    SourceProjectionError,
    SourceProjectionManager,
)
from securescan.workspaces.models import RepositoryManifest, repository_content_digest

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PROJECTION_ID_PATTERN = re.compile(r"securescan-source-projection-[0-9a-f]{16,48}\Z", re.ASCII)
_STDOUT_LIMIT_BYTES = 100 * 1024 * 1024
_STDERR_LIMIT_BYTES = 64 * 1024


class SyftExecutionStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"


class SyftFailureCode(StrEnum):
    EXECUTABLE_INVALID = "SYFT_EXECUTABLE_INVALID"
    VERSION_INVALID = "SYFT_VERSION_INVALID"
    CONFIG_INVALID = "SYFT_CONFIG_INVALID"
    CONTEXT_INVALID = "SYFT_CONTEXT_INVALID"
    PROJECTION_INVALID = "SYFT_PROJECTION_INVALID"
    EXECUTION_FAILED = "SYFT_EXECUTION_FAILED"
    TIMEOUT = "SYFT_TIMEOUT"
    OUTPUT_LIMIT = "SYFT_OUTPUT_LIMIT"
    CANCELLED = "SYFT_CANCELLED"
    INVALID_EXIT_CODE = "SYFT_INVALID_EXIT_CODE"


class SyftSourceExecutionError(RuntimeError):
    def __init__(self, code: SyftFailureCode) -> None:
        self.code = code
        super().__init__("Syft Source execution failed")


def build_syft_source_execution_context(
    *,
    source_run_id: str,
    job_id: str,
    profile: RepositoryProfile,
    plan: SourceAnalysisPlan,
    entry: SourceAnalysisPlanEntry,
    binding: TrustedSyftBinding,
) -> SourceExecutionContext:
    try:
        if (
            not isinstance(profile, RepositoryProfile)
            or not isinstance(plan, SourceAnalysisPlan)
            or not isinstance(entry, SourceAnalysisPlanEntry)
            or not isinstance(binding, TrustedSyftBinding)
            or plan.repository_digest != profile.repository_digest
            or plan.profile_digest != profile.profile_digest()
            or entry not in plan.entries
            or entry.action is not SourcePlanAction.RUN
            or entry.capability is not AnalysisCapability.PACKAGE_INVENTORY
            or entry.analyzer_id != SYFT_SOURCE_ANALYZER_ID
            or entry.component_id is not None
            or not entry.selected_paths
        ):
            raise ValueError
        files = {item.relative_path: item for item in profile.files}
        selected = tuple(
            SourceExecutionSelectedFile(entry=replace(files[path].entry), component_id=None)
            for path in entry.selected_paths
        )
        if tuple(item.relative_path for item in selected) != entry.selected_paths:
            raise ValueError
        return SourceExecutionContext(
            source_run_id=source_run_id,
            job_id=job_id,
            repository_digest=profile.repository_digest,
            profile_digest=profile.profile_digest(),
            plan_digest=plan.plan_digest(),
            source_analyzer_id=SYFT_SOURCE_ANALYZER_ID,
            capability=AnalysisCapability.PACKAGE_INVENTORY,
            component_id=None,
            selected_files=selected,
            binding_digest=binding.binding_digest(),
            core_adapter_id=SYFT_SCANNER_ID,
        )
    except (KeyError, TypeError, ValueError):
        raise SyftSourceExecutionError(SyftFailureCode.CONTEXT_INVALID) from None


@dataclass(frozen=True, slots=True)
class SyftExecutionResultEnvelope:
    scanner_id: str
    scanner_version: str
    binding_digest: str
    execution_status: SyftExecutionStatus
    failure_code: SyftFailureCode | None
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
            self.scanner_id != SYFT_SCANNER_ID
            or self.scanner_version != SYFT_VERSION
            or _SHA256_PATTERN.fullmatch(self.binding_digest) is None
            or not isinstance(self.execution_status, SyftExecutionStatus)
            or (
                self.failure_code is not None and not isinstance(self.failure_code, SyftFailureCode)
            )
            or type(self.return_code) is not int
            or not isinstance(self.stdout_bytes, bytes)
            or len(self.stdout_bytes) > _STDOUT_LIMIT_BYTES
            or not isinstance(self.stderr_bytes, bytes)
            or len(self.stderr_bytes) > _STDERR_LIMIT_BYTES
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
            or _PROJECTION_ID_PATTERN.fullmatch(self.projection_id) is None
            or _SHA256_PATTERN.fullmatch(self.context_digest) is None
            or _SHA256_PATTERN.fullmatch(self.projection_digest) is None
            or (self.execution_status, self.failure_code) != self._expected_outcome()
        ):
            raise ValueError("Syft execution result envelope is invalid")

    def _expected_outcome(self) -> tuple[SyftExecutionStatus, SyftFailureCode | None]:
        if self.timed_out:
            return SyftExecutionStatus.TIMED_OUT, SyftFailureCode.TIMEOUT
        if self.output_limit_exceeded:
            return SyftExecutionStatus.OUTPUT_LIMIT_EXCEEDED, SyftFailureCode.OUTPUT_LIMIT
        if self.cancellation_requested:
            return SyftExecutionStatus.CANCELLED, SyftFailureCode.CANCELLED
        if self.termination_requested or self.force_killed:
            return SyftExecutionStatus.FAILED, SyftFailureCode.EXECUTION_FAILED
        if self.return_code == 0:
            return SyftExecutionStatus.COMPLETED, None
        return SyftExecutionStatus.FAILED, SyftFailureCode.INVALID_EXIT_CODE

    @classmethod
    def from_process_result(
        cls,
        result: CancellableProcessResult,
        *,
        binding: TrustedSyftBinding,
        projection: PreparedSourceProjection,
        cancellation_requested: bool,
    ) -> SyftExecutionResultEnvelope:
        if result.timed_out:
            status, failure = SyftExecutionStatus.TIMED_OUT, SyftFailureCode.TIMEOUT
        elif result.output_limit_exceeded:
            status, failure = (
                SyftExecutionStatus.OUTPUT_LIMIT_EXCEEDED,
                SyftFailureCode.OUTPUT_LIMIT,
            )
        elif cancellation_requested:
            status, failure = SyftExecutionStatus.CANCELLED, SyftFailureCode.CANCELLED
        elif result.termination_requested or result.force_killed:
            status, failure = SyftExecutionStatus.FAILED, SyftFailureCode.EXECUTION_FAILED
        elif result.return_code == 0:
            status, failure = SyftExecutionStatus.COMPLETED, None
        else:
            status, failure = SyftExecutionStatus.FAILED, SyftFailureCode.INVALID_EXIT_CODE
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


class SyftSourceExecutionContextResolver:
    def __init__(
        self, artifact_store: ContentAddressedArtifactStore, binding: TrustedSyftBinding
    ) -> None:
        if not isinstance(binding, TrustedSyftBinding):
            raise TypeError("Syft Source context resolver is invalid")
        self._integrity_resolver = SourceSemgrepExecutionContextIntegrityResolver(artifact_store)
        self._binding = binding

    def resolve(self, job: JobRecord) -> SourceExecutionContext:
        context = self._integrity_resolver.resolve(job)
        if (
            job.adapter_id != SYFT_SCANNER_ID
            or context.binding_digest != self._binding.binding_digest()
            or context.source_analyzer_id != SYFT_SOURCE_ANALYZER_ID
            or context.capability is not AnalysisCapability.PACKAGE_INVENTORY
            or context.core_adapter_id != SYFT_SCANNER_ID
        ):
            raise SyftSourceExecutionError(SyftFailureCode.CONTEXT_INVALID)
        return context


@dataclass(frozen=True, slots=True)
class SyftSourceExecutionAuthorization:
    projection: PreparedSourceProjection


class SyftSourceExecutionResolver:
    def __init__(
        self,
        context_resolver: SyftSourceExecutionContextResolver,
        projection_manager: SourceProjectionManager,
    ) -> None:
        self._context_resolver = context_resolver
        self._projection_manager = projection_manager

    def resolve(self, job: JobRecord) -> SyftSourceExecutionAuthorization:
        if (
            not isinstance(job, JobRecord)
            or job.status is not JobStatus.RUNNING
            or job.cancel_requested
        ):
            raise SyftSourceExecutionError(SyftFailureCode.CONTEXT_INVALID)
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
            raise SyftSourceExecutionError(SyftFailureCode.PROJECTION_INVALID)
        return SyftSourceExecutionAuthorization(projection)


@runtime_checkable
class _ProcessExecutor(Protocol):
    def start(self, request: object) -> CancellableProcessHandle: ...


class SyftSourceExecutionHandle:
    def __init__(
        self,
        process_handle: CancellableProcessHandle,
        binding: TrustedSyftBinding,
        authorization: SyftSourceExecutionAuthorization,
    ) -> None:
        self._process_handle = process_handle
        self._binding = binding
        self._authorization = authorization
        self._cancellation_requested = False
        self._result: SyftExecutionResultEnvelope | None = None

    def __enter__(self) -> SyftSourceExecutionHandle:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def _wrap(self, result: CancellableProcessResult) -> SyftExecutionResultEnvelope:
        if self._result is None:
            self._result = SyftExecutionResultEnvelope.from_process_result(
                result,
                binding=self._binding,
                projection=self._authorization.projection,
                cancellation_requested=self._cancellation_requested,
            )
        return self._result

    def poll(self) -> SyftExecutionResultEnvelope | None:
        try:
            result = self._process_handle.poll()
        except Exception:
            raise SyftSourceExecutionError(SyftFailureCode.EXECUTION_FAILED) from None
        return None if result is None else self._wrap(result)

    def wait(self, timeout_seconds: float | None = None) -> SyftExecutionResultEnvelope | None:
        try:
            result = self._process_handle.wait(timeout_seconds)
        except Exception:
            raise SyftSourceExecutionError(SyftFailureCode.EXECUTION_FAILED) from None
        return None if result is None else self._wrap(result)

    def terminate(self) -> None:
        self._cancellation_requested = True
        self._process_handle.terminate()

    def kill(self) -> None:
        self._cancellation_requested = True
        self._process_handle.kill()

    def close(self) -> None:
        self._process_handle.close()


class SyftSourceExecutionBridge:
    def __init__(
        self,
        execution_resolver: SyftSourceExecutionResolver,
        binding: TrustedSyftBinding,
        process_executor: CancellableProcessExecutor | _ProcessExecutor | None = None,
    ) -> None:
        executor = CancellableProcessExecutor() if process_executor is None else process_executor
        if not isinstance(executor, _ProcessExecutor):
            raise TypeError("Syft Source execution bridge is invalid")
        self._execution_resolver = execution_resolver
        self._binding = binding
        self._process_executor = executor

    def start(self, job: JobRecord) -> SyftSourceExecutionHandle:
        try:
            authorization = self._execution_resolver.resolve(job)
            handle = self._binding.start_directory_execution(
                authorization.projection.source_directory, self._process_executor
            )
        except SyftExecutableIntegrityError:
            raise SyftSourceExecutionError(SyftFailureCode.EXECUTABLE_INVALID) from None
        except SyftVersionVerificationError:
            raise SyftSourceExecutionError(SyftFailureCode.VERSION_INVALID) from None
        except SyftConfigurationIntegrityError:
            raise SyftSourceExecutionError(SyftFailureCode.CONFIG_INVALID) from None
        except InvalidSyftExecutionRequestError:
            raise SyftSourceExecutionError(SyftFailureCode.EXECUTION_FAILED) from None
        except (SourceSemgrepExecutionContextError, SourceProjectionError):
            raise SyftSourceExecutionError(SyftFailureCode.PROJECTION_INVALID) from None
        return SyftSourceExecutionHandle(handle, self._binding, authorization)

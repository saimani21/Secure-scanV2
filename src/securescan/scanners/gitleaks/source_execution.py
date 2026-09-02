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
from securescan.scanners.gitleaks.binding import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
    GitleaksConfigurationIntegrityError,
    GitleaksExecutableIntegrityError,
    GitleaksVersionVerificationError,
    InvalidGitleaksExecutionRequestError,
    TrustedGitleaksBinding,
)
from securescan.scanners.semgrep.source_execution import (
    SourceExecutionEnvelope,
    SourceSemgrepExecutionContextError,
    SourceSemgrepExecutionContextIntegrityResolver,
)
from securescan.source.enums import AnalysisCapability
from securescan.source.execution_context import SourceExecutionContext
from securescan.source.projection import (
    PreparedSourceProjection,
    SourceProjectionError,
    SourceProjectionManager,
)
from securescan.workspaces.models import (
    RepositoryManifest,
    repository_content_digest,
)

GITLEAKS_SOURCE_ANALYZER_ID = "gitleaks-source-v1"
GITLEAKS_V04A_BASELINE_COMMIT = "6f8e5002e14385e095af8784a91afc4a1618b017"

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PROJECTION_ID_PATTERN = re.compile(
    r"securescan-source-projection-[0-9a-f]{16,48}\Z",
    re.ASCII,
)
_STDOUT_LIMIT_BYTES = 64 * 1024 * 1024
_STDERR_LIMIT_BYTES = 64 * 1024


class GitleaksExecutionStatus(StrEnum):
    COMPLETED_NO_FINDINGS = "completed_no_findings"
    COMPLETED_WITH_FINDINGS = "completed_with_findings"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"


class GitleaksFailureCode(StrEnum):
    EXECUTABLE_INVALID = "GITLEAKS_EXECUTABLE_INVALID"
    VERSION_INVALID = "GITLEAKS_VERSION_INVALID"
    CONFIG_INVALID = "GITLEAKS_CONFIG_INVALID"
    CONTEXT_INVALID = "GITLEAKS_CONTEXT_INVALID"
    PROJECTION_INVALID = "GITLEAKS_PROJECTION_INVALID"
    EXECUTION_FAILED = "GITLEAKS_EXECUTION_FAILED"
    TIMEOUT = "GITLEAKS_TIMEOUT"
    OUTPUT_LIMIT = "GITLEAKS_OUTPUT_LIMIT"
    CANCELLED = "GITLEAKS_CANCELLED"
    INVALID_EXIT_CODE = "GITLEAKS_INVALID_EXIT_CODE"


_FAILURE_MESSAGES = {
    GitleaksFailureCode.EXECUTABLE_INVALID: "Trusted Gitleaks executable is unavailable",
    GitleaksFailureCode.VERSION_INVALID: "Trusted Gitleaks version is unavailable",
    GitleaksFailureCode.CONFIG_INVALID: "Trusted Gitleaks configuration is unavailable",
    GitleaksFailureCode.CONTEXT_INVALID: "Gitleaks Source execution context is invalid",
    GitleaksFailureCode.PROJECTION_INVALID: "Gitleaks Source projection is invalid",
    GitleaksFailureCode.EXECUTION_FAILED: "Gitleaks execution could not be started or observed",
}


class GitleaksSourceExecutionError(RuntimeError):
    """Fixed-message Gitleaks execution failure that never embeds tool output."""

    def __init__(self, code: GitleaksFailureCode) -> None:
        if code not in _FAILURE_MESSAGES:
            raise TypeError("Gitleaks Source execution failure code is invalid")
        self.code = code
        super().__init__(_FAILURE_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class GitleaksExecutionResultEnvelope:
    scanner_id: str
    scanner_version: str
    binding_digest: str
    execution_status: GitleaksExecutionStatus
    failure_code: GitleaksFailureCode | None
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
            self.scanner_id != GITLEAKS_SCANNER_ID
            or self.scanner_version != GITLEAKS_VERSION
            or not isinstance(self.binding_digest, str)
            or _SHA256_PATTERN.fullmatch(self.binding_digest) is None
            or not isinstance(self.execution_status, GitleaksExecutionStatus)
            or (
                self.failure_code is not None
                and not isinstance(self.failure_code, GitleaksFailureCode)
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
            or not isinstance(self.projection_id, str)
            or _PROJECTION_ID_PATTERN.fullmatch(self.projection_id) is None
            or any(
                not isinstance(digest, str)
                or _SHA256_PATTERN.fullmatch(digest) is None
                for digest in (self.context_digest, self.projection_digest)
            )
            or (self.execution_status, self.failure_code)
            != self._expected_outcome()
        ):
            raise ValueError("Gitleaks execution result envelope is invalid")

    def _expected_outcome(
        self,
    ) -> tuple[GitleaksExecutionStatus, GitleaksFailureCode | None]:
        if self.timed_out:
            return GitleaksExecutionStatus.TIMED_OUT, GitleaksFailureCode.TIMEOUT
        if self.output_limit_exceeded:
            return (
                GitleaksExecutionStatus.OUTPUT_LIMIT_EXCEEDED,
                GitleaksFailureCode.OUTPUT_LIMIT,
            )
        if self.cancellation_requested:
            return GitleaksExecutionStatus.CANCELLED, GitleaksFailureCode.CANCELLED
        if self.termination_requested or self.force_killed:
            return (
                GitleaksExecutionStatus.FAILED,
                GitleaksFailureCode.EXECUTION_FAILED,
            )
        if self.return_code == 0:
            return GitleaksExecutionStatus.COMPLETED_NO_FINDINGS, None
        if self.return_code == 1:
            return GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS, None
        return (
            GitleaksExecutionStatus.FAILED,
            GitleaksFailureCode.INVALID_EXIT_CODE,
        )

    @classmethod
    def from_process_result(
        cls,
        result: CancellableProcessResult,
        *,
        binding: TrustedGitleaksBinding,
        projection: PreparedSourceProjection,
        cancellation_requested: bool,
    ) -> GitleaksExecutionResultEnvelope:
        if (
            not isinstance(result, CancellableProcessResult)
            or not isinstance(binding, TrustedGitleaksBinding)
            or not isinstance(projection, PreparedSourceProjection)
            or type(cancellation_requested) is not bool
        ):
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.EXECUTION_FAILED
            )
        if result.timed_out:
            status = GitleaksExecutionStatus.TIMED_OUT
            failure_code = GitleaksFailureCode.TIMEOUT
        elif result.output_limit_exceeded:
            status = GitleaksExecutionStatus.OUTPUT_LIMIT_EXCEEDED
            failure_code = GitleaksFailureCode.OUTPUT_LIMIT
        elif cancellation_requested:
            status = GitleaksExecutionStatus.CANCELLED
            failure_code = GitleaksFailureCode.CANCELLED
        elif result.termination_requested or result.force_killed:
            status = GitleaksExecutionStatus.FAILED
            failure_code = GitleaksFailureCode.EXECUTION_FAILED
        elif result.return_code == 0:
            status = GitleaksExecutionStatus.COMPLETED_NO_FINDINGS
            failure_code = None
        elif result.return_code == 1:
            status = GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
            failure_code = None
        else:
            status = GitleaksExecutionStatus.FAILED
            failure_code = GitleaksFailureCode.INVALID_EXIT_CODE
        return cls(
            scanner_id=binding.scanner_id,
            scanner_version=binding.scanner_version,
            binding_digest=binding.binding_digest(),
            execution_status=status,
            failure_code=failure_code,
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


class GitleaksSourceExecutionContextResolver:
    """Apply the frozen Gitleaks policy to an existing durable C1 context."""

    def __init__(
        self,
        artifact_store: ContentAddressedArtifactStore,
        binding: TrustedGitleaksBinding,
    ) -> None:
        if not isinstance(binding, TrustedGitleaksBinding):
            raise TypeError("Gitleaks Source context resolver is invalid")
        binding._validate_state()
        self._integrity_resolver = SourceSemgrepExecutionContextIntegrityResolver(
            artifact_store
        )
        self._binding = binding

    def resolve(self, job: JobRecord) -> SourceExecutionContext:
        context = self._integrity_resolver.resolve(job)
        try:
            self._binding._validate_state()
            matches = (
                job.adapter_id == GITLEAKS_SCANNER_ID
                and context.binding_digest == self._binding.binding_digest()
                and context.source_analyzer_id == GITLEAKS_SOURCE_ANALYZER_ID
                and context.capability is AnalysisCapability.SECRET_DETECTION
                and context.core_adapter_id == GITLEAKS_SCANNER_ID
            )
        except Exception as exc:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.CONTEXT_INVALID
            ) from exc
        if not matches:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.CONTEXT_INVALID
            )
        return context


@dataclass(frozen=True, slots=True)
class GitleaksSourceExecutionAuthorization:
    projection: PreparedSourceProjection


class GitleaksSourceExecutionResolver:
    """Resolve only the immutable C2 projection named by durable Source state."""

    def __init__(
        self,
        context_resolver: GitleaksSourceExecutionContextResolver,
        projection_manager: SourceProjectionManager,
    ) -> None:
        if (
            not isinstance(
                context_resolver,
                GitleaksSourceExecutionContextResolver,
            )
            or not isinstance(projection_manager, SourceProjectionManager)
        ):
            raise TypeError("Gitleaks Source execution resolver is invalid")
        self._context_resolver = context_resolver
        self._projection_manager = projection_manager

    def resolve(self, job: JobRecord) -> GitleaksSourceExecutionAuthorization:
        if (
            not isinstance(job, JobRecord)
            or job.status is not JobStatus.RUNNING
            or job.cancel_requested
        ):
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.CONTEXT_INVALID
            )
        envelope = SourceExecutionEnvelope.from_payload_json(job.payload_json)
        context = self._context_resolver.resolve(job)
        reference = envelope.projection_reference
        projection = self._projection_manager.reopen_projection(
            reference.projection_id,
            expected_context_digest=reference.context_digest,
            expected_projection_digest=reference.projection_digest,
        )
        selected_entries = tuple(
            replace(selected.entry) for selected in context.selected_files
        )
        selected_manifest = RepositoryManifest(
            entries=selected_entries,
            file_count=len(selected_entries),
            total_bytes=sum(entry.size_bytes for entry in selected_entries),
            content_digest=repository_content_digest(selected_entries),
        )
        if (
            reference.context_digest != envelope.context_digest
            or reference.context_digest != context.context_digest()
            or projection.context_digest != context.context_digest()
            or reference.projection_digest != selected_manifest.content_digest
            or projection.projection_digest != selected_manifest.content_digest
            or projection.manifest != selected_manifest
        ):
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.PROJECTION_INVALID
            )
        return GitleaksSourceExecutionAuthorization(projection=projection)


@runtime_checkable
class _ProcessExecutor(Protocol):
    def start(self, request: object) -> CancellableProcessHandle: ...


class GitleaksSourceExecutionHandle:
    """Expose cancellable opaque output without parsing or persisting it."""

    def __init__(
        self,
        process_handle: CancellableProcessHandle,
        binding: TrustedGitleaksBinding,
        authorization: GitleaksSourceExecutionAuthorization,
    ) -> None:
        if (
            not isinstance(process_handle, CancellableProcessHandle)
            or not isinstance(binding, TrustedGitleaksBinding)
            or not isinstance(authorization, GitleaksSourceExecutionAuthorization)
        ):
            raise TypeError("Gitleaks Source execution handle is invalid")
        self._process_handle = process_handle
        self._binding = binding
        self._authorization = authorization
        self._cancellation_requested = False
        self._result: GitleaksExecutionResultEnvelope | None = None

    def __enter__(self) -> GitleaksSourceExecutionHandle:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def poll(self) -> GitleaksExecutionResultEnvelope | None:
        if self._result is not None:
            return self._result
        try:
            result = self._process_handle.poll()
        except Exception:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.EXECUTION_FAILED
            ) from None
        if result is None:
            return None
        self._result = GitleaksExecutionResultEnvelope.from_process_result(
            result,
            binding=self._binding,
            projection=self._authorization.projection,
            cancellation_requested=self._cancellation_requested,
        )
        return self._result

    def terminate(self) -> None:
        self._cancellation_requested = True
        try:
            self._process_handle.terminate()
        except Exception:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.EXECUTION_FAILED
            ) from None

    def kill(self) -> None:
        self._cancellation_requested = True
        try:
            self._process_handle.kill()
        except Exception:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.EXECUTION_FAILED
            ) from None

    def wait(
        self,
        timeout_seconds: float | None = None,
    ) -> GitleaksExecutionResultEnvelope | None:
        try:
            result = self._process_handle.wait(timeout_seconds)
        except Exception:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.EXECUTION_FAILED
            ) from None
        if result is None:
            return None
        if self._result is None:
            self._result = GitleaksExecutionResultEnvelope.from_process_result(
                result,
                binding=self._binding,
                projection=self._authorization.projection,
                cancellation_requested=self._cancellation_requested,
            )
        return self._result

    def close(self) -> None:
        try:
            self._process_handle.close()
        except Exception:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.EXECUTION_FAILED
            ) from None


class GitleaksSourceExecutionBridge:
    """Launch frozen Gitleaks only for a durable, verified Source projection."""

    def __init__(
        self,
        execution_resolver: GitleaksSourceExecutionResolver,
        binding: TrustedGitleaksBinding,
        process_executor: CancellableProcessExecutor | _ProcessExecutor | None = None,
    ) -> None:
        executor = CancellableProcessExecutor() if process_executor is None else process_executor
        if (
            not isinstance(execution_resolver, GitleaksSourceExecutionResolver)
            or not isinstance(binding, TrustedGitleaksBinding)
            or not isinstance(executor, _ProcessExecutor)
        ):
            raise TypeError("Gitleaks Source execution bridge is invalid")
        binding._validate_state()
        self._execution_resolver = execution_resolver
        self._binding = binding
        self._process_executor = executor

    def start(self, job: JobRecord) -> GitleaksSourceExecutionHandle:
        try:
            authorization = self._execution_resolver.resolve(job)
        except GitleaksSourceExecutionError:
            raise
        except SourceSemgrepExecutionContextError:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.CONTEXT_INVALID
            ) from None
        except SourceProjectionError:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.PROJECTION_INVALID
            ) from None
        except Exception:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.CONTEXT_INVALID
            ) from None

        try:
            process_handle = self._binding.start_current_snapshot_execution(
                authorization.projection.source_directory,
                self._process_executor,
            )
        except GitleaksExecutableIntegrityError:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.EXECUTABLE_INVALID
            ) from None
        except GitleaksVersionVerificationError:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.VERSION_INVALID
            ) from None
        except GitleaksConfigurationIntegrityError:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.CONFIG_INVALID
            ) from None
        except InvalidGitleaksExecutionRequestError:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.EXECUTION_FAILED
            ) from None
        except Exception:
            raise GitleaksSourceExecutionError(
                GitleaksFailureCode.EXECUTION_FAILED
            ) from None
        return GitleaksSourceExecutionHandle(
            process_handle,
            self._binding,
            authorization,
        )

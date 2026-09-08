from __future__ import annotations

from pathlib import Path
from typing import Protocol

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import JobStatus
from securescan.execution.supervisor import (
    AttemptBoundProcessExecutor,
    SupervisorAttemptIdentity,
)
from securescan.jobs.models import JobRecord
from securescan.scanners.checkov import (
    CHECKOV_SOURCE_ANALYZER_ID,
    CheckovExecutionResultEnvelope,
    CheckovSourceExecutionBridge,
    CheckovSourceExecutionContextResolver,
    CheckovSourceExecutionResolver,
    TrustedCheckovBinding,
)
from securescan.scanners.gitleaks import (
    GITLEAKS_SOURCE_ANALYZER_ID,
    GitleaksExecutionResultEnvelope,
    GitleaksSourceExecutionBridge,
    GitleaksSourceExecutionContextResolver,
    GitleaksSourceExecutionResolver,
    TrustedGitleaksBinding,
)
from securescan.scanners.syft import (
    SYFT_SOURCE_ANALYZER_ID,
    SyftExecutionResultEnvelope,
    SyftSourceExecutionBridge,
    SyftSourceExecutionContextResolver,
    SyftSourceExecutionResolver,
    TrustedSyftBinding,
)
from securescan.source.execution_context import SourceExecutionContext
from securescan.source.projection import PreparedSourceProjection, SourceProjectionManager

from .execution import (
    SourceScannerAttemptRecord,
    SourceScannerAttemptService,
    SourceScannerExecutionConflictError,
)
from .execution_models import SafeSourceNativeResult


class _BridgeHandle(Protocol):
    def poll(self) -> object | None: ...

    def wait(self, timeout_seconds: float | None = None) -> object | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def close(self) -> None: ...


class SourceLocalNativeExecutionHandle:
    """Expose only a safe canonical native result from a frozen local bridge."""

    def __init__(
        self,
        *,
        handle: _BridgeHandle,
        projection: PreparedSourceProjection,
        context: SourceExecutionContext,
        attempt: SourceScannerAttemptRecord,
        analyzer_id: str,
    ) -> None:
        self._handle = handle
        self._projection = projection
        self._context = context
        self._attempt = attempt
        self._analyzer_id = analyzer_id
        self._result: SafeSourceNativeResult | None = None

    def poll(self) -> SafeSourceNativeResult | None:
        if self._result is not None:
            return self._result
        envelope = self._handle.poll()
        return None if envelope is None else self._wrap(envelope)

    def wait(self, timeout_seconds: float | None = None) -> SafeSourceNativeResult | None:
        if self._result is not None:
            return self._result
        envelope = self._handle.wait(timeout_seconds)
        return None if envelope is None else self._wrap(envelope)

    def terminate(self) -> None:
        self._handle.terminate()

    def kill(self) -> None:
        self._handle.kill()

    def close(self) -> None:
        self._handle.close()

    def _wrap(self, envelope: object) -> SafeSourceNativeResult:
        common = {
            "projection": self._projection,
            "node_id": self._attempt.node_id,
            "job_id": self._attempt.job_id,
            "attempt_number": self._attempt.attempt_number,
            "analyzer_id": self._analyzer_id,
            "context": self._context,
        }
        if isinstance(envelope, GitleaksExecutionResultEnvelope):
            result = SafeSourceNativeResult.from_gitleaks_execution(
                envelope=envelope, **common
            )
        elif isinstance(envelope, SyftExecutionResultEnvelope):
            result = SafeSourceNativeResult.from_syft_execution(
                envelope=envelope, **common
            )
        elif isinstance(envelope, CheckovExecutionResultEnvelope):
            result = SafeSourceNativeResult.from_checkov_execution(
                envelope=envelope, **common
            )
        else:
            raise SourceScannerExecutionConflictError
        self._result = result
        return result


class SourceLocalBridgeExecutionService:
    """Bind the frozen local scanner bridges to S6B attempt containment."""

    def __init__(
        self,
        artifact_store: ContentAddressedArtifactStore,
        projection_manager: SourceProjectionManager,
        attempt_service: SourceScannerAttemptService,
        receipt_root: Path,
    ) -> None:
        if (
            not isinstance(artifact_store, ContentAddressedArtifactStore)
            or not isinstance(projection_manager, SourceProjectionManager)
            or not isinstance(attempt_service, SourceScannerAttemptService)
            or not isinstance(receipt_root, Path)
            or not receipt_root.is_absolute()
        ):
            raise SourceScannerExecutionConflictError
        self._artifacts = artifact_store
        self._projections = projection_manager
        self._attempts = attempt_service
        self._receipt_root = receipt_root

    def start_gitleaks(
        self,
        *,
        job: JobRecord,
        attempt: SourceScannerAttemptRecord,
        binding: TrustedGitleaksBinding,
    ) -> SourceLocalNativeExecutionHandle:
        context_resolver = GitleaksSourceExecutionContextResolver(self._artifacts, binding)
        resolver = GitleaksSourceExecutionResolver(context_resolver, self._projections)
        context, projection = self._resolve(job, attempt, context_resolver, resolver)
        executor = self._executor(
            attempt,
            binding.build_current_snapshot_request(projection.source_directory),
        )
        bridge = GitleaksSourceExecutionBridge(resolver, binding, executor)
        return SourceLocalNativeExecutionHandle(
            handle=bridge.start(job),
            projection=projection,
            context=context,
            attempt=attempt,
            analyzer_id=GITLEAKS_SOURCE_ANALYZER_ID,
        )

    def start_syft(
        self,
        *,
        job: JobRecord,
        attempt: SourceScannerAttemptRecord,
        binding: TrustedSyftBinding,
    ) -> SourceLocalNativeExecutionHandle:
        context_resolver = SyftSourceExecutionContextResolver(self._artifacts, binding)
        resolver = SyftSourceExecutionResolver(context_resolver, self._projections)
        context, projection = self._resolve(job, attempt, context_resolver, resolver)
        executor = self._executor(
            attempt,
            binding.build_directory_request(projection.source_directory),
        )
        bridge = SyftSourceExecutionBridge(resolver, binding, executor)
        return SourceLocalNativeExecutionHandle(
            handle=bridge.start(job),
            projection=projection,
            context=context,
            attempt=attempt,
            analyzer_id=SYFT_SOURCE_ANALYZER_ID,
        )

    def start_checkov(
        self,
        *,
        job: JobRecord,
        attempt: SourceScannerAttemptRecord,
        binding: TrustedCheckovBinding,
    ) -> SourceLocalNativeExecutionHandle:
        context_resolver = CheckovSourceExecutionContextResolver(self._artifacts, binding)
        resolver = CheckovSourceExecutionResolver(context_resolver, self._projections)
        context, projection = self._resolve(job, attempt, context_resolver, resolver)
        executor = self._executor(
            attempt,
            binding.build_directory_request(projection.source_directory),
        )
        bridge = CheckovSourceExecutionBridge(resolver, binding, executor)
        return SourceLocalNativeExecutionHandle(
            handle=bridge.start(job),
            projection=projection,
            context=context,
            attempt=attempt,
            analyzer_id=CHECKOV_SOURCE_ANALYZER_ID,
        )

    def _executor(
        self,
        attempt: SourceScannerAttemptRecord,
        final_request: object,
    ) -> AttemptBoundProcessExecutor:
        from securescan.execution import CancellableProcessRequest

        if not isinstance(final_request, CancellableProcessRequest):
            raise SourceScannerExecutionConflictError
        return AttemptBoundProcessExecutor(
            attempt=SupervisorAttemptIdentity(
                job_id=attempt.job_id,
                attempt_number=attempt.attempt_number,
                attempt_token=attempt.attempt_token,
            ),
            final_request=final_request,
            attempt_persistence=self._attempts,
            receipt_directory=(
                self._receipt_root / attempt.job_id / str(attempt.attempt_number)
            ),
        )

    @staticmethod
    def _resolve(
        job: JobRecord,
        attempt: SourceScannerAttemptRecord,
        context_resolver: object,
        execution_resolver: object,
    ) -> tuple[SourceExecutionContext, PreparedSourceProjection]:
        if (
            not isinstance(job, JobRecord)
            or job.status is not JobStatus.RUNNING
            or job.cancel_requested
            or job.id != attempt.job_id
            or job.run_id != attempt.run_id
            or job.attempt_count != attempt.attempt_number
        ):
            raise SourceScannerExecutionConflictError
        context = context_resolver.resolve(job)  # type: ignore[attr-defined]
        authorization = execution_resolver.resolve(job)  # type: ignore[attr-defined]
        if not isinstance(context, SourceExecutionContext) or not isinstance(
            authorization.projection, PreparedSourceProjection
        ):
            raise SourceScannerExecutionConflictError
        return context, authorization.projection

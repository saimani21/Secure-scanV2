from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol, runtime_checkable

from securescan.domain.job_state import is_terminal_job_status
from securescan.jobs.models import JobRecord
from securescan.jobs.repository import JobRepositoryError
from securescan.scanners.semgrep.source_execution import (
    SOURCE_EXECUTION_PAYLOAD_KEY,
    SourceExecutionEnvelope,
)
from securescan.source.execution_context import SourceExecutionContext
from securescan.source.projection import (
    SourceProjectionCleanupError,
    SourceProjectionError,
    SourceProjectionManager,
    SourceProjectionMissingError,
)
from securescan.workspaces.models import RepositoryManifest, repository_content_digest


class SourceProjectionLifecycleDisposition(StrEnum):
    CLEANED = "cleaned"
    ALREADY_ABSENT = "already_absent"
    RETAINED_NON_TERMINAL = "retained_non_terminal"
    UNSAFE_TO_CLEAN = "unsafe_to_clean"
    CLEANUP_FAILED = "cleanup_failed"
    IGNORED_NON_SOURCE = "ignored_non_source"
    DURABLE_JOB_MISSING = "durable_job_missing"


@dataclass(frozen=True, slots=True)
class SourceProjectionLifecycleResult:
    job_id: str
    disposition: SourceProjectionLifecycleDisposition
    projection_id: str | None


@runtime_checkable
class SourceExecutionContextResolver(Protocol):
    """Resolve one scanner-specific policy-validated durable Source context."""

    def resolve(self, job: JobRecord) -> SourceExecutionContext: ...


@runtime_checkable
class SourceJobRepository(Protocol):
    """Read the durable job truth required by projection reconciliation."""

    def get_job(self, job_id: str) -> JobRecord | None: ...


class SourceProjectionLifecycleService:
    """Reconcile one projection from existing durable job truth."""

    def __init__(
        self,
        job_repository: SourceJobRepository,
        context_resolver: SourceExecutionContextResolver,
        projection_manager: SourceProjectionManager,
    ) -> None:
        if (
            not isinstance(job_repository, SourceJobRepository)
            or not isinstance(context_resolver, SourceExecutionContextResolver)
            or not isinstance(projection_manager, SourceProjectionManager)
        ):
            raise TypeError("Source projection lifecycle configuration is invalid")
        self._job_repository = job_repository
        self._context_resolver = context_resolver
        self._projection_manager = projection_manager

    def reconcile_job(self, job_id: str) -> SourceProjectionLifecycleResult:
        if not isinstance(job_id, str) or not job_id.strip():
            raise TypeError("Source projection lifecycle job identity is invalid")
        try:
            job = self._job_repository.get_job(job_id)
        except JobRepositoryError:
            return self._result(
                job_id,
                SourceProjectionLifecycleDisposition.UNSAFE_TO_CLEAN,
            )
        if job is None:
            return self._result(
                job_id,
                SourceProjectionLifecycleDisposition.DURABLE_JOB_MISSING,
            )
        payload = job.payload_json
        if not isinstance(payload, dict) or SOURCE_EXECUTION_PAYLOAD_KEY not in payload:
            return self._result(
                job.id,
                SourceProjectionLifecycleDisposition.IGNORED_NON_SOURCE,
            )
        if not is_terminal_job_status(job.status):
            return self._result(
                job.id,
                SourceProjectionLifecycleDisposition.RETAINED_NON_TERMINAL,
            )

        projection_id: str | None = None
        try:
            envelope = SourceExecutionEnvelope.from_payload_json(payload)
            reference = envelope.projection_reference
            projection_id = reference.projection_id
            context = self._context_resolver.resolve(job)
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
                or reference.projection_digest != selected_manifest.content_digest
            ):
                return self._result(
                    job.id,
                    SourceProjectionLifecycleDisposition.UNSAFE_TO_CLEAN,
                    projection_id,
                )
            projection = self._projection_manager.reopen_projection(
                reference.projection_id,
                expected_context_digest=reference.context_digest,
                expected_projection_digest=reference.projection_digest,
            )
            if projection.manifest != selected_manifest:
                return self._result(
                    job.id,
                    SourceProjectionLifecycleDisposition.UNSAFE_TO_CLEAN,
                    projection_id,
                )
        except SourceProjectionMissingError:
            return self._result(
                job.id,
                SourceProjectionLifecycleDisposition.ALREADY_ABSENT,
                projection_id,
            )
        except Exception:
            return self._result(
                job.id,
                SourceProjectionLifecycleDisposition.UNSAFE_TO_CLEAN,
                projection_id,
            )

        try:
            self._projection_manager.cleanup_projection(projection)
        except SourceProjectionMissingError:
            disposition = SourceProjectionLifecycleDisposition.ALREADY_ABSENT
        except SourceProjectionCleanupError:
            disposition = SourceProjectionLifecycleDisposition.CLEANUP_FAILED
        except SourceProjectionError:
            disposition = SourceProjectionLifecycleDisposition.UNSAFE_TO_CLEAN
        except Exception:
            disposition = SourceProjectionLifecycleDisposition.CLEANUP_FAILED
        else:
            disposition = SourceProjectionLifecycleDisposition.CLEANED
        return self._result(job.id, disposition, projection_id)

    @staticmethod
    def _result(
        job_id: str,
        disposition: SourceProjectionLifecycleDisposition,
        projection_id: str | None = None,
    ) -> SourceProjectionLifecycleResult:
        return SourceProjectionLifecycleResult(
            job_id=job_id,
            disposition=disposition,
            projection_id=projection_id,
        )


class SourceProjectionTerminalObserver:
    """Best-effort immediate cleanup with an optional operational result sink."""

    def __init__(
        self,
        lifecycle_service: SourceProjectionLifecycleService,
        result_observer: Callable[[SourceProjectionLifecycleResult], object] | None = None,
    ) -> None:
        if not isinstance(lifecycle_service, SourceProjectionLifecycleService) or (
            result_observer is not None and not callable(result_observer)
        ):
            raise TypeError("Source projection terminal observer is invalid")
        self._lifecycle_service = lifecycle_service
        self._result_observer = result_observer

    def __call__(self, job: JobRecord) -> SourceProjectionLifecycleResult:
        if not isinstance(job, JobRecord):
            raise TypeError("Source projection terminal observer job is invalid")
        result = self._lifecycle_service.reconcile_job(job.id)
        if self._result_observer is not None:
            self._result_observer(result)
        return result

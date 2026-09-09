from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4, uuid5

from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import (
    ArtifactKind,
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    ToolExecutionRow,
    utc_now,
)
from securescan.scanners.semgrep.source_execution import (
    SourceExecutionEnvelope,
    SourceProjectionExecutionReference,
)
from securescan.source.execution_context import (
    SourceExecutionContext,
    SourceExecutionSelectedFile,
)
from securescan.source.projection import (
    PreparedSourceProjection,
    SourceProjectionError,
    SourceProjectionManager,
)
from securescan.workspaces.models import (
    PreparedRepositoryWorkspace,
    RepositoryManifest,
    repository_content_digest,
)

from .execution_models import (
    SAFE_NATIVE_RESULT_MEDIA_TYPE,
    SAFE_NATIVE_RESULT_SCHEMA_VERSION,
    SafeSourceNativeResult,
    SourceAttemptCleanupReceipt,
    SourceSandboxCleanupReceipt,
    SourceScannerExecutionIntegrityError,
    SourceScannerFailureCode,
    source_sandbox_execution_identity,
)
from .models import (
    OrchestrationContainmentState,
    OrchestrationLifecycleState,
    OrchestrationNodeDisposition,
    OrchestrationNodeLifecycleState,
    SourceAuthority,
    SourceOrchestrationIntegrityError,
)
from .service import SourceOrchestrationService

_JOB_NAMESPACE = UUID("483e3159-ff89-52aa-a2c7-2ed299c90947")
_JOB_KEY_DOMAIN = b"securescan-source-scanner-job-s6b-v1\0"
_CONTEXT_MEDIA_TYPE = "application/json"
_ADAPTER_VERSION = "s6b-v1"
_MAX_CLEANUP_RECEIPT_BYTES = 64 * 1024
_LOCAL_AUTHORITIES = frozenset(
    {
        SourceAuthority.SEMGREP.value,
        SourceAuthority.GITLEAKS.value,
        SourceAuthority.SYFT.value,
        SourceAuthority.CHECKOV.value,
    }
)
_SUCCESS_OUTCOMES = frozenset(
    {
        ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
        ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS,
        ExecutionOutcome.SUCCEEDED_WITH_WARNINGS,
        ExecutionOutcome.PARTIAL_ANALYSIS,
    }
)


class SourceScannerExecutionError(RuntimeError):
    def __init__(self, message: str = "Source scanner execution operation failed") -> None:
        super().__init__(message)


class SourceScannerExecutionConflictError(SourceScannerExecutionError):
    def __init__(self) -> None:
        super().__init__("Source scanner execution identity conflicts with durable state")


class SourceScannerAttemptBlockedError(SourceScannerExecutionError):
    def __init__(self) -> None:
        super().__init__("A prior Source scanner attempt is not proven clean")


class SourceScannerResultRejectedError(SourceScannerExecutionError):
    def __init__(self) -> None:
        super().__init__("Source scanner result acceptance was rejected")


@dataclass(frozen=True, slots=True)
class SourceScannerJobRecord:
    run_id: str
    node_id: str
    job_id: str
    authority: str
    context_digest: str
    projection_id: str
    projection_digest: str
    created: bool


@dataclass(frozen=True, slots=True)
class SourceScannerAttemptRecord:
    run_id: str
    node_id: str
    job_id: str
    attempt_number: int
    attempt_token: str = field(repr=False)
    containment_state: OrchestrationContainmentState


@dataclass(frozen=True, slots=True)
class AcceptedSourceNativeResult:
    run_id: str
    node_id: str
    job_id: str
    attempt_number: int
    artifact_sha256: str
    artifact_size_bytes: int
    storage_path: str
    created: bool


def source_scanner_job_id(node_id: str) -> str:
    if not isinstance(node_id, str) or len(node_id) != 64:
        raise SourceScannerExecutionIntegrityError
    try:
        int(node_id, 16)
    except ValueError as exc:
        raise SourceScannerExecutionIntegrityError from exc
    return str(uuid5(_JOB_NAMESPACE, node_id))


def _job_key(node_id: str) -> str:
    digest = hashlib.sha256()
    digest.update(_JOB_KEY_DOMAIN)
    digest.update(node_id.encode("ascii"))
    return digest.hexdigest()


def _selected_manifest(context: SourceExecutionContext) -> RepositoryManifest:
    entries = tuple(replace(item.entry) for item in context.selected_files)
    return RepositoryManifest(
        entries=entries,
        file_count=len(entries),
        total_bytes=sum(item.size_bytes for item in entries),
        content_digest=repository_content_digest(entries),
    )


def _record_from_rows(
    mapping: SourceOrchestrationScannerJobRow, *, created: bool
) -> SourceScannerJobRecord:
    return SourceScannerJobRecord(
        run_id=mapping.run_id,
        node_id=mapping.node_id,
        job_id=mapping.job_id,
        authority=mapping.authority,
        context_digest=mapping.context_digest,
        projection_id=mapping.projection_id,
        projection_digest=mapping.projection_digest,
        created=created,
    )


class SourceScannerJobService:
    """Create one trusted local scanner Job from the frozen S6A snapshot."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        orchestration_service: SourceOrchestrationService,
        projection_manager: SourceProjectionManager,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._session_factory = session_factory
        self._artifacts = artifact_store
        self._orchestrations = orchestration_service
        self._projections = projection_manager
        self._clock = clock

    def create_job(
        self,
        *,
        run_id: str,
        node_id: str,
        workspace: PreparedRepositoryWorkspace,
        priority: int = 100,
        max_attempts: int = 3,
    ) -> SourceScannerJobRecord:
        record = self._orchestrations.load(run_id)
        if record.lifecycle_state is not OrchestrationLifecycleState.ACTIVE:
            raise SourceScannerExecutionConflictError
        try:
            node = next(item for item in record.snapshot.nodes if item.node_id == node_id)
        except StopIteration:
            raise SourceScannerExecutionConflictError from None
        if (
            node.authority.value not in _LOCAL_AUTHORITIES
            or node.initial_state is not OrchestrationNodeLifecycleState.READY
            or type(priority) is not int
            or priority < 0
            or type(max_attempts) is not int
            or max_attempts < 1
        ):
            raise SourceScannerExecutionConflictError
        authority = record.snapshot.roster.for_capability(node.capability)
        if (
            authority.authority is not node.authority
            or authority.analyzer_id != node.analyzer_id
            or authority.contract_digest != node.contract_digest
        ):
            raise SourceScannerExecutionConflictError

        job_id = source_scanner_job_id(node.node_id)
        files = {item.relative_path: item for item in record.snapshot.profile.files}
        try:
            selected = tuple(
                SourceExecutionSelectedFile(
                    entry=replace(files[path].entry),
                    component_id=files[path].component_id,
                )
                for path in node.selected_paths
            )
            context = SourceExecutionContext(
                source_run_id=run_id,
                job_id=job_id,
                repository_digest=record.snapshot.profile.repository_digest,
                profile_digest=record.snapshot.profile.profile_digest(),
                plan_digest=record.snapshot.plan.plan_digest(),
                source_analyzer_id=node.analyzer_id,
                capability=node.capability,
                component_id=node.component_id,
                selected_files=selected,
                binding_digest=node.contract_digest,
                core_adapter_id=node.authority.value,
            )
        except (KeyError, ValueError, SourceOrchestrationIntegrityError):
            raise SourceScannerExecutionConflictError from None
        if tuple(item.relative_path for item in context.selected_files) != node.selected_paths:
            raise SourceScannerExecutionConflictError

        expected_projection_digest = _selected_manifest(context).content_digest
        projection = self._build_or_reopen_projection(
            workspace=workspace,
            context=context,
            suffix=node.node_id[:32],
            expected_projection_digest=expected_projection_digest,
        )
        context_payload = context.canonical_json()
        context_artifact = self._artifacts.put(
            context_payload,
            kind=ArtifactKind.SOURCE_EXECUTION_CONTEXT,
            media_type=_CONTEXT_MEDIA_TYPE,
            sanitized=False,
        )
        if (
            self._artifacts.read_by_sha256(
                context_artifact.sha256,
                expected_size_bytes=context_artifact.size_bytes,
            )
            != context_payload
        ):
            raise SourceScannerExecutionConflictError
        envelope = SourceExecutionEnvelope(
            artifact_sha256=context_artifact.sha256,
            artifact_size_bytes=context_artifact.size_bytes,
            context_digest=context.context_digest(),
            projection_reference=SourceProjectionExecutionReference(
                projection_id=projection.projection_id,
                context_digest=projection.context_digest,
                projection_digest=projection.projection_digest,
            ),
        )
        now = self._clock().astimezone(UTC)
        try:
            with self._session_factory.begin() as session:
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == run_id)
                    .with_for_update()
                )
                durable_node = session.scalar(
                    select(SourceOrchestrationNodeRow)
                    .where(SourceOrchestrationNodeRow.node_id == node_id)
                    .with_for_update()
                )
                if parent is None or durable_node is None:
                    raise SourceScannerExecutionConflictError
                existing = session.scalar(
                    select(SourceOrchestrationScannerJobRow).where(
                        SourceOrchestrationScannerJobRow.node_id == node_id
                    )
                )
                if existing is not None:
                    job = session.get(JobRow, existing.job_id)
                    if not self._matches_existing(
                        existing, job, context, projection, priority, max_attempts
                    ):
                        raise SourceScannerExecutionConflictError
                    return _record_from_rows(existing, created=False)
                if (
                    parent.lifecycle_state != OrchestrationLifecycleState.ACTIVE.value
                    or parent.cancel_requested
                    or durable_node.run_id != run_id
                    or durable_node.lifecycle_state != OrchestrationNodeLifecycleState.READY.value
                    or durable_node.authority != node.authority.value
                    or durable_node.capability != node.capability.value
                    or durable_node.analyzer_id != node.analyzer_id
                    or durable_node.contract_digest != node.contract_digest
                    or durable_node.selected_paths_json != list(node.selected_paths)
                ):
                    raise SourceScannerExecutionConflictError
                job = JobRow(
                    id=job_id,
                    run_id=run_id,
                    adapter_id=node.authority.value,
                    status=JobStatus.QUEUED.value,
                    priority=priority,
                    attempt_count=0,
                    max_attempts=max_attempts,
                    available_at=now,
                    cancel_requested=False,
                    idempotency_key=_job_key(node.node_id),
                    payload_json=envelope.payload_json(),
                    created_at=now,
                    updated_at=now,
                )
                mapping = SourceOrchestrationScannerJobRow(
                    job_id=job_id,
                    run_id=run_id,
                    node_id=node_id,
                    authority=node.authority.value,
                    capability=node.capability.value,
                    analyzer_id=node.analyzer_id,
                    contract_digest=node.contract_digest,
                    context_digest=context.context_digest(),
                    context_artifact_sha256=context_artifact.sha256,
                    context_artifact_size_bytes=context_artifact.size_bytes,
                    context_artifact_storage_path=context_artifact.storage_path,
                    projection_id=projection.projection_id,
                    projection_digest=projection.projection_digest,
                    selected_attempt_number=None,
                    created_at=now,
                )
                session.add_all((job, mapping))
                durable_node.lifecycle_state = OrchestrationNodeLifecycleState.QUEUED.value
                durable_node.state_version += 1
                session.flush()
                return _record_from_rows(mapping, created=True)
        except SourceScannerExecutionError:
            raise
        except (IntegrityError, SQLAlchemyError):
            try:
                with self._session_factory() as session:
                    existing = session.scalar(
                        select(SourceOrchestrationScannerJobRow).where(
                            SourceOrchestrationScannerJobRow.node_id == node_id
                        )
                    )
                    job = None if existing is None else session.get(JobRow, existing.job_id)
                    if existing is None or not self._matches_existing(
                        existing, job, context, projection, priority, max_attempts
                    ):
                        raise SourceScannerExecutionConflictError
                    return _record_from_rows(existing, created=False)
            except SourceScannerExecutionError:
                raise
            except SQLAlchemyError:
                raise SourceScannerExecutionError from None

    def _build_or_reopen_projection(
        self,
        *,
        workspace: PreparedRepositoryWorkspace,
        context: SourceExecutionContext,
        suffix: str,
        expected_projection_digest: str,
    ) -> PreparedSourceProjection:
        projection_id = f"securescan-source-projection-{suffix}"
        try:
            return self._projections.build_projection(
                workspace,
                context,
                projection_suffix=suffix,
            )
        except SourceProjectionError:
            deadline = time.monotonic() + 2.0
            while True:
                try:
                    return self._projections.reopen_projection(
                        projection_id,
                        expected_context_digest=context.context_digest(),
                        expected_projection_digest=expected_projection_digest,
                    )
                except SourceProjectionError:
                    if time.monotonic() >= deadline:
                        raise SourceScannerExecutionConflictError from None
                    time.sleep(0.01)

    @staticmethod
    def _matches_existing(
        mapping: SourceOrchestrationScannerJobRow,
        job: JobRow | None,
        context: SourceExecutionContext,
        projection: PreparedSourceProjection,
        priority: int,
        max_attempts: int,
    ) -> bool:
        return bool(
            job is not None
            and job.id == context.job_id
            and job.run_id == context.source_run_id
            and job.adapter_id == context.core_adapter_id
            and job.idempotency_key == _job_key(mapping.node_id)
            and job.priority == priority
            and job.max_attempts == max_attempts
            and mapping.run_id == context.source_run_id
            and mapping.context_digest == context.context_digest()
            and mapping.contract_digest == context.binding_digest
            and mapping.projection_id == projection.projection_id
            and mapping.projection_digest == projection.projection_digest
        )


class SourceScannerAttemptService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        projection_manager: SourceProjectionManager,
        *,
        clock: Callable[[], datetime] = utc_now,
        token_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._session_factory = session_factory
        self._artifacts = artifact_store
        self._projections = projection_manager
        self._clock = clock
        self._token_factory = token_factory

    def register_attempt(
        self, *, job_id: str, worker_id: str, lease_token: str
    ) -> SourceScannerAttemptRecord:
        now = self._clock().astimezone(UTC)
        try:
            with self._session_factory.begin() as session:
                mapping, node, job = self._locked_job_state(session, job_id)
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == mapping.run_id)
                    .with_for_update()
                )
                prior = tuple(
                    session.scalars(
                        select(SourceOrchestrationAttemptRow)
                        .where(SourceOrchestrationAttemptRow.job_id == job_id)
                        .order_by(SourceOrchestrationAttemptRow.attempt_number)
                        .with_for_update()
                    )
                )
                if (
                    parent is None
                    or parent.cancel_requested
                    or parent.lifecycle_state != OrchestrationLifecycleState.ACTIVE.value
                    or job.status != JobStatus.RUNNING.value
                    or job.leased_by != worker_id
                    or job.lease_token != lease_token
                    or job.attempt_count < 1
                    or mapping.selected_attempt_number is not None
                    or any(
                        item.containment_state != OrchestrationContainmentState.CLEAN.value
                        for item in prior
                    )
                ):
                    raise SourceScannerAttemptBlockedError
                existing = next(
                    (item for item in prior if item.attempt_number == job.attempt_count), None
                )
                if existing is not None:
                    if existing.worker_id != worker_id or existing.lease_token != lease_token:
                        raise SourceScannerExecutionConflictError
                    return self._attempt_record(existing)
                if prior and prior[-1].attempt_number >= job.attempt_count:
                    raise SourceScannerExecutionConflictError
                row = SourceOrchestrationAttemptRow(
                    job_id=job.id,
                    attempt_number=job.attempt_count,
                    run_id=mapping.run_id,
                    node_id=mapping.node_id,
                    attempt_token=str(self._token_factory()),
                    worker_id=worker_id,
                    lease_token=lease_token,
                    containment_state=OrchestrationContainmentState.ACTIVE.value,
                    acceptance_state="PENDING",
                    started_at=now,
                )
                session.add(row)
                node.lifecycle_state = OrchestrationNodeLifecycleState.RUNNING.value
                node.containment_state = OrchestrationContainmentState.ACTIVE.value
                node.state_version += 1
                session.flush()
                return self._attempt_record(row)
        except SourceScannerExecutionError:
            raise
        except (IntegrityError, SQLAlchemyError):
            raise SourceScannerExecutionError from None

    def register_supervisor(
        self,
        *,
        job_id: str,
        attempt_number: int,
        attempt_token: str,
        supervisor_identity: str,
        supervisor_pid: int,
        supervisor_start_ticks: int,
        scanner_pid: int,
        scanner_pgid: int,
        scanner_start_ticks: int,
    ) -> SourceScannerAttemptRecord:
        try:
            with self._session_factory.begin() as session:
                row = self._locked_attempt(session, job_id, attempt_number)
                supplied = (
                    supervisor_identity,
                    supervisor_pid,
                    supervisor_start_ticks,
                    scanner_pid,
                    scanner_pgid,
                    scanner_start_ticks,
                )
                if (
                    row.attempt_token != attempt_token
                    or row.containment_state != OrchestrationContainmentState.ACTIVE.value
                    or any(type(value) is not int or value < 1 for value in supplied[1:])
                    or not isinstance(supervisor_identity, str)
                    or len(supervisor_identity) != 64
                ):
                    raise SourceScannerExecutionConflictError
                existing = (
                    row.supervisor_identity,
                    row.supervisor_pid,
                    row.supervisor_start_ticks,
                    row.scanner_pid,
                    row.scanner_pgid,
                    row.scanner_start_ticks,
                )
                if any(value is not None for value in existing) and existing != supplied:
                    raise SourceScannerExecutionConflictError
                (
                    row.supervisor_identity,
                    row.supervisor_pid,
                    row.supervisor_start_ticks,
                    row.scanner_pid,
                    row.scanner_pgid,
                    row.scanner_start_ticks,
                ) = supplied
                return self._attempt_record(row)
        except SourceScannerExecutionError:
            raise
        except SQLAlchemyError:
            raise SourceScannerExecutionError from None

    def record_cleanup(self, receipt: SourceAttemptCleanupReceipt) -> SourceScannerAttemptRecord:
        if not isinstance(receipt, SourceAttemptCleanupReceipt):
            raise SourceScannerExecutionConflictError
        try:
            with self._session_factory.begin() as session:
                row = self._locked_attempt(session, receipt.job_id, receipt.attempt_number)
                mapping = session.get(SourceOrchestrationScannerJobRow, row.job_id)
                node = session.scalar(
                    select(SourceOrchestrationNodeRow)
                    .where(SourceOrchestrationNodeRow.node_id == row.node_id)
                    .with_for_update()
                )
                receipt_identity = (
                    receipt.supervisor_identity,
                    receipt.supervisor_pid,
                    receipt.supervisor_start_ticks,
                    receipt.scanner_pid,
                    receipt.scanner_pgid,
                    receipt.scanner_start_ticks,
                )
                row_identity = (
                    row.supervisor_identity,
                    row.supervisor_pid,
                    row.supervisor_start_ticks,
                    row.scanner_pid,
                    row.scanner_pgid,
                    row.scanner_start_ticks,
                )
                if (
                    mapping is None
                    or node is None
                    or mapping.authority == SourceAuthority.SEMGREP.value
                    or receipt.attempt_token != row.attempt_token
                    or row_identity != receipt_identity
                    or (
                        receipt.cleanup_outcome.value == OrchestrationContainmentState.CLEAN.value
                        and not _scanner_process_tree_absent(receipt)
                    )
                ):
                    raise SourceScannerExecutionConflictError
                digest = receipt.sha256()
                if row.cleanup_receipt_sha256 is not None:
                    if (
                        row.cleanup_receipt_sha256 != digest
                        or row.cleanup_receipt_json != receipt.canonical_data()
                    ):
                        raise SourceScannerExecutionConflictError
                    return self._attempt_record(row)
                containment = OrchestrationContainmentState(receipt.cleanup_outcome.value)
                row.cleanup_receipt_sha256 = digest
                row.cleanup_receipt_json = receipt.canonical_data()
                row.containment_state = containment.value
                node.containment_state = containment.value
                if containment is OrchestrationContainmentState.RECONCILIATION_REQUIRED:
                    node.lifecycle_state = (
                        OrchestrationNodeLifecycleState.RECONCILIATION_REQUIRED.value
                    )
                node.state_version += 1
                return self._attempt_record(row)
        except SourceScannerExecutionError:
            raise
        except SQLAlchemyError:
            raise SourceScannerExecutionError from None

    def record_sandbox_cleanup(
        self, receipt: SourceSandboxCleanupReceipt
    ) -> SourceScannerAttemptRecord:
        """Record normal Semgrep Docker completion without inventing process evidence."""
        if not isinstance(receipt, SourceSandboxCleanupReceipt):
            raise SourceScannerExecutionConflictError
        try:
            with self._session_factory.begin() as session:
                row = self._locked_attempt(
                    session, receipt.job_id, receipt.attempt_number
                )
                mapping = session.get(SourceOrchestrationScannerJobRow, row.job_id)
                node = session.scalar(
                    select(SourceOrchestrationNodeRow)
                    .where(SourceOrchestrationNodeRow.node_id == row.node_id)
                    .with_for_update()
                )
                if (
                    mapping is None
                    or node is None
                    or mapping.authority != SourceAuthority.SEMGREP.value
                    or receipt.attempt_token != row.attempt_token
                    or receipt.sandbox_identity
                    != source_sandbox_execution_identity(
                        row.job_id, row.attempt_number, row.attempt_token
                    )
                    or any(
                        value is not None
                        for value in (
                            row.supervisor_identity,
                            row.supervisor_pid,
                            row.supervisor_start_ticks,
                            row.scanner_pid,
                            row.scanner_pgid,
                            row.scanner_start_ticks,
                        )
                    )
                ):
                    raise SourceScannerExecutionConflictError
                digest = receipt.sha256()
                if row.cleanup_receipt_sha256 is not None:
                    if (
                        row.containment_state
                        != OrchestrationContainmentState.CLEAN.value
                        or row.cleanup_receipt_sha256 != digest
                        or row.cleanup_receipt_json != receipt.canonical_data()
                    ):
                        raise SourceScannerExecutionConflictError
                    return self._attempt_record(row)
                if (
                    row.cleanup_receipt_json is not None
                    or row.containment_state
                    not in {
                        OrchestrationContainmentState.ACTIVE.value,
                        OrchestrationContainmentState.RECONCILIATION_REQUIRED.value,
                    }
                ):
                    raise SourceScannerExecutionConflictError
                row.cleanup_receipt_sha256 = digest
                row.cleanup_receipt_json = receipt.canonical_data()
                row.containment_state = OrchestrationContainmentState.CLEAN.value
                node.containment_state = OrchestrationContainmentState.CLEAN.value
                node.state_version += 1
                return self._attempt_record(row)
        except SourceScannerExecutionError:
            raise
        except SQLAlchemyError:
            raise SourceScannerExecutionError from None

    def recover_cleanup_receipt(
        self,
        *,
        job_id: str,
        attempt_number: int,
        receipt_directory: Path,
    ) -> SourceScannerAttemptRecord:
        """Recover only from the exact durable receipt bound to this attempt."""
        try:
            with self._session_factory() as session:
                attempt = session.get(
                    SourceOrchestrationAttemptRow, (job_id, attempt_number)
                )
                if attempt is None:
                    raise SourceScannerExecutionConflictError
                attempt_token = attempt.attempt_token
            filename = f"{job_id}-{attempt_number}-{attempt_token}.json"
            payload = _read_stable_cleanup_receipt(receipt_directory, filename)
            receipt = SourceAttemptCleanupReceipt.from_json(payload)
            if (
                receipt.scanner_pid is None
                or receipt.scanner_pgid is None
                or receipt.scanner_start_ticks is None
            ):
                raise SourceScannerExecutionIntegrityError
            self.register_supervisor(
                job_id=job_id,
                attempt_number=attempt_number,
                attempt_token=attempt_token,
                supervisor_identity=receipt.supervisor_identity,
                supervisor_pid=receipt.supervisor_pid,
                supervisor_start_ticks=receipt.supervisor_start_ticks,
                scanner_pid=receipt.scanner_pid,
                scanner_pgid=receipt.scanner_pgid,
                scanner_start_ticks=receipt.scanner_start_ticks,
            )
            return self.record_cleanup(receipt)
        except Exception:
            return self._mark_reconciliation_required(job_id, attempt_number)

    def _mark_reconciliation_required(
        self, job_id: str, attempt_number: int
    ) -> SourceScannerAttemptRecord:
        try:
            with self._session_factory.begin() as session:
                attempt = self._locked_attempt(session, job_id, attempt_number)
                node = session.scalar(
                    select(SourceOrchestrationNodeRow)
                    .where(SourceOrchestrationNodeRow.node_id == attempt.node_id)
                    .with_for_update()
                )
                if node is None or attempt.acceptance_state == "ACCEPTED":
                    raise SourceScannerExecutionConflictError
                attempt.containment_state = (
                    OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
                )
                node.containment_state = (
                    OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
                )
                node.lifecycle_state = (
                    OrchestrationNodeLifecycleState.RECONCILIATION_REQUIRED.value
                )
                node.state_version += 1
                return self._attempt_record(attempt)
        except SourceScannerExecutionError:
            raise
        except SQLAlchemyError:
            raise SourceScannerExecutionError from None

    def record_failure(
        self,
        *,
        job_id: str,
        attempt_number: int,
        attempt_token: str,
        lease_token: str,
        failure_code: SourceScannerFailureCode,
        failure_category: JobFailureCategory,
        execution_outcome: ExecutionOutcome,
        return_code: int | None,
        duration_ms: int,
        retryable: bool,
    ) -> SourceScannerAttemptRecord:
        if (
            not isinstance(failure_code, SourceScannerFailureCode)
            or not isinstance(failure_category, JobFailureCategory)
            or not isinstance(execution_outcome, ExecutionOutcome)
            or execution_outcome in _SUCCESS_OUTCOMES
            or (return_code is not None and type(return_code) is not int)
            or type(duration_ms) is not int
            or duration_ms < 0
            or type(retryable) is not bool
        ):
            raise SourceScannerExecutionConflictError
        now = self._clock().astimezone(UTC)
        try:
            with self._session_factory.begin() as session:
                mapping, node, job = self._locked_job_state(session, job_id)
                attempt = self._locked_attempt(session, job_id, attempt_number)
                if (
                    attempt.attempt_token != attempt_token
                    or attempt.lease_token != lease_token
                    or job.lease_token != lease_token
                    or attempt.acceptance_state != "PENDING"
                    or attempt.tool_execution_id is not None
                    or attempt.containment_state
                    not in {
                        OrchestrationContainmentState.CLEAN.value,
                        OrchestrationContainmentState.RECONCILIATION_REQUIRED.value,
                    }
                    or (
                        attempt.containment_state
                        == OrchestrationContainmentState.CLEAN.value
                        and not _valid_durable_clean_receipt(attempt, mapping)
                    )
                ):
                    raise SourceScannerExecutionConflictError
                containment_failed = (
                    attempt.containment_state
                    == OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
                )
                if (
                    containment_failed
                    and failure_code is not SourceScannerFailureCode.CONTAINMENT_FAILURE
                ):
                    failure_code = SourceScannerFailureCode.CONTAINMENT_FAILURE
                    failure_category = JobFailureCategory.WORKER_CRASH
                    execution_outcome = ExecutionOutcome.INTERNAL_ERROR
                    retryable = True
                tool = ToolExecutionRow(
                    run_id=mapping.run_id,
                    job_id=job.id,
                    attempt_number=attempt.attempt_number,
                    adapter_id=mapping.authority,
                    tool_version=self._scanner_version(session, mapping),
                    adapter_version=_ADAPTER_VERSION,
                    outcome=execution_outcome.value,
                    exit_code=return_code,
                    duration_ms=duration_ms,
                    warning_json=[],
                    error=None,
                    failure_category=failure_category.value,
                    retryable=retryable,
                )
                session.add(tool)
                session.flush()
                attempt.tool_execution_id = tool.id
                attempt.acceptance_state = "REJECTED"
                attempt.failure_code = failure_code.value
                attempt.finished_at = now
                job.last_error = failure_code.value
                job.updated_at = now
                if containment_failed:
                    node.lifecycle_state = (
                        OrchestrationNodeLifecycleState.RECONCILIATION_REQUIRED.value
                    )
                elif retryable and job.attempt_count < job.max_attempts:
                    job.status = JobStatus.RETRY_PENDING.value
                    job.leased_by = None
                    job.lease_token = None
                    job.lease_expires_at = None
                    node.lifecycle_state = OrchestrationNodeLifecycleState.RETRY_PENDING.value
                    node.containment_state = OrchestrationContainmentState.CLEAN.value
                else:
                    job.status = JobStatus.FAILED.value
                    job.finished_at = now
                    job.leased_by = None
                    job.lease_token = None
                    job.lease_expires_at = None
                    node.lifecycle_state = OrchestrationNodeLifecycleState.TERMINAL.value
                    node.terminal_disposition = OrchestrationNodeDisposition.FAILED.value
                    node.containment_state = OrchestrationContainmentState.CLEAN.value
                node.state_version += 1
                return self._attempt_record(attempt)
        except SourceScannerExecutionError:
            raise
        except (IntegrityError, SQLAlchemyError):
            raise SourceScannerExecutionError from None

    def accept_result(
        self,
        result: SafeSourceNativeResult,
        *,
        lease_token: str,
        execution_outcome: ExecutionOutcome,
        return_code: int,
        duration_ms: int,
    ) -> AcceptedSourceNativeResult:
        if (
            not isinstance(result, SafeSourceNativeResult)
            or execution_outcome not in _SUCCESS_OUTCOMES
            or type(return_code) is not int
            or type(duration_ms) is not int
            or duration_ms < 0
        ):
            raise SourceScannerResultRejectedError
        payload = result.canonical_json()
        if SafeSourceNativeResult.from_json(payload) != result:
            raise SourceScannerResultRejectedError
        context = self._load_context_for_result(result)
        try:
            projection = self._projections.reopen_projection(
                result.projection_id,
                expected_context_digest=result.context_digest,
                expected_projection_digest=result.projection_digest,
            )
        except SourceProjectionError:
            raise SourceScannerResultRejectedError from None
        if projection.manifest != _selected_manifest(context):
            raise SourceScannerResultRejectedError
        artifact = self._artifacts.put(
            payload,
            kind=ArtifactKind.SANITIZED_NATIVE_REPORT,
            media_type=SAFE_NATIVE_RESULT_MEDIA_TYPE,
            sanitized=True,
        )
        try:
            reloaded = self._artifacts.read_by_sha256(
                artifact.sha256, expected_size_bytes=artifact.size_bytes
            )
            if reloaded != payload or SafeSourceNativeResult.from_json(reloaded) != result:
                raise SourceScannerResultRejectedError
        except (OSError, ValueError, SourceScannerExecutionIntegrityError):
            raise SourceScannerResultRejectedError from None
        now = self._clock().astimezone(UTC)
        try:
            with self._session_factory.begin() as session:
                unlocked_mapping = session.get(SourceOrchestrationScannerJobRow, result.job_id)
                if unlocked_mapping is None:
                    raise SourceScannerResultRejectedError
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == unlocked_mapping.run_id)
                    .with_for_update()
                )
                mapping = session.scalar(
                    select(SourceOrchestrationScannerJobRow)
                    .where(SourceOrchestrationScannerJobRow.job_id == result.job_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                if mapping is None:
                    raise SourceScannerResultRejectedError
                node = session.scalar(
                    select(SourceOrchestrationNodeRow)
                    .where(SourceOrchestrationNodeRow.node_id == mapping.node_id)
                    .with_for_update()
                )
                job = session.scalar(
                    select(JobRow).where(JobRow.id == mapping.job_id).with_for_update()
                )
                attempt = session.scalar(
                    select(SourceOrchestrationAttemptRow)
                    .where(
                        SourceOrchestrationAttemptRow.job_id == result.job_id,
                        SourceOrchestrationAttemptRow.attempt_number == result.attempt_number,
                    )
                    .with_for_update()
                )
                if parent is None or node is None or job is None or attempt is None:
                    raise SourceScannerResultRejectedError
                if attempt.acceptance_state == "ACCEPTED":
                    if (
                        attempt.native_result_sha256 != artifact.sha256
                        or attempt.native_result_size_bytes != artifact.size_bytes
                        or mapping.selected_attempt_number != result.attempt_number
                    ):
                        raise SourceScannerResultRejectedError
                    return AcceptedSourceNativeResult(
                        mapping.run_id,
                        mapping.node_id,
                        mapping.job_id,
                        result.attempt_number,
                        artifact.sha256,
                        artifact.size_bytes,
                        artifact.storage_path,
                        False,
                    )
                expected = self._result_matches_state(
                    result,
                    context,
                    mapping,
                    node,
                    job,
                    attempt,
                    lease_token,
                    now,
                )
                if (
                    not expected
                    or parent.cancel_requested
                    or parent.lifecycle_state
                    in {
                        OrchestrationLifecycleState.CANCELLATION_REQUESTED.value,
                        OrchestrationLifecycleState.TERMINAL.value,
                    }
                    or mapping.selected_attempt_number is not None
                    or not _valid_durable_clean_receipt(attempt, mapping)
                ):
                    raise SourceScannerResultRejectedError
                tool = ToolExecutionRow(
                    run_id=mapping.run_id,
                    job_id=job.id,
                    attempt_number=attempt.attempt_number,
                    adapter_id=mapping.authority,
                    tool_version=result.scanner_version,
                    adapter_version=_ADAPTER_VERSION,
                    outcome=execution_outcome.value,
                    exit_code=return_code,
                    duration_ms=duration_ms,
                    warning_json=[],
                    error=None,
                    failure_category=None,
                    retryable=None,
                )
                session.add(tool)
                session.flush()
                attempt.tool_execution_id = tool.id
                attempt.native_result_sha256 = artifact.sha256
                attempt.native_result_size_bytes = artifact.size_bytes
                attempt.native_result_media_type = SAFE_NATIVE_RESULT_MEDIA_TYPE
                attempt.native_result_schema_version = SAFE_NATIVE_RESULT_SCHEMA_VERSION
                attempt.native_result_storage_path = artifact.storage_path
                attempt.projection_revalidated = True
                attempt.acceptance_state = "ACCEPTED"
                attempt.finished_at = now
                attempt.accepted_at = now
                mapping.selected_attempt_number = attempt.attempt_number
                partial = execution_outcome in {
                    ExecutionOutcome.SUCCEEDED_WITH_WARNINGS,
                    ExecutionOutcome.PARTIAL_ANALYSIS,
                }
                job.status = (JobStatus.PARTIAL if partial else JobStatus.SUCCEEDED).value
                job.finished_at = now
                job.updated_at = now
                job.leased_by = None
                job.lease_token = None
                job.lease_expires_at = None
                node.lifecycle_state = OrchestrationNodeLifecycleState.TERMINAL.value
                node.terminal_disposition = (
                    OrchestrationNodeDisposition.PARTIAL
                    if partial
                    else OrchestrationNodeDisposition.COMPLETE
                ).value
                node.containment_state = OrchestrationContainmentState.CLEAN.value
                node.state_version += 1
                run = session.get(AnalysisRunRow, mapping.run_id)
                if run is None or run.report_json is not None:
                    raise SourceScannerResultRejectedError
                session.flush()
                return AcceptedSourceNativeResult(
                    mapping.run_id,
                    mapping.node_id,
                    mapping.job_id,
                    attempt.attempt_number,
                    artifact.sha256,
                    artifact.size_bytes,
                    artifact.storage_path,
                    True,
                )
        except SourceScannerExecutionError:
            raise
        except (IntegrityError, SQLAlchemyError):
            raise SourceScannerResultRejectedError from None

    def load_accepted_result(self, *, run_id: str, node_id: str) -> SafeSourceNativeResult:
        try:
            with self._session_factory() as session:
                mapping = session.scalar(
                    select(SourceOrchestrationScannerJobRow).where(
                        SourceOrchestrationScannerJobRow.run_id == run_id,
                        SourceOrchestrationScannerJobRow.node_id == node_id,
                    )
                )
                if mapping is None or mapping.selected_attempt_number is None:
                    raise SourceScannerResultRejectedError
                attempt = session.get(
                    SourceOrchestrationAttemptRow,
                    (mapping.job_id, mapping.selected_attempt_number),
                )
                if (
                    attempt is None
                    or attempt.acceptance_state != "ACCEPTED"
                    or attempt.native_result_sha256 is None
                    or attempt.native_result_size_bytes is None
                    or attempt.native_result_media_type != SAFE_NATIVE_RESULT_MEDIA_TYPE
                    or attempt.native_result_schema_version
                    != SAFE_NATIVE_RESULT_SCHEMA_VERSION
                ):
                    raise SourceScannerResultRejectedError
                payload = self._artifacts.read_by_sha256(
                    attempt.native_result_sha256,
                    expected_size_bytes=attempt.native_result_size_bytes,
                )
                result = SafeSourceNativeResult.from_json(payload)
                if (
                    result.node_id != node_id
                    or result.job_id != mapping.job_id
                    or result.attempt_number != mapping.selected_attempt_number
                    or result.authority != mapping.authority
                    or result.analyzer_id != mapping.analyzer_id
                    or result.binding_digest != mapping.contract_digest
                    or result.context_digest != mapping.context_digest
                    or result.projection_id != mapping.projection_id
                    or result.projection_digest != mapping.projection_digest
                    or result.sha256() != attempt.native_result_sha256
                ):
                    raise SourceScannerResultRejectedError
                return result
        except SourceScannerExecutionError:
            raise
        except (OSError, ValueError, SQLAlchemyError, SourceScannerExecutionIntegrityError):
            raise SourceScannerResultRejectedError from None

    def _load_context_for_result(self, result: SafeSourceNativeResult) -> SourceExecutionContext:
        try:
            with self._session_factory() as session:
                mapping = session.get(SourceOrchestrationScannerJobRow, result.job_id)
                if mapping is None:
                    raise SourceScannerResultRejectedError
                path = (
                    f"sha256/{mapping.context_artifact_sha256[:2]}/"
                    f"{mapping.context_artifact_sha256}"
                )
                if mapping.context_artifact_storage_path != path:
                    raise SourceScannerResultRejectedError
                payload = self._artifacts.read_by_sha256(
                    mapping.context_artifact_sha256,
                    expected_size_bytes=mapping.context_artifact_size_bytes,
                )
                context = SourceExecutionContext.from_json(payload)
                if context.context_digest() != mapping.context_digest:
                    raise SourceScannerResultRejectedError
                return context
        except SourceScannerExecutionError:
            raise
        except Exception:
            raise SourceScannerResultRejectedError from None

    @staticmethod
    def _result_matches_state(
        result: SafeSourceNativeResult,
        context: SourceExecutionContext,
        mapping: SourceOrchestrationScannerJobRow,
        node: SourceOrchestrationNodeRow,
        job: JobRow,
        attempt: SourceOrchestrationAttemptRow,
        lease_token: str,
        operation_time: datetime,
    ) -> bool:
        return bool(
            mapping.run_id == node.run_id == job.run_id == attempt.run_id
            and mapping.node_id == node.node_id == attempt.node_id == result.node_id
            and mapping.job_id == job.id == attempt.job_id == result.job_id
            and mapping.authority == result.authority == result.scanner_id == job.adapter_id
            and mapping.analyzer_id == result.analyzer_id == context.source_analyzer_id
            and mapping.contract_digest == result.binding_digest == context.binding_digest
            and mapping.context_digest == result.context_digest == context.context_digest()
            and mapping.projection_id == result.projection_id
            and mapping.projection_digest == result.projection_digest
            and context.repository_digest == result.repository_digest
            and context.profile_digest == result.profile_digest
            and context.plan_digest == result.plan_digest
            and attempt.attempt_number == result.attempt_number == job.attempt_count
            and attempt.lease_token == lease_token == job.lease_token
            and attempt.worker_id == job.leased_by
            and attempt.acceptance_state == "PENDING"
            and job.status == JobStatus.RUNNING.value
            and not job.cancel_requested
            and job.lease_expires_at is not None
            and _as_utc(job.lease_expires_at) > _as_utc(operation_time)
        )

    @staticmethod
    def _locked_job_state(
        session: Session, job_id: str
    ) -> tuple[SourceOrchestrationScannerJobRow, SourceOrchestrationNodeRow, JobRow]:
        mapping = session.scalar(
            select(SourceOrchestrationScannerJobRow)
            .where(SourceOrchestrationScannerJobRow.job_id == job_id)
            .with_for_update()
        )
        node = (
            None
            if mapping is None
            else session.scalar(
                select(SourceOrchestrationNodeRow)
                .where(SourceOrchestrationNodeRow.node_id == mapping.node_id)
                .with_for_update()
            )
        )
        job = session.scalar(select(JobRow).where(JobRow.id == job_id).with_for_update())
        if mapping is None or node is None or job is None or mapping.run_id != job.run_id:
            raise SourceScannerExecutionConflictError
        return mapping, node, job

    @staticmethod
    def _locked_attempt(
        session: Session, job_id: str, attempt_number: int
    ) -> SourceOrchestrationAttemptRow:
        row = session.scalar(
            select(SourceOrchestrationAttemptRow)
            .where(
                SourceOrchestrationAttemptRow.job_id == job_id,
                SourceOrchestrationAttemptRow.attempt_number == attempt_number,
            )
            .with_for_update()
        )
        if row is None:
            raise SourceScannerExecutionConflictError
        return row

    @staticmethod
    def _attempt_record(row: SourceOrchestrationAttemptRow) -> SourceScannerAttemptRecord:
        return SourceScannerAttemptRecord(
            run_id=row.run_id,
            node_id=row.node_id,
            job_id=row.job_id,
            attempt_number=row.attempt_number,
            attempt_token=row.attempt_token,
            containment_state=OrchestrationContainmentState(row.containment_state),
        )

    @staticmethod
    def _scanner_version(session: Session, mapping: SourceOrchestrationScannerJobRow) -> str:
        from securescan.persistence.database import SourceOrchestrationAuthorityRow

        authority = session.get(
            SourceOrchestrationAuthorityRow,
            (mapping.run_id, mapping.authority),
        )
        if authority is None or authority.capability != mapping.capability:
            raise SourceScannerExecutionConflictError
        return authority.implementation_version


class SourceScannerLeaseReconciliationService:
    """Quarantine expired local attempts; S6C alone may decide retry policy."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock

    def quarantine_expired(self, *, limit: int = 100) -> tuple[SourceScannerAttemptRecord, ...]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise SourceScannerExecutionError
        now = self._clock()
        try:
            with self._session_factory.begin() as session:
                statement = (
                    select(SourceOrchestrationAttemptRow)
                    .join(
                        JobRow,
                        JobRow.id == SourceOrchestrationAttemptRow.job_id,
                    )
                    .where(
                        SourceOrchestrationAttemptRow.containment_state
                        == OrchestrationContainmentState.ACTIVE.value,
                        JobRow.status.in_([JobStatus.LEASED.value, JobStatus.RUNNING.value]),
                        JobRow.lease_expires_at.is_not(None),
                        JobRow.lease_expires_at <= now,
                    )
                    .order_by(
                        SourceOrchestrationAttemptRow.job_id,
                        SourceOrchestrationAttemptRow.attempt_number,
                    )
                    .limit(limit)
                    .with_for_update()
                )
                if session.get_bind().dialect.name == "postgresql":
                    statement = statement.with_for_update(skip_locked=True)
                rows = tuple(session.scalars(statement))
                records: list[SourceScannerAttemptRecord] = []
                for row in rows:
                    node = session.get(SourceOrchestrationNodeRow, row.node_id)
                    if node is None:
                        raise SourceScannerExecutionError
                    row.containment_state = (
                        OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
                    )
                    node.containment_state = (
                        OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
                    )
                    node.lifecycle_state = (
                        OrchestrationNodeLifecycleState.RECONCILIATION_REQUIRED.value
                    )
                    node.state_version += 1
                    records.append(SourceScannerAttemptService._attempt_record(row))
                return tuple(records)
        except SourceScannerExecutionError:
            raise
        except SQLAlchemyError:
            raise SourceScannerExecutionError from None


def is_orchestrated_scanner_job(session: Session, job_id: str) -> bool:
    return bool(
        session.scalar(select(exists().where(SourceOrchestrationScannerJobRow.job_id == job_id)))
    )


def _valid_durable_clean_receipt(
    attempt: SourceOrchestrationAttemptRow,
    mapping: SourceOrchestrationScannerJobRow,
) -> bool:
    try:
        if (
            attempt.containment_state != OrchestrationContainmentState.CLEAN.value
            or attempt.cleanup_receipt_sha256 is None
            or not isinstance(attempt.cleanup_receipt_json, dict)
        ):
            return False
        payload = (
            json.dumps(
                attempt.cleanup_receipt_json,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        if mapping.authority == SourceAuthority.SEMGREP.value:
            receipt = SourceSandboxCleanupReceipt.from_json(payload)
            return bool(
                receipt.sha256() == attempt.cleanup_receipt_sha256
                and receipt.job_id == attempt.job_id
                and receipt.attempt_number == attempt.attempt_number
                and receipt.attempt_token == attempt.attempt_token
                and receipt.execution_id == attempt.job_id
                and receipt.sandbox_identity
                == source_sandbox_execution_identity(
                    attempt.job_id,
                    attempt.attempt_number,
                    attempt.attempt_token,
                )
                and receipt.execution_removed
                and all(
                    value is None
                    for value in (
                        attempt.supervisor_identity,
                        attempt.supervisor_pid,
                        attempt.supervisor_start_ticks,
                        attempt.scanner_pid,
                        attempt.scanner_pgid,
                        attempt.scanner_start_ticks,
                    )
                )
            )
        if mapping.authority not in {
            SourceAuthority.GITLEAKS.value,
            SourceAuthority.SYFT.value,
            SourceAuthority.CHECKOV.value,
            SourceAuthority.OSV.value,
        }:
            return False
        receipt = SourceAttemptCleanupReceipt.from_json(payload)
        return bool(
            receipt.cleanup_outcome.value == OrchestrationContainmentState.CLEAN.value
            and receipt.process_tree_empty
            and receipt.sha256() == attempt.cleanup_receipt_sha256
            and receipt.job_id == attempt.job_id
            and receipt.attempt_number == attempt.attempt_number
            and receipt.attempt_token == attempt.attempt_token
            and receipt.supervisor_identity == attempt.supervisor_identity
            and receipt.supervisor_pid == attempt.supervisor_pid
            and receipt.supervisor_start_ticks == attempt.supervisor_start_ticks
            and receipt.scanner_pid == attempt.scanner_pid
            and receipt.scanner_pgid == attempt.scanner_pgid
            and receipt.scanner_start_ticks == attempt.scanner_start_ticks
            and _scanner_process_tree_absent(receipt)
        )
    except (TypeError, ValueError, SourceScannerExecutionIntegrityError):
        return False


def _scanner_process_tree_absent(receipt: SourceAttemptCleanupReceipt) -> bool:
    if receipt.scanner_pid is None or receipt.scanner_pgid is None:
        return True
    proc = "/proc"
    if not os.path.isdir(proc):
        return False
    try:
        payload = open(  # noqa: SIM115 - short, bounded procfs metadata read
            f"{proc}/{receipt.scanner_pid}/stat", encoding="ascii"
        ).read(4096)
    except OSError:
        payload = ""
    if payload:
        try:
            fields = payload[payload.rfind(")") + 2 :].split()
            if int(fields[19]) == receipt.scanner_start_ticks:
                return False
        except (IndexError, ValueError):
            return False
    try:
        entries = os.listdir(proc)
    except OSError:
        return False
    for name in entries:
        if not name.isdigit():
            continue
        try:
            with open(f"{proc}/{name}/stat", encoding="ascii") as stream:
                process_payload = stream.read(4096)
            fields = process_payload[process_payload.rfind(")") + 2 :].split()
        except OSError:
            continue
        try:
            if int(fields[2]) == receipt.scanner_pgid:
                return False
        except (IndexError, ValueError):
            return False
    return True


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_stable_cleanup_receipt(directory: Path, filename: str) -> bytes:
    """Read an exact supervisor receipt without trusting a replaceable pathname."""
    directory_descriptor = -1
    receipt_descriptor = -1
    try:
        if (
            not isinstance(directory, Path)
            or not directory.is_absolute()
            or not isinstance(filename, str)
            or not filename
            or Path(filename).name != filename
        ):
            raise OSError
        directory_before = directory.lstat()
        if (
            not stat.S_ISDIR(directory_before.st_mode)
            or stat.S_ISLNK(directory_before.st_mode)
            or stat.S_IMODE(directory_before.st_mode) != 0o700
        ):
            raise OSError
        directory_descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        directory_opened = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(directory_opened.st_mode)
            or _stat_identity(directory_before) != _stat_identity(directory_opened)
        ):
            raise OSError
        receipt_before = os.stat(filename, dir_fd=directory_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(receipt_before.st_mode)
            or stat.S_ISLNK(receipt_before.st_mode)
            or stat.S_IMODE(receipt_before.st_mode) != 0o600
            or receipt_before.st_nlink != 1
            or receipt_before.st_size < 1
            or receipt_before.st_size > _MAX_CLEANUP_RECEIPT_BYTES
        ):
            raise OSError
        receipt_descriptor = os.open(
            filename,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        receipt_opened = os.fstat(receipt_descriptor)
        if (
            not stat.S_ISREG(receipt_opened.st_mode)
            or _stat_identity(receipt_before) != _stat_identity(receipt_opened)
        ):
            raise OSError
        payload = bytearray()
        while len(payload) <= _MAX_CLEANUP_RECEIPT_BYTES:
            chunk = os.read(
                receipt_descriptor,
                min(4096, _MAX_CLEANUP_RECEIPT_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        receipt_finished = os.fstat(receipt_descriptor)
        receipt_after = os.stat(filename, dir_fd=directory_descriptor, follow_symlinks=False)
        directory_finished = os.fstat(directory_descriptor)
        directory_after = directory.lstat()
        if (
            len(payload) > _MAX_CLEANUP_RECEIPT_BYTES
            or len(payload) != receipt_before.st_size
            or _stat_identity(receipt_before) != _stat_identity(receipt_finished)
            or _stat_identity(receipt_before) != _stat_identity(receipt_after)
            or _stat_identity(directory_before) != _stat_identity(directory_finished)
            or _stat_identity(directory_before) != _stat_identity(directory_after)
        ):
            raise OSError
        return bytes(payload)
    except (OSError, TypeError, ValueError):
        raise SourceScannerExecutionIntegrityError from None
    finally:
        if receipt_descriptor >= 0:
            with suppress(OSError):
                os.close(receipt_descriptor)
        if directory_descriptor >= 0:
            with suppress(OSError):
                os.close(directory_descriptor)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)

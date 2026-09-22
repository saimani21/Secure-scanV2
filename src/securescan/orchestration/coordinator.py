from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import JobStatus, RunStatus
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
)
from securescan.source.projection import SourceProjectionManager
from securescan.workspaces.models import PreparedRepositoryWorkspace

from .dependency_evaluation import (
    DependencyEvaluationDecision,
    SourceDependencyEvaluationError,
    SourceDependencyEvaluationService,
)
from .execution import SourceScannerJobService
from .models import (
    OrchestrationContainmentState,
    OrchestrationLifecycleState,
    OrchestrationNodeDisposition,
    OrchestrationNodeLifecycleState,
    SourceAuthority,
    TrustedSourceAuthorityRoster,
)
from .osv_execution import SourceOsvExecutionError, SourceOsvJobService
from .service import (
    SourceOrchestrationService,
    SourceOrchestrationStaleVersionError,
    SourceOrchestrationStateError,
)

SOURCE_RETRY_DELAYS_SECONDS = (5, 30)


class SourceCoordinatorError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Source orchestration coordination failed")


@dataclass(frozen=True, slots=True)
class SourceCoordinatorResult:
    run_id: str
    lifecycle_state: OrchestrationLifecycleState
    jobs_created: tuple[str, ...]
    retries_promoted: tuple[str, ...]
    state_changed: bool


class SourceOrchestrationCoordinatorService:
    """Short-lived, restartable coordinator over durable Source state."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        roster: TrustedSourceAuthorityRoster,
        projection_manager: SourceProjectionManager,
    ) -> None:
        self._sessions = session_factory
        self._orchestrations = SourceOrchestrationService(
            session_factory, artifact_store, roster
        )
        self._local_jobs = SourceScannerJobService(
            session_factory,
            artifact_store,
            self._orchestrations,
            projection_manager,
        )
        self._evaluations = SourceDependencyEvaluationService(
            session_factory, artifact_store
        )
        self._osv_jobs = SourceOsvJobService(
            session_factory, artifact_store, self._evaluations
        )

    def request_cancellation(self, run_id: str) -> SourceCoordinatorResult:
        for _ in range(16):
            record = self._orchestrations.load(run_id)
            if record.lifecycle_state in {
                OrchestrationLifecycleState.CANCELLATION_REQUESTED,
                OrchestrationLifecycleState.TERMINAL,
            }:
                break
            try:
                self._orchestrations.request_cancellation(run_id, record.state_version)
                break
            except SourceOrchestrationStaleVersionError:
                continue
            except SourceOrchestrationStateError:
                break
        else:
            raise SourceCoordinatorError
        return self.advance(run_id=run_id)

    def advance(
        self,
        *,
        run_id: str,
        workspace: PreparedRepositoryWorkspace | None = None,
    ) -> SourceCoordinatorResult:
        changed = self._enforce_parent_boundary(run_id)
        state = self._parent_state(run_id)
        if state in {
            OrchestrationLifecycleState.CANCELLATION_REQUESTED,
            OrchestrationLifecycleState.TERMINAL,
        }:
            changed = self._resolve_cancellation(run_id) or changed
            return SourceCoordinatorResult(
                run_id, self._parent_state(run_id), (), (), changed
            )

        created: list[str] = []
        if state is OrchestrationLifecycleState.ACTIVE and workspace is not None:
            for node_id in self._ready_local_node_ids(run_id):
                record = self._local_jobs.create_job(
                    run_id=run_id,
                    node_id=node_id,
                    workspace=workspace,
                )
                if record.created:
                    created.append(record.job_id)

        if self._parent_state(run_id) is OrchestrationLifecycleState.ACTIVE:
            changed = self._advance_dependency(run_id, created) or changed
        promoted = self._promote_due_retries(run_id)
        changed = bool(created or promoted) or changed
        changed = self._mark_assembly_ready(run_id) or changed
        return SourceCoordinatorResult(
            run_id,
            self._parent_state(run_id),
            tuple(sorted(created)),
            tuple(sorted(promoted)),
            changed,
        )

    def _advance_dependency(self, run_id: str, created: list[str]) -> bool:
        dependency = self._dependency_state(run_id)
        if dependency is None:
            return False
        osv_node_id, osv_state, syft_disposition, syft_reason = dependency
        changed = False
        if osv_state is OrchestrationNodeLifecycleState.WAITING_DEPENDENCY:
            if syft_disposition in {
                OrchestrationNodeDisposition.COMPLETE,
                OrchestrationNodeDisposition.PARTIAL,
            }:
                try:
                    evaluation = self._evaluations.evaluate(
                        run_id=run_id, osv_node_id=osv_node_id
                    )
                    changed = evaluation.created
                except SourceDependencyEvaluationError:
                    return self._fail_dependency_evaluation(run_id, osv_node_id)
            elif syft_disposition is not None:
                return self._block_dependency(
                    run_id, osv_node_id, syft_disposition, syft_reason
                )
            else:
                return False
        try:
            evaluation = self._evaluations.load(run_id=run_id, osv_node_id=osv_node_id)
        except SourceDependencyEvaluationError:
            return self._fail_dependency_evaluation(run_id, osv_node_id) or changed
        if evaluation.evaluation.decision is DependencyEvaluationDecision.OSV_RUN_REQUIRED:
            try:
                job = self._osv_jobs.create_job(run_id=run_id, node_id=osv_node_id)
            except SourceOsvExecutionError:
                return changed
            if job.created:
                created.append(job.job_id)
                changed = True
        return changed

    def _fail_dependency_evaluation(self, run_id: str, node_id: str) -> bool:
        """Persist a deterministic dependency-evaluation failure.

        Dependency evaluation consumes already-accepted immutable Syft evidence.
        Repeating the same failed evaluation without a state or evidence change
        cannot make progress, so the OSV node must become an explicit failed
        coverage authority rather than wait for the parent deadline.
        """
        try:
            with self._sessions.begin() as session:
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == run_id)
                    .with_for_update()
                )
                node = session.scalar(
                    select(SourceOrchestrationNodeRow)
                    .where(
                        SourceOrchestrationNodeRow.run_id == run_id,
                        SourceOrchestrationNodeRow.node_id == node_id,
                    )
                    .with_for_update()
                )
                mapping = session.scalar(
                    select(SourceOrchestrationScannerJobRow).where(
                        SourceOrchestrationScannerJobRow.run_id == run_id,
                        SourceOrchestrationScannerJobRow.node_id == node_id,
                    )
                )
                if (
                    parent is None
                    or node is None
                    or mapping is not None
                    or parent.lifecycle_state
                    != OrchestrationLifecycleState.ACTIVE.value
                    or parent.cancel_requested
                    or node.lifecycle_state
                    not in {
                        OrchestrationNodeLifecycleState.WAITING_DEPENDENCY.value,
                        OrchestrationNodeLifecycleState.READY.value,
                    }
                ):
                    return False
                _terminalize(
                    node,
                    OrchestrationNodeDisposition.FAILED,
                    "DEPENDENCY_EVALUATION_FAILED",
                )
                return True
        except SQLAlchemyError:
            raise SourceCoordinatorError from None

    def _enforce_parent_boundary(self, run_id: str) -> bool:
        try:
            with self._sessions.begin() as session:
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == run_id)
                    .with_for_update()
                )
                if parent is None:
                    raise SourceCoordinatorError
                state = OrchestrationLifecycleState(parent.lifecycle_state)
                if state in {
                    OrchestrationLifecycleState.TERMINAL,
                    OrchestrationLifecycleState.CANCELLATION_REQUESTED,
                }:
                    return False
                now = _database_now(session)
                if now < _utc(parent.deadline_at):
                    return False
                changed = parent.deadline_exceeded_at is None
                if parent.deadline_exceeded_at is None:
                    parent.deadline_exceeded_at = now
                    parent.state_version += 1
                    parent.updated_at = now
                nodes = tuple(
                    session.scalars(
                        select(SourceOrchestrationNodeRow)
                        .where(SourceOrchestrationNodeRow.run_id == run_id)
                        .order_by(SourceOrchestrationNodeRow.node_id)
                        .with_for_update()
                    )
                )
                mappings = tuple(
                    session.scalars(
                        select(SourceOrchestrationScannerJobRow)
                        .where(SourceOrchestrationScannerJobRow.run_id == run_id)
                        .with_for_update()
                    )
                )
                jobs = {
                    row.id: row
                    for row in session.scalars(
                        select(JobRow)
                        .where(JobRow.run_id == run_id)
                        .with_for_update()
                    )
                }
                mapped_nodes = {item.node_id: jobs.get(item.job_id) for item in mappings}
                for node in nodes:
                    if node.lifecycle_state == OrchestrationNodeLifecycleState.TERMINAL.value:
                        continue
                    job = mapped_nodes.get(node.node_id)
                    if job is not None and job.status in {
                        JobStatus.RUNNING.value,
                        JobStatus.LEASED.value,
                    }:
                        job.cancel_requested = True
                        job.cancel_requested_at = now
                        job.last_error = "DEADLINE_EXCEEDED"
                        job.updated_at = now
                        changed = True
                        continue
                    if job is not None:
                        job.status = JobStatus.FAILED.value
                        job.finished_at = now
                        job.last_error = "DEADLINE_EXCEEDED"
                        job.updated_at = now
                    _terminalize(
                        node,
                        OrchestrationNodeDisposition.FAILED,
                        "DEADLINE_EXCEEDED",
                    )
                    changed = True
                return changed
        except SourceCoordinatorError:
            raise
        except SQLAlchemyError:
            raise SourceCoordinatorError from None

    def _resolve_cancellation(self, run_id: str) -> bool:
        try:
            with self._sessions.begin() as session:
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == run_id)
                    .with_for_update()
                )
                if parent is None:
                    raise SourceCoordinatorError
                if parent.lifecycle_state == OrchestrationLifecycleState.TERMINAL.value:
                    return False
                if (
                    parent.lifecycle_state
                    != OrchestrationLifecycleState.CANCELLATION_REQUESTED.value
                    or not parent.cancel_requested
                ):
                    return False
                now = _database_now(session)
                nodes = tuple(
                    session.scalars(
                        select(SourceOrchestrationNodeRow)
                        .where(SourceOrchestrationNodeRow.run_id == run_id)
                        .order_by(SourceOrchestrationNodeRow.node_id)
                        .with_for_update()
                    )
                )
                mappings = tuple(
                    session.scalars(
                        select(SourceOrchestrationScannerJobRow)
                        .where(SourceOrchestrationScannerJobRow.run_id == run_id)
                        .with_for_update()
                    )
                )
                jobs = {
                    row.id: row
                    for row in session.scalars(
                        select(JobRow)
                        .where(JobRow.run_id == run_id)
                        .with_for_update()
                    )
                }
                mapped_nodes = {item.node_id: jobs.get(item.job_id) for item in mappings}
                changed = False
                active = False
                for node in nodes:
                    if node.lifecycle_state == OrchestrationNodeLifecycleState.TERMINAL.value:
                        continue
                    job = mapped_nodes.get(node.node_id)
                    if job is not None and job.status in {
                        JobStatus.RUNNING.value,
                        JobStatus.LEASED.value,
                    }:
                        job.cancel_requested = True
                        if job.cancel_requested_at is None:
                            job.cancel_requested_at = now
                        job.updated_at = now
                        active = True
                        changed = True
                        continue
                    if node.lifecycle_state == (
                        OrchestrationNodeLifecycleState.RECONCILIATION_REQUIRED.value
                    ):
                        active = True
                        continue
                    if job is not None:
                        job.status = JobStatus.CANCELLED.value
                        job.cancel_requested = True
                        job.cancel_requested_at = job.cancel_requested_at or now
                        job.finished_at = now
                        job.updated_at = now
                    _terminalize(
                        node,
                        OrchestrationNodeDisposition.CANCELLED,
                        "PARENT_CANCELLED",
                    )
                    changed = True
                if not active and all(
                    node.lifecycle_state == OrchestrationNodeLifecycleState.TERMINAL.value
                    for node in nodes
                ):
                    parent.lifecycle_state = OrchestrationLifecycleState.TERMINAL.value
                    parent.terminal_outcome = "CANCELLED"
                    parent.state_version += 1
                    parent.updated_at = now
                    run = session.get(AnalysisRunRow, run_id)
                    if run is None or run.report_json is not None:
                        raise SourceCoordinatorError
                    run.status = RunStatus.CANCELLED.value
                    run.finished_at = now
                    changed = True
                return changed
        except SourceCoordinatorError:
            raise
        except SQLAlchemyError:
            raise SourceCoordinatorError from None

    def _promote_due_retries(self, run_id: str) -> list[str]:
        try:
            with self._sessions.begin() as session:
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == run_id)
                    .with_for_update()
                )
                if parent is None:
                    raise SourceCoordinatorError
                now = _database_now(session)
                if (
                    parent.lifecycle_state != OrchestrationLifecycleState.ACTIVE.value
                    or parent.cancel_requested
                    or now >= _utc(parent.deadline_at)
                ):
                    return []
                mappings = tuple(
                    session.scalars(
                        select(SourceOrchestrationScannerJobRow)
                        .where(SourceOrchestrationScannerJobRow.run_id == run_id)
                        .order_by(SourceOrchestrationScannerJobRow.job_id)
                        .with_for_update()
                    )
                )
                promoted: list[str] = []
                for mapping in mappings:
                    job = session.scalar(
                        select(JobRow)
                        .where(JobRow.id == mapping.job_id)
                        .with_for_update()
                    )
                    node = session.scalar(
                        select(SourceOrchestrationNodeRow)
                        .where(SourceOrchestrationNodeRow.node_id == mapping.node_id)
                        .with_for_update()
                    )
                    if (
                        job is None
                        or node is None
                        or job.status != JobStatus.RETRY_PENDING.value
                        or job.cancel_requested
                        or job.attempt_count >= job.max_attempts
                        or mapping.selected_attempt_number is not None
                    ):
                        continue
                    attempts = tuple(
                        session.scalars(
                            select(SourceOrchestrationAttemptRow)
                            .where(
                                SourceOrchestrationAttemptRow.job_id == mapping.job_id
                            )
                            .order_by(SourceOrchestrationAttemptRow.attempt_number)
                            .with_for_update()
                        )
                    )
                    if (
                        len(attempts) != job.attempt_count
                        or any(
                            item.acceptance_state != "REJECTED"
                            or item.finished_at is None
                            or item.containment_state
                            != OrchestrationContainmentState.CLEAN.value
                            for item in attempts
                        )
                    ):
                        continue
                    latest = attempts[-1]
                    if latest.finished_at is None:
                        continue
                    delay_index = min(latest.attempt_number, len(SOURCE_RETRY_DELAYS_SECONDS)) - 1
                    due_at = _utc(latest.finished_at) + timedelta(
                        seconds=SOURCE_RETRY_DELAYS_SECONDS[delay_index]
                    )
                    if now < due_at:
                        job.available_at = due_at
                        continue
                    job.status = JobStatus.QUEUED.value
                    job.available_at = now
                    job.updated_at = now
                    node.lifecycle_state = OrchestrationNodeLifecycleState.QUEUED.value
                    node.containment_state = OrchestrationContainmentState.CLEAN.value
                    node.state_version += 1
                    promoted.append(job.id)
                return promoted
        except SourceCoordinatorError:
            raise
        except SQLAlchemyError:
            raise SourceCoordinatorError from None

    def _block_dependency(
        self,
        run_id: str,
        node_id: str,
        disposition: OrchestrationNodeDisposition,
        reason: str | None,
    ) -> bool:
        try:
            with self._sessions.begin() as session:
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == run_id)
                    .with_for_update()
                )
                node = session.scalar(
                    select(SourceOrchestrationNodeRow)
                    .where(SourceOrchestrationNodeRow.node_id == node_id)
                    .with_for_update()
                )
                if (
                    parent is None
                    or node is None
                    or parent.lifecycle_state
                    != OrchestrationLifecycleState.ACTIVE.value
                    or node.lifecycle_state
                    != OrchestrationNodeLifecycleState.WAITING_DEPENDENCY.value
                ):
                    return False
                suffix = reason or disposition.value
                _terminalize(
                    node,
                    OrchestrationNodeDisposition.BLOCKED_BY_DEPENDENCY,
                    f"SYFT_{suffix}"[:128],
                )
                return True
        except SQLAlchemyError:
            raise SourceCoordinatorError from None

    def _mark_assembly_ready(self, run_id: str) -> bool:
        try:
            with self._sessions.begin() as session:
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == run_id)
                    .with_for_update()
                )
                if parent is None:
                    raise SourceCoordinatorError
                if (
                    parent.lifecycle_state != OrchestrationLifecycleState.ACTIVE.value
                    or parent.cancel_requested
                ):
                    return False
                nodes = tuple(
                    session.scalars(
                        select(SourceOrchestrationNodeRow)
                        .where(SourceOrchestrationNodeRow.run_id == run_id)
                        .order_by(SourceOrchestrationNodeRow.node_id)
                        .with_for_update()
                    )
                )
                active_attempts = session.scalar(
                    select(func.count())
                    .select_from(SourceOrchestrationAttemptRow)
                    .where(
                        SourceOrchestrationAttemptRow.run_id == run_id,
                        SourceOrchestrationAttemptRow.containment_state
                        != OrchestrationContainmentState.CLEAN.value,
                    )
                )
                if not nodes or active_attempts or any(
                    item.lifecycle_state != OrchestrationNodeLifecycleState.TERMINAL.value
                    for item in nodes
                ):
                    return False
                parent.lifecycle_state = OrchestrationLifecycleState.ASSEMBLY_READY.value
                parent.state_version += 1
                parent.updated_at = _database_now(session)
                return True
        except SourceCoordinatorError:
            raise
        except SQLAlchemyError:
            raise SourceCoordinatorError from None

    def _ready_local_node_ids(self, run_id: str) -> tuple[str, ...]:
        with self._sessions() as session:
            return tuple(
                session.scalars(
                    select(SourceOrchestrationNodeRow.node_id)
                    .where(
                        SourceOrchestrationNodeRow.run_id == run_id,
                        SourceOrchestrationNodeRow.lifecycle_state
                        == OrchestrationNodeLifecycleState.READY.value,
                        SourceOrchestrationNodeRow.authority.in_(
                            sorted(
                                {
                                    SourceAuthority.SEMGREP.value,
                                    SourceAuthority.GITLEAKS.value,
                                    SourceAuthority.SYFT.value,
                                    SourceAuthority.CHECKOV.value,
                                }
                            )
                        ),
                    )
                    .order_by(SourceOrchestrationNodeRow.node_id)
                )
            )

    def _dependency_state(
        self, run_id: str
    ) -> tuple[
        str,
        OrchestrationNodeLifecycleState,
        OrchestrationNodeDisposition | None,
        str | None,
    ] | None:
        with self._sessions() as session:
            rows = tuple(
                session.scalars(
                    select(SourceOrchestrationNodeRow)
                    .where(SourceOrchestrationNodeRow.run_id == run_id)
                    .order_by(SourceOrchestrationNodeRow.node_id)
                )
            )
        osv = next((row for row in rows if row.authority == SourceAuthority.OSV.value), None)
        syft = next((row for row in rows if row.authority == SourceAuthority.SYFT.value), None)
        if osv is None or syft is None:
            return None
        return (
            osv.node_id,
            OrchestrationNodeLifecycleState(osv.lifecycle_state),
            None
            if syft.terminal_disposition is None
            else OrchestrationNodeDisposition(syft.terminal_disposition),
            syft.terminal_reason_code,
        )

    def _parent_state(self, run_id: str) -> OrchestrationLifecycleState:
        with self._sessions() as session:
            value = session.scalar(
                select(SourceOrchestrationRow.lifecycle_state).where(
                    SourceOrchestrationRow.run_id == run_id
                )
            )
        if value is None:
            raise SourceCoordinatorError
        return OrchestrationLifecycleState(value)


def _terminalize(
    node: SourceOrchestrationNodeRow,
    disposition: OrchestrationNodeDisposition,
    reason: str,
) -> None:
    node.lifecycle_state = OrchestrationNodeLifecycleState.TERMINAL.value
    node.terminal_disposition = disposition.value
    node.terminal_reason_code = reason
    node.containment_state = OrchestrationContainmentState.CLEAN.value
    node.state_version += 1


def _database_now(session: Session) -> datetime:
    value = session.scalar(select(func.now()))
    if not isinstance(value, datetime):
        raise SourceCoordinatorError
    return _utc(value)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

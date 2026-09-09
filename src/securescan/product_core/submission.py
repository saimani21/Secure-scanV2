from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid5

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import TargetType
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    SourcePlanningSnapshot,
    frozen_source_v1_authority_roster,
)
from securescan.orchestration.service import (
    SourceOrchestrationCreateRequest,
    SourceOrchestrationService,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    ProjectRow,
    SourceLineageRunRow,
    SourceOrchestrationRow,
    SourceScanSubmissionRow,
    SourceTargetLineageRow,
    TargetRow,
    utc_now,
)
from securescan.source.inventory import build_repository_inventory
from securescan.source.models import RepositoryProfile
from securescan.source.planning import SourceAnalysisPlan
from securescan.workspaces import PreparedRepositoryWorkspace, RepositoryWorkspaceManager
from securescan.workspaces.models import RepositoryManifest

from .finding_index import ProductCoreIndexError, SourceFindingIndexService, SourceLineage
from .lifecycle import ProductCoreLifecycleError, SourceFindingLifecycleService

_TARGET_NAMESPACE = UUID("af194ec5-f341-4de5-b5dc-2ef4f35ef8b9")


class SourceIntakeKind(StrEnum):
    MANAGED_WORKSPACE_V1 = "MANAGED_WORKSPACE_V1"


class ProductCoreSubmissionError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Source Product Core submission operation failed")


class ProductCoreFinalizationNotReadyError(ProductCoreSubmissionError):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source Product Core finalization is not ready")


@dataclass(frozen=True, slots=True)
class SourceScanSubmission:
    run_id: str
    lineage_id: str
    submission_sequence_number: int
    predecessor_run_id: str | None
    predecessor_sequence_number: int | None
    intake_kind: SourceIntakeKind
    intake_ref: str
    created_at: datetime
    finalized_at: datetime | None
    created: bool


@dataclass(frozen=True, slots=True)
class SourcePreparedScanRequest:
    project_id: str
    lineage_id: str
    workspace: PreparedRepositoryWorkspace
    profile: RepositoryProfile
    plan: SourceAnalysisPlan
    idempotency_key: str
    deadline_at: datetime


class SourceScanSubmissionService:
    """Reserve explicit lineage order and bind runs to opaque managed intake."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        workspace_manager: RepositoryWorkspaceManager,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._sessions = session_factory
        self._workspaces = workspace_manager
        self._clock = clock
        self._orchestrations = SourceOrchestrationService(
            session_factory, artifact_store, frozen_source_v1_authority_roster()
        )
        self._index = SourceFindingIndexService(
            session_factory, artifact_store, clock=clock
        )
        self._lifecycle = SourceFindingLifecycleService(
            session_factory, artifact_store, clock=clock
        )

    def create_lineage(self, *, project_id: str) -> SourceLineage:
        return self._index.create_lineage(project_id=project_id)

    def submit_prepared(self, request: SourcePreparedScanRequest) -> SourceScanSubmission:
        if not isinstance(request, SourcePreparedScanRequest):
            raise ProductCoreSubmissionError
        self._verify_prepared_request(request)
        target_id = str(
            uuid5(
                _TARGET_NAMESPACE,
                f"{request.project_id}\0{request.workspace.workspace_id}\0"
                f"{request.idempotency_key}",
            )
        )
        self._create_or_verify_target(
            target_id=target_id,
            project_id=request.project_id,
            lineage_id=request.lineage_id,
            workspace=request.workspace,
        )
        try:
            orchestration = self._orchestrations.create(
                SourceOrchestrationCreateRequest(
                    target_id=target_id,
                    idempotency_key=request.idempotency_key,
                    profile=request.profile,
                    plan=request.plan,
                    deadline_at=request.deadline_at,
                )
            )
            submission = self.reserve(
                run_id=orchestration.run_id,
                lineage_id=request.lineage_id,
                intake_ref=request.workspace.workspace_id,
            )
            if orchestration.lifecycle_state is OrchestrationLifecycleState.PREPARED:
                self._orchestrations.activate(
                    orchestration.run_id, orchestration.state_version
                )
            return submission
        except ProductCoreSubmissionError:
            raise
        except Exception:
            raise ProductCoreSubmissionError from None

    def reserve(
        self, *, run_id: str, lineage_id: str, intake_ref: str
    ) -> SourceScanSubmission:
        self._require_uuid(run_id)
        self._require_uuid(lineage_id)
        self._require_intake_ref(intake_ref)
        try:
            with self._sessions.begin() as session:
                lineage = session.scalar(
                    select(SourceTargetLineageRow)
                    .where(SourceTargetLineageRow.lineage_id == lineage_id)
                    .with_for_update()
                )
                run = session.get(AnalysisRunRow, run_id)
                target = None if run is None else session.get(TargetRow, run.target_id)
                if (
                    lineage is None
                    or run is None
                    or target is None
                    or target.project_id != lineage.project_id
                    or target.target_type != TargetType.SOURCE_REPOSITORY.value
                    or target.source_path != intake_ref
                ):
                    raise ProductCoreSubmissionError

                existing = session.get(SourceScanSubmissionRow, run_id)
                if existing is not None:
                    if (
                        existing.lineage_id != lineage_id
                        or existing.intake_kind
                        != SourceIntakeKind.MANAGED_WORKSPACE_V1.value
                        or existing.intake_ref != intake_ref
                    ):
                        raise ProductCoreSubmissionError
                    return self._record(existing, created=False)

                submission_tail = session.scalar(
                    select(SourceScanSubmissionRow)
                    .where(SourceScanSubmissionRow.lineage_id == lineage_id)
                    .order_by(SourceScanSubmissionRow.submission_sequence_number.desc())
                    .limit(1)
                    .with_for_update()
                )
                lineage_tail = session.scalar(
                    select(SourceLineageRunRow)
                    .where(SourceLineageRunRow.lineage_id == lineage_id)
                    .order_by(SourceLineageRunRow.sequence_number.desc())
                    .limit(1)
                    .with_for_update()
                )
                predecessor_run_id, predecessor_sequence = self._tail_identity(
                    submission_tail, lineage_tail
                )
                sequence = 1 if predecessor_sequence is None else predecessor_sequence + 1
                row = SourceScanSubmissionRow(
                    run_id=run_id,
                    lineage_id=lineage_id,
                    submission_sequence_number=sequence,
                    predecessor_run_id=predecessor_run_id,
                    predecessor_sequence_number=predecessor_sequence,
                    intake_kind=SourceIntakeKind.MANAGED_WORKSPACE_V1.value,
                    intake_ref=intake_ref,
                    created_at=self._now(),
                    finalized_at=None,
                )
                session.add(row)
                session.flush()
                return self._record(row, created=True)
        except ProductCoreSubmissionError:
            raise
        except (IntegrityError, SQLAlchemyError, TypeError, ValueError):
            raise ProductCoreSubmissionError from None

    def resolve_workspace(self, *, run_id: str) -> PreparedRepositoryWorkspace:
        self._require_uuid(run_id)
        try:
            with self._sessions() as session:
                submission = session.get(SourceScanSubmissionRow, run_id)
                run = (
                    None
                    if submission is None
                    else session.get(AnalysisRunRow, run_id)
                )
                target_row = (
                    None if run is None else session.get(TargetRow, run.target_id)
                )
                lineage = (
                    None
                    if submission is None
                    else session.get(SourceTargetLineageRow, submission.lineage_id)
                )
                if (
                    submission is None
                    or run is None
                    or target_row is None
                    or lineage is None
                    or target_row.project_id != lineage.project_id
                    or target_row.target_type != TargetType.SOURCE_REPOSITORY.value
                    or target_row.source_path != submission.intake_ref
                ):
                    raise ProductCoreSubmissionError
            orchestration = self._orchestrations.load(run_id)
            if orchestration.target_id != run.target_id:
                raise ProductCoreSubmissionError
            manifest = self._manifest(orchestration.snapshot)
            workspace = self._workspaces.resolve_workspace(
                submission.intake_ref, manifest
            )
            inventory = build_repository_inventory(workspace)
            if (
                inventory.repository_digest
                != orchestration.snapshot.profile.repository_digest
                or target_row.content_digest != inventory.repository_digest
            ):
                raise ProductCoreSubmissionError
            return workspace
        except ProductCoreSubmissionError:
            raise
        except Exception:
            raise ProductCoreSubmissionError from None

    def finalize(self, *, run_id: str) -> SourceScanSubmission:
        self._require_uuid(run_id)
        submission = self._load(run_id)
        self._require_finalization_ready(submission)
        try:
            membership = self._index.attach_published_run(
                lineage_id=submission.lineage_id,
                run_id=run_id,
                expected_predecessor_run_id=submission.predecessor_run_id,
            )
            if (
                membership.sequence_number != submission.submission_sequence_number
                or membership.predecessor_run_id != submission.predecessor_run_id
            ):
                raise ProductCoreSubmissionError
            self._index.index_attached_run(
                lineage_id=submission.lineage_id, run_id=run_id
            )
            self._lifecycle.evaluate(
                lineage_id=submission.lineage_id, run_id=run_id
            )
            return self._mark_finalized(submission)
        except ProductCoreFinalizationNotReadyError:
            raise
        except (ProductCoreIndexError, ProductCoreLifecycleError):
            raise ProductCoreSubmissionError from None

    def _verify_prepared_request(self, request: SourcePreparedScanRequest) -> None:
        self._require_uuid(request.project_id)
        self._require_uuid(request.lineage_id)
        if (
            not isinstance(request.workspace, PreparedRepositoryWorkspace)
            or not isinstance(request.profile, RepositoryProfile)
            or not isinstance(request.plan, SourceAnalysisPlan)
        ):
            raise ProductCoreSubmissionError
        try:
            owned = self._workspaces.resolve_workspace(
                request.workspace.workspace_id, request.workspace.manifest
            )
            inventory = build_repository_inventory(owned)
        except Exception:
            raise ProductCoreSubmissionError from None
        entries = tuple(file.entry for file in request.profile.files)
        if (
            owned != request.workspace
            or entries != request.workspace.manifest.entries
            or inventory.repository_digest != request.profile.repository_digest
            or request.plan.repository_digest != request.profile.repository_digest
            or request.plan.profile_digest != request.profile.profile_digest()
        ):
            raise ProductCoreSubmissionError

    def _create_or_verify_target(
        self,
        *,
        target_id: str,
        project_id: str,
        lineage_id: str,
        workspace: PreparedRepositoryWorkspace,
    ) -> None:
        try:
            with self._sessions.begin() as session:
                project = session.get(ProjectRow, project_id)
                lineage = session.get(SourceTargetLineageRow, lineage_id)
                if (
                    project is None
                    or lineage is None
                    or lineage.project_id != project_id
                ):
                    raise ProductCoreSubmissionError
                existing = session.get(TargetRow, target_id)
                if existing is None:
                    session.add(
                        TargetRow(
                            id=target_id,
                            project_id=project_id,
                            target_type=TargetType.SOURCE_REPOSITORY.value,
                            content_digest=workspace.manifest.content_digest,
                            source_path=workspace.workspace_id,
                            metadata_json={
                                "intake_kind": SourceIntakeKind.MANAGED_WORKSPACE_V1.value,
                                "intake_ref": workspace.workspace_id,
                            },
                        )
                    )
                    session.flush()
                elif (
                    existing.project_id != project_id
                    or existing.target_type != TargetType.SOURCE_REPOSITORY.value
                    or existing.content_digest != workspace.manifest.content_digest
                    or existing.source_path != workspace.workspace_id
                    or existing.metadata_json
                    != {
                        "intake_kind": SourceIntakeKind.MANAGED_WORKSPACE_V1.value,
                        "intake_ref": workspace.workspace_id,
                    }
                ):
                    raise ProductCoreSubmissionError
        except ProductCoreSubmissionError:
            raise
        except (IntegrityError, SQLAlchemyError):
            raise ProductCoreSubmissionError from None

    def _require_finalization_ready(self, submission: SourceScanSubmission) -> None:
        try:
            with self._sessions() as session:
                parent = session.get(SourceOrchestrationRow, submission.run_id)
                if (
                    parent is None
                    or parent.lifecycle_state != OrchestrationLifecycleState.TERMINAL.value
                    or parent.published_at is None
                ):
                    raise ProductCoreFinalizationNotReadyError
                if submission.predecessor_run_id is None:
                    return
                predecessor_submission = session.get(
                    SourceScanSubmissionRow, submission.predecessor_run_id
                )
                predecessor_membership = session.get(
                    SourceLineageRunRow, submission.predecessor_run_id
                )
                if (
                    predecessor_membership is None
                    or predecessor_membership.lineage_id != submission.lineage_id
                    or predecessor_membership.sequence_number
                    != submission.predecessor_sequence_number
                    or predecessor_membership.lifecycle_evaluated_at is None
                    or (
                        predecessor_submission is not None
                        and predecessor_submission.finalized_at is None
                    )
                ):
                    raise ProductCoreFinalizationNotReadyError
        except ProductCoreFinalizationNotReadyError:
            raise
        except SQLAlchemyError:
            raise ProductCoreSubmissionError from None

    def _mark_finalized(
        self, expected: SourceScanSubmission
    ) -> SourceScanSubmission:
        try:
            with self._sessions.begin() as session:
                row = session.scalar(
                    select(SourceScanSubmissionRow)
                    .where(SourceScanSubmissionRow.run_id == expected.run_id)
                    .with_for_update()
                )
                membership = session.get(SourceLineageRunRow, expected.run_id)
                if (
                    row is None
                    or membership is None
                    or row.lineage_id != expected.lineage_id
                    or row.submission_sequence_number
                    != expected.submission_sequence_number
                    or membership.lineage_id != row.lineage_id
                    or membership.sequence_number != row.submission_sequence_number
                    or membership.lifecycle_evaluated_at is None
                ):
                    raise ProductCoreSubmissionError
                if row.finalized_at is None:
                    row.finalized_at = self._now()
                    session.flush()
                return self._record(row, created=False)
        except ProductCoreSubmissionError:
            raise
        except SQLAlchemyError:
            raise ProductCoreSubmissionError from None

    def _load(self, run_id: str) -> SourceScanSubmission:
        try:
            with self._sessions() as session:
                row = session.get(SourceScanSubmissionRow, run_id)
                if row is None:
                    raise ProductCoreSubmissionError
                return self._record(row, created=False)
        except ProductCoreSubmissionError:
            raise
        except SQLAlchemyError:
            raise ProductCoreSubmissionError from None

    @staticmethod
    def _tail_identity(
        submission: SourceScanSubmissionRow | None,
        membership: SourceLineageRunRow | None,
    ) -> tuple[str | None, int | None]:
        candidates = []
        if submission is not None:
            candidates.append((submission.run_id, submission.submission_sequence_number))
        if membership is not None:
            candidates.append((membership.run_id, membership.sequence_number))
        if not candidates:
            return None, None
        maximum = max(sequence for _run_id, sequence in candidates)
        runs = {run_id for run_id, sequence in candidates if sequence == maximum}
        if len(runs) != 1:
            raise ProductCoreSubmissionError
        return runs.pop(), maximum

    @staticmethod
    def _manifest(snapshot: SourcePlanningSnapshot) -> RepositoryManifest:
        entries = tuple(file.entry for file in snapshot.profile.files)
        return RepositoryManifest(
            entries=entries,
            file_count=len(entries),
            total_bytes=sum(entry.size_bytes for entry in entries),
            content_digest=snapshot.profile.repository_digest,
        )

    @staticmethod
    def _record(row: SourceScanSubmissionRow, *, created: bool) -> SourceScanSubmission:
        return SourceScanSubmission(
            run_id=row.run_id,
            lineage_id=row.lineage_id,
            submission_sequence_number=row.submission_sequence_number,
            predecessor_run_id=row.predecessor_run_id,
            predecessor_sequence_number=row.predecessor_sequence_number,
            intake_kind=SourceIntakeKind(row.intake_kind),
            intake_ref=row.intake_ref,
            created_at=SourceScanSubmissionService._as_utc(row.created_at),
            finalized_at=(
                None
                if row.finalized_at is None
                else SourceScanSubmissionService._as_utc(row.finalized_at)
            ),
            created=created,
        )

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @staticmethod
    def _require_uuid(value: object) -> None:
        try:
            valid = isinstance(value, str) and str(UUID(value)) == value
        except ValueError:
            valid = False
        if not valid:
            raise ProductCoreSubmissionError

    @staticmethod
    def _require_intake_ref(value: object) -> None:
        if (
            not isinstance(value, str)
            or not value.startswith("securescan-workspace-")
            or not 16 <= len(value.removeprefix("securescan-workspace-")) <= 48
            or any(
                character not in "0123456789abcdef"
                for character in value.removeprefix("securescan-workspace-")
            )
        ):
            raise ProductCoreSubmissionError

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ProductCoreSubmissionError
        return value.astimezone(UTC)

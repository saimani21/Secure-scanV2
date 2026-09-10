from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import TargetType
from securescan.orchestration.models import SourceOrchestrationIntegrityError
from securescan.orchestration.service import (
    SourceOrchestrationError,
    SourceOrchestrationRecord,
    SourceOrchestrationService,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceOrchestrationRow,
    SourceScanSubmissionRow,
    SourceTargetLineageRow,
    TargetRow,
)

from .submission import (
    ProductCoreSubmissionError,
    SourceIntakeKind,
    SourcePreparedScanRequest,
    SourceScanSubmission,
    SourceScanSubmissionService,
)


class SourceHttpSubmissionError(RuntimeError):
    def __init__(self, message: str = "Source scan submission is unavailable") -> None:
        super().__init__(message)


class SourceHttpTargetNotFoundError(SourceHttpSubmissionError):
    def __init__(self) -> None:
        super().__init__("Trusted Source target was not found")


class SourceHttpLineageNotFoundError(SourceHttpSubmissionError):
    def __init__(self) -> None:
        super().__init__("Source lineage was not found")


class SourceHttpSubmissionConflictError(SourceHttpSubmissionError):
    def __init__(self) -> None:
        super().__init__("Source scan submission conflicts with durable state")


@dataclass(frozen=True, slots=True)
class SourceTrustedTargetScanRequest:
    project_id: str
    trusted_target_id: str
    lineage_id: str | None
    idempotency_key: str
    deadline_at: datetime


class SourceTrustedTargetSubmissionService:
    """Submit from a previously verified opaque PC3A target, never a host path."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        submission_service: SourceScanSubmissionService,
        orchestration_service: SourceOrchestrationService,
    ) -> None:
        self._sessions = session_factory
        self._submissions = submission_service
        self._orchestrations = orchestration_service

    def submit(self, request: SourceTrustedTargetScanRequest) -> SourceScanSubmission:
        self._validate(request)
        deadline = request.deadline_at.astimezone(UTC)
        try:
            trusted_run_id, intake_ref = self._trusted_source(request)
            source = self._orchestrations.load(trusted_run_id)
            workspace = self._submissions.resolve_workspace(run_id=trusted_run_id)
            replay = self._replay(request, source, intake_ref, deadline)
            if replay is not None:
                return replay
            lineage_id = request.lineage_id
            if lineage_id is None:
                lineage_id = self._submissions.create_lineage(
                    project_id=request.project_id
                ).lineage_id
            else:
                self._require_lineage(request.project_id, lineage_id)
            return self._submissions.submit_prepared(
                SourcePreparedScanRequest(
                    project_id=request.project_id,
                    lineage_id=lineage_id,
                    workspace=workspace,
                    profile=source.snapshot.profile,
                    plan=source.snapshot.plan,
                    idempotency_key=request.idempotency_key,
                    deadline_at=deadline,
                )
            )
        except (
            SourceHttpTargetNotFoundError,
            SourceHttpLineageNotFoundError,
            SourceHttpSubmissionConflictError,
        ):
            raise
        except (
            ProductCoreSubmissionError,
            SourceOrchestrationError,
            SourceOrchestrationIntegrityError,
            SQLAlchemyError,
        ):
            raise SourceHttpSubmissionError from None

    def _trusted_source(self, request: SourceTrustedTargetScanRequest) -> tuple[str, str]:
        with self._sessions() as session:
            target = session.get(TargetRow, request.trusted_target_id)
            if target is None:
                raise SourceHttpTargetNotFoundError
            expected_metadata = {
                "intake_kind": SourceIntakeKind.MANAGED_WORKSPACE_V1.value,
                "intake_ref": target.source_path,
            }
            if (
                target.project_id != request.project_id
                or target.target_type != TargetType.SOURCE_REPOSITORY.value
                or target.metadata_json != expected_metadata
            ):
                raise SourceHttpSubmissionConflictError
            rows = tuple(
                session.execute(
                    select(SourceScanSubmissionRow, AnalysisRunRow)
                    .join(
                        AnalysisRunRow,
                        AnalysisRunRow.id == SourceScanSubmissionRow.run_id,
                    )
                    .where(AnalysisRunRow.target_id == target.id)
                    .limit(2)
                )
            )
            if len(rows) != 1:
                raise SourceHttpSubmissionConflictError
            submission, run = rows[0]
            if (
                run.target_id != target.id
                or submission.intake_ref != target.source_path
                or submission.intake_kind != SourceIntakeKind.MANAGED_WORKSPACE_V1.value
            ):
                raise SourceHttpSubmissionConflictError
            return submission.run_id, submission.intake_ref

    def _replay(
        self,
        request: SourceTrustedTargetScanRequest,
        source: SourceOrchestrationRecord,
        intake_ref: str,
        deadline: datetime,
    ) -> SourceScanSubmission | None:
        with self._sessions() as session:
            parent = session.scalar(
                select(SourceOrchestrationRow).where(
                    SourceOrchestrationRow.idempotency_key == request.idempotency_key
                )
            )
            if parent is None:
                return None
            run = session.get(AnalysisRunRow, parent.run_id)
            target = None if run is None else session.get(TargetRow, run.target_id)
            submission = session.get(SourceScanSubmissionRow, parent.run_id)
            if (
                run is None
                or target is None
                or submission is None
                or target.project_id != request.project_id
                or submission.intake_ref != intake_ref
                or (request.lineage_id is not None and submission.lineage_id != request.lineage_id)
                or self._utc(parent.deadline_at) != deadline
                or parent.profile_digest != source.snapshot.profile.profile_digest()
                or parent.plan_digest != source.snapshot.plan.plan_digest()
            ):
                raise SourceHttpSubmissionConflictError
            return self._submissions.reserve(
                run_id=parent.run_id,
                lineage_id=submission.lineage_id,
                intake_ref=intake_ref,
            )

    def _require_lineage(self, project_id: str, lineage_id: str) -> None:
        with self._sessions() as session:
            lineage = session.get(SourceTargetLineageRow, lineage_id)
            if lineage is None:
                raise SourceHttpLineageNotFoundError
            if lineage.project_id != project_id:
                raise SourceHttpSubmissionConflictError

    @staticmethod
    def _utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @staticmethod
    def _validate(request: SourceTrustedTargetScanRequest) -> None:
        if not isinstance(request, SourceTrustedTargetScanRequest):
            raise SourceHttpSubmissionError
        for value in (request.project_id, request.trusted_target_id):
            try:
                valid = isinstance(value, str) and str(UUID(value)) == value
            except ValueError:
                valid = False
            if not valid:
                raise SourceHttpSubmissionError
        if request.lineage_id is not None:
            try:
                if (
                    not isinstance(request.lineage_id, str)
                    or str(UUID(request.lineage_id)) != request.lineage_id
                ):
                    raise ValueError
            except (AttributeError, TypeError, ValueError):
                raise SourceHttpSubmissionError from None
        if (
            not isinstance(request.idempotency_key, str)
            or len(request.idempotency_key) != 64
            or request.idempotency_key != request.idempotency_key.lower()
            or any(character not in "0123456789abcdef" for character in request.idempotency_key)
            or not isinstance(request.deadline_at, datetime)
            or request.deadline_at.tzinfo is None
            or request.deadline_at.utcoffset() is None
        ):
            raise SourceHttpSubmissionError

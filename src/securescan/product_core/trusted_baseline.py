from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import RunStatus
from securescan.evidence import SECURESCAN_EVIDENCE_SCHEMA_VERSION
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    OrchestrationTerminalOutcome,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceFindingOccurrenceRow,
    SourceLineageRunRow,
    SourceOrchestrationRow,
    SourceScanSubmissionRow,
    SourceTargetLineageRow,
    SourceTrustedBaselinePromotionRow,
    TargetRow,
    utc_now,
)

from .finding_index import ProductCoreIndexError, SourceFindingIndexService

LOCAL_OPERATOR = "LOCAL_OPERATOR"
MAX_BASELINE_HISTORY_LIMIT = 200
_ELIGIBLE_OUTCOMES = {
    OrchestrationTerminalOutcome.COMPLETED.value: RunStatus.COMPLETED.value,
    OrchestrationTerminalOutcome.PARTIAL.value: RunStatus.PARTIAL.value,
}


class TrustedBaselineError(Exception):
    pass


class TrustedBaselineNotFoundError(TrustedBaselineError):
    pass


class TrustedBaselineConflictError(TrustedBaselineError):
    pass


class TrustedBaselineIneligibleError(TrustedBaselineError):
    pass


class TrustedBaselineValidationError(TrustedBaselineError):
    pass


class TrustedBaselinePersistenceError(TrustedBaselineError):
    pass


@dataclass(frozen=True, slots=True)
class TrustedBaseline:
    baseline_id: str
    lineage_id: str
    run_id: str
    run_sequence_number: int
    revision: int
    actor_type: str
    promoted_at: datetime


@dataclass(frozen=True, slots=True)
class TrustedBaselineState:
    lineage_id: str
    revision: int
    baseline: TrustedBaseline | None


@dataclass(frozen=True, slots=True)
class TrustedBaselineHistoryPage:
    items: tuple[TrustedBaseline, ...]
    total: int
    limit: int
    offset: int


class SourceTrustedBaselineService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        *,
        clock: Callable[[], datetime] = utc_now,
        baseline_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise TrustedBaselinePersistenceError
        self._sessions = session_factory
        self._index = SourceFindingIndexService(session_factory, artifact_store)
        self._clock = clock
        self._baseline_id_factory = baseline_id_factory

    def get_current(self, *, project_id: str, lineage_id: str) -> TrustedBaselineState:
        self._validate_identifiers(project_id, lineage_id)
        try:
            with self._sessions() as session:
                self._stable_read(session)
                self._require_lineage(session, project_id, lineage_id)
                row = self._current_row(session, lineage_id)
                return TrustedBaselineState(
                    lineage_id=lineage_id,
                    revision=0 if row is None else row.revision,
                    baseline=None if row is None else self._record(session, row),
                )
        except TrustedBaselineError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise TrustedBaselinePersistenceError from None

    def list_history(
        self,
        *,
        project_id: str,
        lineage_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> TrustedBaselineHistoryPage:
        self._validate_identifiers(project_id, lineage_id)
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= MAX_BASELINE_HISTORY_LIMIT
        ):
            raise TrustedBaselineValidationError("limit must be between 1 and 200")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise TrustedBaselineValidationError("offset must be nonnegative")
        try:
            with self._sessions() as session:
                self._stable_read(session)
                self._require_lineage(session, project_id, lineage_id)
                total = session.scalar(
                    select(func.count())
                    .select_from(SourceTrustedBaselinePromotionRow)
                    .where(SourceTrustedBaselinePromotionRow.lineage_id == lineage_id)
                )
                rows = tuple(
                    session.scalars(
                        select(SourceTrustedBaselinePromotionRow)
                        .where(SourceTrustedBaselinePromotionRow.lineage_id == lineage_id)
                        .order_by(SourceTrustedBaselinePromotionRow.revision)
                        .limit(limit)
                        .offset(offset)
                    )
                )
                return TrustedBaselineHistoryPage(
                    items=tuple(self._record(session, row) for row in rows),
                    total=total,
                    limit=limit,
                    offset=offset,
                )
        except TrustedBaselineError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise TrustedBaselinePersistenceError from None

    def promote(
        self,
        *,
        project_id: str,
        lineage_id: str,
        run_id: str,
        expected_revision: int,
    ) -> TrustedBaseline:
        self._validate_identifiers(project_id, lineage_id, run_id)
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 0
        ):
            raise TrustedBaselineValidationError("expected_revision must be nonnegative")
        try:
            report = self._index.load_verified_published_report(run_id=run_id)
        except ProductCoreIndexError:
            raise TrustedBaselineIneligibleError from None
        now = self._now()
        try:
            with self._sessions.begin() as session:
                self._require_lineage(session, project_id, lineage_id, lock_lineage=True)
                current = self._current_row(session, lineage_id, lock=True)
                current_revision = 0 if current is None else current.revision
                if current_revision != expected_revision:
                    raise TrustedBaselineConflictError
                membership = session.scalar(
                    select(SourceLineageRunRow)
                    .where(SourceLineageRunRow.run_id == run_id)
                    .with_for_update()
                )
                self._require_eligible_run(
                    session,
                    project_id=project_id,
                    lineage_id=lineage_id,
                    membership=membership,
                    report_schema_version=report.schema_version,
                )
                if current is not None:
                    previous = session.get(SourceLineageRunRow, current.run_id)
                    if (
                        previous is None
                        or membership is None
                        or membership.sequence_number < previous.sequence_number
                    ):
                        raise TrustedBaselineIneligibleError
                baseline_id = str(self._baseline_id_factory())
                self._require_uuid(baseline_id)
                row = SourceTrustedBaselinePromotionRow(
                    baseline_id=baseline_id,
                    lineage_id=lineage_id,
                    run_id=run_id,
                    revision=current_revision + 1,
                    actor_type=LOCAL_OPERATOR,
                    promoted_at=now,
                )
                session.add(row)
                session.flush()
                return self._record(session, row)
        except (
            TrustedBaselineConflictError,
            TrustedBaselineIneligibleError,
            TrustedBaselineNotFoundError,
            TrustedBaselineValidationError,
        ):
            raise
        except IntegrityError:
            raise TrustedBaselineConflictError from None
        except (SQLAlchemyError, TypeError, ValueError):
            raise TrustedBaselinePersistenceError from None

    @staticmethod
    def _require_eligible_run(
        session: Session,
        *,
        project_id: str,
        lineage_id: str,
        membership: SourceLineageRunRow | None,
        report_schema_version: str,
    ) -> None:
        if membership is None:
            raise TrustedBaselineIneligibleError
        submission = session.get(SourceScanSubmissionRow, membership.run_id)
        run = session.get(AnalysisRunRow, membership.run_id)
        parent = session.get(SourceOrchestrationRow, membership.run_id)
        target = None if run is None else session.get(TargetRow, run.target_id)
        occurrence_count = session.scalar(
            select(func.count())
            .select_from(SourceFindingOccurrenceRow)
            .where(SourceFindingOccurrenceRow.run_id == membership.run_id)
        )
        unprioritized = session.scalar(
            select(func.count())
            .select_from(SourceFindingOccurrenceRow)
            .where(
                SourceFindingOccurrenceRow.run_id == membership.run_id,
                (
                    SourceFindingOccurrenceRow.priority_band.is_(None)
                    | SourceFindingOccurrenceRow.priority_reason_codes_json.is_(None)
                ),
            )
        )
        if (
            membership.lineage_id != lineage_id
            or membership.indexing_state != "INDEXED"
            or membership.indexed_at is None
            or membership.lifecycle_evaluated_at is None
            or membership.lifecycle_evaluation_sha256 is None
            or membership.lifecycle_event_count is None
            or membership.report_schema_version != SECURESCAN_EVIDENCE_SCHEMA_VERSION
            or report_schema_version != membership.report_schema_version
            or submission is None
            or submission.lineage_id != lineage_id
            or submission.submission_sequence_number != membership.sequence_number
            or submission.finalized_at is None
            or run is None
            or target is None
            or target.project_id != project_id
            or parent is None
            or parent.lifecycle_state != OrchestrationLifecycleState.TERMINAL.value
            or parent.terminal_outcome not in _ELIGIBLE_OUTCOMES
            or run.status != _ELIGIBLE_OUTCOMES[parent.terminal_outcome]
            or parent.published_at is None
            or occurrence_count is None
            or unprioritized != 0
        ):
            raise TrustedBaselineIneligibleError

    @staticmethod
    def _require_lineage(
        session: Session,
        project_id: str,
        lineage_id: str,
        *,
        lock_lineage: bool = False,
    ) -> SourceTargetLineageRow:
        statement = select(SourceTargetLineageRow).where(
            SourceTargetLineageRow.lineage_id == lineage_id
        )
        if lock_lineage:
            statement = statement.with_for_update()
        row = session.scalar(statement)
        if row is None or row.project_id != project_id:
            raise TrustedBaselineNotFoundError
        return row

    @staticmethod
    def _current_row(
        session: Session, lineage_id: str, *, lock: bool = False
    ) -> SourceTrustedBaselinePromotionRow | None:
        statement = (
            select(SourceTrustedBaselinePromotionRow)
            .where(SourceTrustedBaselinePromotionRow.lineage_id == lineage_id)
            .order_by(SourceTrustedBaselinePromotionRow.revision.desc())
            .limit(1)
        )
        if lock:
            statement = statement.with_for_update()
        return session.scalar(statement)

    @staticmethod
    def _record(session: Session, row: SourceTrustedBaselinePromotionRow) -> TrustedBaseline:
        membership = session.get(SourceLineageRunRow, row.run_id)
        if membership is None or membership.lineage_id != row.lineage_id:
            raise TrustedBaselinePersistenceError
        return TrustedBaseline(
            baseline_id=row.baseline_id,
            lineage_id=row.lineage_id,
            run_id=row.run_id,
            run_sequence_number=membership.sequence_number,
            revision=row.revision,
            actor_type=row.actor_type,
            promoted_at=SourceTrustedBaselineService._as_utc(row.promoted_at),
        )

    @staticmethod
    def _validate_identifiers(*values: str) -> None:
        try:
            valid = all(isinstance(value, str) and str(UUID(value)) == value for value in values)
        except (AttributeError, TypeError, ValueError):
            valid = False
        if not valid:
            raise TrustedBaselineValidationError("invalid trusted-baseline identifier")

    @staticmethod
    def _require_uuid(value: object) -> None:
        try:
            valid = isinstance(value, str) and str(UUID(value)) == value
        except (AttributeError, TypeError, ValueError):
            valid = False
        if not valid:
            raise TrustedBaselinePersistenceError

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise TrustedBaselinePersistenceError
        return value.astimezone(UTC)

    @staticmethod
    def _stable_read(session: Session) -> None:
        if session.get_bind().dialect.name == "postgresql":
            session.connection(execution_options={"isolation_level": "REPEATABLE READ"})

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

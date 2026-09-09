from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import and_, case, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, aliased, sessionmaker

from securescan.persistence.database import (
    SourceLineageRunRow,
    SourceOrchestrationRow,
    SourceScanSubmissionRow,
)

from .submission import (
    ProductCoreFinalizationNotReadyError,
    SourceScanSubmissionService,
)

DEFAULT_FINALIZATION_LIMIT = 50
MAX_FINALIZATION_LIMIT = 200


class ProductFinalizationRunnerError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Source Product Core finalization runner failed")


class ProductFinalizationOutcome(StrEnum):
    FINALIZED = "FINALIZED"
    ALREADY_FINALIZED = "ALREADY_FINALIZED"
    NOT_READY = "NOT_READY"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class ProductFinalizationRunResult:
    run_id: str
    outcome: ProductFinalizationOutcome


@dataclass(frozen=True, slots=True)
class ProductFinalizationBatchResult:
    examined_count: int
    finalized_count: int
    already_finalized_count: int
    not_ready_count: int
    failed_count: int
    outcomes: tuple[ProductFinalizationRunResult, ...]


class SourceProductFinalizationRunner:
    """Bounded application runner over PC3A's convergent finalization boundary."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        submission_service: SourceScanSubmissionService,
    ) -> None:
        if not isinstance(submission_service, SourceScanSubmissionService):
            raise ProductFinalizationRunnerError
        self._sessions = session_factory
        self._submissions = submission_service

    def finalize_ready(
        self, *, limit: int = DEFAULT_FINALIZATION_LIMIT
    ) -> ProductFinalizationBatchResult:
        self._validate_limit(limit)
        candidates = self._discover(limit)
        outcomes = tuple(self._finalize(run_id) for run_id in candidates)
        return ProductFinalizationBatchResult(
            examined_count=len(outcomes),
            finalized_count=sum(
                item.outcome is ProductFinalizationOutcome.FINALIZED for item in outcomes
            ),
            already_finalized_count=sum(
                item.outcome is ProductFinalizationOutcome.ALREADY_FINALIZED
                for item in outcomes
            ),
            not_ready_count=sum(
                item.outcome is ProductFinalizationOutcome.NOT_READY for item in outcomes
            ),
            failed_count=sum(
                item.outcome is ProductFinalizationOutcome.FAILED for item in outcomes
            ),
            outcomes=outcomes,
        )

    def _discover(self, limit: int) -> tuple[str, ...]:
        try:
            with self._sessions() as session:
                predecessor_membership = aliased(SourceLineageRunRow)
                predecessor_submission = aliased(SourceScanSubmissionRow)
                predecessor_ready = or_(
                    SourceScanSubmissionRow.predecessor_run_id.is_(None),
                    and_(
                        predecessor_membership.run_id
                        == SourceScanSubmissionRow.predecessor_run_id,
                        predecessor_membership.lineage_id
                        == SourceScanSubmissionRow.lineage_id,
                        predecessor_membership.sequence_number
                        == SourceScanSubmissionRow.predecessor_sequence_number,
                        predecessor_membership.lifecycle_evaluated_at.is_not(None),
                        or_(
                            predecessor_submission.run_id.is_(None),
                            predecessor_submission.finalized_at.is_not(None),
                        ),
                    ),
                )
                return tuple(
                    session.scalars(
                        select(SourceScanSubmissionRow.run_id)
                        .join(
                            SourceOrchestrationRow,
                            SourceOrchestrationRow.run_id
                            == SourceScanSubmissionRow.run_id,
                        )
                        .outerjoin(
                            predecessor_membership,
                            predecessor_membership.run_id
                            == SourceScanSubmissionRow.predecessor_run_id,
                        )
                        .outerjoin(
                            predecessor_submission,
                            predecessor_submission.run_id
                            == SourceScanSubmissionRow.predecessor_run_id,
                        )
                        .where(
                            SourceScanSubmissionRow.finalized_at.is_(None),
                            SourceOrchestrationRow.published_at.is_not(None),
                        )
                        .order_by(
                            case((predecessor_ready, 0), else_=1),
                            SourceScanSubmissionRow.lineage_id,
                            SourceScanSubmissionRow.submission_sequence_number,
                        )
                        .limit(limit)
                    )
                )
        except SQLAlchemyError:
            raise ProductFinalizationRunnerError from None

    def _finalize(self, run_id: str) -> ProductFinalizationRunResult:
        if self._already_finalized(run_id):
            return ProductFinalizationRunResult(
                run_id, ProductFinalizationOutcome.ALREADY_FINALIZED
            )
        try:
            finalized = self._submissions.finalize(run_id=run_id)
        except ProductCoreFinalizationNotReadyError:
            outcome = ProductFinalizationOutcome.NOT_READY
        except Exception:
            # Per-candidate failure is deliberately isolated from the bounded batch.
            outcome = ProductFinalizationOutcome.FAILED
        else:
            outcome = (
                ProductFinalizationOutcome.FINALIZED
                if finalized.finalized_at is not None
                else ProductFinalizationOutcome.FAILED
            )
        return ProductFinalizationRunResult(run_id, outcome)

    def _already_finalized(self, run_id: str) -> bool:
        try:
            with self._sessions() as session:
                row = session.get(SourceScanSubmissionRow, run_id)
                return row is not None and row.finalized_at is not None
        except SQLAlchemyError:
            return False

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_FINALIZATION_LIMIT
        ):
            raise ProductFinalizationRunnerError

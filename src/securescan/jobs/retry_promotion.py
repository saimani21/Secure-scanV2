from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobStatus
from securescan.domain.job_state import InvalidJobTransition, validate_job_transition
from securescan.jobs.execution import _comparable_timestamp
from securescan.jobs.leasing import UnsupportedQueueDatabaseError
from securescan.jobs.mappers import job_record_from_row
from securescan.jobs.models import JobRecord
from securescan.persistence.database import (
    JobRow,
    SourceOrchestrationScannerJobRow,
    utc_now,
)
from securescan.runs.aggregation import RunAggregationError, recompute_analysis_run_status


class JobRetryPromotionError(RuntimeError):
    """Raised when atomic retry promotion fails."""


class InvalidRetryPromotionRequestError(JobRetryPromotionError):
    """Raised when the requested promotion batch size is invalid."""

    def __init__(self, limit: object) -> None:
        self.limit = limit
        super().__init__("limit must be between 1 and 1000")


class JobRetryPromotionService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock

    def promote_due_retries(
        self,
        limit: int = 100,
    ) -> list[JobRecord]:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 1000
        ):
            raise InvalidRetryPromotionRequestError(limit)

        validate_job_transition(
            JobStatus.RETRY_PENDING,
            JobStatus.QUEUED,
        )

        try:
            with self._session_factory.begin() as session:
                dialect_name = session.get_bind().dialect.name
                if dialect_name != "postgresql":
                    raise UnsupportedQueueDatabaseError(dialect_name)

                operation_timestamp = self._clock()
                rows = list(
                    session.scalars(
                        select(JobRow)
                        .where(
                            JobRow.status == JobStatus.RETRY_PENDING.value,
                            JobRow.available_at <= operation_timestamp,
                            JobRow.cancel_requested.is_(False),
                            JobRow.attempt_count < JobRow.max_attempts,
                            JobRow.leased_by.is_(None),
                            JobRow.lease_token.is_(None),
                            JobRow.lease_expires_at.is_(None),
                            ~select(SourceOrchestrationScannerJobRow.job_id)
                            .where(SourceOrchestrationScannerJobRow.job_id == JobRow.id)
                            .exists(),
                        )
                        .order_by(
                            JobRow.available_at.asc(),
                            JobRow.priority.asc(),
                            JobRow.created_at.asc(),
                            JobRow.id.asc(),
                        )
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                )

                for row in rows:
                    validate_job_transition(
                        JobStatus(row.status),
                        JobStatus.QUEUED,
                    )
                    row.status = JobStatus.QUEUED.value
                    if row.updated_at is None or _comparable_timestamp(
                        row.updated_at
                    ) < _comparable_timestamp(operation_timestamp):
                        row.updated_at = operation_timestamp
                    recompute_analysis_run_status(
                        session,
                        row.run_id,
                        changed_at=operation_timestamp,
                    )

                session.flush()
                records = [job_record_from_row(row) for row in rows]
        except (
            InvalidRetryPromotionRequestError,
            UnsupportedQueueDatabaseError,
            InvalidJobTransition,
            JobRetryPromotionError,
        ):
            raise
        except RunAggregationError as exc:
            raise JobRetryPromotionError("Failed to promote due retry jobs") from exc
        except SQLAlchemyError:
            raise JobRetryPromotionError("Failed to promote due retry jobs") from None

        return records

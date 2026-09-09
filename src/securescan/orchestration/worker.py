from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import exists, func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobStatus
from securescan.jobs.execution import JobExecutionService
from securescan.jobs.mappers import job_record_from_row
from securescan.jobs.models import JobRecord
from securescan.persistence.database import (
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    utc_now,
)

from .execution import SourceScannerAttemptRecord, SourceScannerAttemptService
from .models import (
    OrchestrationContainmentState,
    OrchestrationLifecycleState,
    OrchestrationNodeLifecycleState,
    SourceAuthority,
)


class SourceWorkerError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Source orchestration worker cycle failed")


class SourceWorkerDisposition(StrEnum):
    IDLE = "IDLE"
    DISPATCHED = "DISPATCHED"


@dataclass(frozen=True, slots=True)
class SourceWorkerCycleResult:
    disposition: SourceWorkerDisposition
    job_id: str | None
    authority: SourceAuthority | None
    attempt_number: int | None


class SourceAuthorityRunner(Protocol):
    def __call__(
        self, job: JobRecord, attempt: SourceScannerAttemptRecord
    ) -> None: ...


class SourceAuthorityDispatcher:
    """Exact five-authority dispatch table; runners retain frozen scanner logic."""

    def __init__(self, runners: Mapping[SourceAuthority, SourceAuthorityRunner]) -> None:
        if set(runners) != set(SourceAuthority) or any(
            not callable(runner) for runner in runners.values()
        ):
            raise SourceWorkerError
        self._runners = dict(runners)

    def dispatch(
        self,
        authority: SourceAuthority,
        job: JobRecord,
        attempt: SourceScannerAttemptRecord,
    ) -> None:
        try:
            runner = self._runners[authority]
        except (KeyError, TypeError):
            raise SourceWorkerError from None
        runner(job, attempt)


class SourceMappedJobLeasingService:
    """Lease only mapped Source jobs while holding the parent ordering lock."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        clock: Callable[[], datetime] = utc_now,
        token_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._sessions = session_factory
        self._clock = clock
        self._tokens = token_factory

    def lease_next(
        self, *, worker_id: str, lease_seconds: int = 30
    ) -> JobRecord | None:
        worker = worker_id.strip() if isinstance(worker_id, str) else ""
        if not worker or len(worker) > 200 or not 1 <= lease_seconds <= 86_400:
            raise SourceWorkerError
        operation_time = self._now()
        try:
            with self._sessions.begin() as session:
                queued = (
                    select(JobRow.id)
                    .join(
                        SourceOrchestrationScannerJobRow,
                        SourceOrchestrationScannerJobRow.job_id == JobRow.id,
                    )
                    .where(
                        JobRow.run_id == SourceOrchestrationRow.run_id,
                        JobRow.status == JobStatus.QUEUED.value,
                        JobRow.available_at <= operation_time,
                        JobRow.cancel_requested.is_(False),
                        JobRow.attempt_count < JobRow.max_attempts,
                    )
                )
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(
                        SourceOrchestrationRow.lifecycle_state
                        == OrchestrationLifecycleState.ACTIVE.value,
                        SourceOrchestrationRow.cancel_requested.is_(False),
                        SourceOrchestrationRow.deadline_at > func.now(),
                        exists(queued),
                    )
                    .order_by(SourceOrchestrationRow.created_at, SourceOrchestrationRow.run_id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if parent is None:
                    return None
                active_count = session.scalar(
                    select(func.count())
                    .select_from(SourceOrchestrationScannerJobRow)
                    .join(
                        JobRow,
                        JobRow.id == SourceOrchestrationScannerJobRow.job_id,
                    )
                    .where(
                        SourceOrchestrationScannerJobRow.run_id == parent.run_id,
                        or_(
                            JobRow.status.in_(
                                (JobStatus.LEASED.value, JobStatus.RUNNING.value)
                            ),
                            exists().where(
                                SourceOrchestrationAttemptRow.job_id == JobRow.id,
                                SourceOrchestrationAttemptRow.containment_state
                                == OrchestrationContainmentState.RECONCILIATION_REQUIRED.value,
                            ),
                        ),
                    )
                )
                if active_count is None or active_count >= parent.max_active_jobs:
                    return None
                job = session.scalar(
                    select(JobRow)
                    .join(
                        SourceOrchestrationScannerJobRow,
                        SourceOrchestrationScannerJobRow.job_id == JobRow.id,
                    )
                    .where(
                        JobRow.run_id == parent.run_id,
                        JobRow.status == JobStatus.QUEUED.value,
                        JobRow.available_at <= operation_time,
                        JobRow.cancel_requested.is_(False),
                        JobRow.attempt_count < JobRow.max_attempts,
                    )
                    .order_by(
                        JobRow.priority,
                        JobRow.available_at,
                        JobRow.created_at,
                        JobRow.id,
                    )
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if job is None:
                    return None
                mapping = session.get(SourceOrchestrationScannerJobRow, job.id)
                node = (
                    None
                    if mapping is None
                    else session.scalar(
                        select(SourceOrchestrationNodeRow)
                        .where(SourceOrchestrationNodeRow.node_id == mapping.node_id)
                        .with_for_update()
                    )
                )
                if (
                    mapping is None
                    or node is None
                    or node.lifecycle_state
                    not in {
                        OrchestrationNodeLifecycleState.QUEUED.value,
                        OrchestrationNodeLifecycleState.RETRY_PENDING.value,
                    }
                ):
                    raise SourceWorkerError
                job.status = JobStatus.LEASED.value
                job.leased_by = worker
                job.lease_token = str(self._tokens())
                job.heartbeat_at = operation_time
                job.lease_expires_at = operation_time + timedelta(seconds=lease_seconds)
                job.attempt_count += 1
                job.updated_at = operation_time
                node.lifecycle_state = OrchestrationNodeLifecycleState.QUEUED.value
                node.state_version += 1
                session.flush()
                return job_record_from_row(job)
        except SourceWorkerError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise SourceWorkerError from None

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise SourceWorkerError
        return value.astimezone(UTC)


class SourceOrchestrationWorkerCycle:
    """One short-lived lease/start/attempt/authority dispatch cycle."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        leasing: SourceMappedJobLeasingService,
        attempts: SourceScannerAttemptService,
        dispatcher: SourceAuthorityDispatcher,
        *,
        worker_id: str,
        lease_seconds: int = 30,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if not worker_id.strip() or len(worker_id.strip()) > 200:
            raise SourceWorkerError
        self._sessions = session_factory
        self._leasing = leasing
        self._execution = JobExecutionService(session_factory, clock=clock)
        self._attempts = attempts
        self._dispatcher = dispatcher
        self._worker_id = worker_id.strip()
        self._lease_seconds = lease_seconds

    def run_one(self) -> SourceWorkerCycleResult:
        leased = self._leasing.lease_next(
            worker_id=self._worker_id, lease_seconds=self._lease_seconds
        )
        if leased is None:
            return SourceWorkerCycleResult(SourceWorkerDisposition.IDLE, None, None, None)
        lease_token = leased.lease_token
        if lease_token is None:
            raise SourceWorkerError
        try:
            job = self._execution.start_job(
                leased.id, self._worker_id, lease_token
            )
            attempt = self._attempts.register_attempt(
                job_id=job.id,
                worker_id=self._worker_id,
                lease_token=lease_token,
            )
            authority = self._authority(job.id)
            self._dispatcher.dispatch(authority, job, attempt)
            self._validate_dispatch_completion(job.id, attempt.attempt_number)
            return SourceWorkerCycleResult(
                SourceWorkerDisposition.DISPATCHED,
                job.id,
                authority,
                attempt.attempt_number,
            )
        except SourceWorkerError:
            raise
        except Exception:
            raise SourceWorkerError from None

    def _authority(self, job_id: str) -> SourceAuthority:
        try:
            with self._sessions() as session:
                mapping = session.get(SourceOrchestrationScannerJobRow, job_id)
                if mapping is None:
                    raise SourceWorkerError
                return SourceAuthority(mapping.authority)
        except (SQLAlchemyError, ValueError):
            raise SourceWorkerError from None

    def _validate_dispatch_completion(self, job_id: str, attempt_number: int) -> None:
        try:
            with self._sessions() as session:
                job = session.get(JobRow, job_id)
                attempt = session.get(
                    SourceOrchestrationAttemptRow, (job_id, attempt_number)
                )
                if (
                    job is None
                    or attempt is None
                    or job.status
                    in {JobStatus.LEASED.value, JobStatus.RUNNING.value}
                    or attempt.acceptance_state not in {"ACCEPTED", "REJECTED"}
                    or attempt.finished_at is None
                ):
                    raise SourceWorkerError
        except SQLAlchemyError:
            raise SourceWorkerError from None

from __future__ import annotations

import time
from collections.abc import Callable
from uuid import UUID

from securescan.domain.enums import JobFailureCategory, JobStatus
from securescan.jobs.cancellation import (
    JobCancellationConflictError,
    JobCancellationError,
)
from securescan.jobs.execution import (
    JobCancellationRequestedError,
    JobExecutionService,
    JobLeaseExpiredError,
    JobLeaseOwnershipError,
    JobLeaseTokenMismatchError,
)
from securescan.jobs.failure_commit import (
    FailedToolExecutionCommit,
    JobFailureCommitRequest,
    JobFailureCommitResult,
    JobFailureCommitService,
)
from securescan.jobs.heartbeat import JobHeartbeatError
from securescan.jobs.leasing import JobLeasingService
from securescan.jobs.models import JobRecord
from securescan.jobs.repository import JobNotFoundError, JobStateConflictError
from securescan.jobs.result_commit import (
    JobResultCommitRequest,
    JobResultCommitResult,
    JobResultCommitService,
)
from securescan.worker.models import (
    ControllableWorkerAdapter,
    WorkerAdapter,
    WorkerAdapterResolutionError,
    WorkerAdapterResolver,
    WorkerCancellationAcknowledger,
    WorkerCancellationError,
    WorkerCommitError,
    WorkerCycleDisposition,
    WorkerCycleInvariantError,
    WorkerCycleResult,
    WorkerExecutionContractError,
    WorkerExecutionHandle,
    WorkerExecutionOutcome,
    WorkerFailedExecution,
    WorkerHeartbeatError,
    WorkerHeartbeatRenewer,
    WorkerJobReader,
    WorkerProcessTerminationError,
    WorkerSuccessfulExecution,
)

_LEASE_LOSS_ERRORS = (
    JobLeaseExpiredError,
    JobLeaseOwnershipError,
    JobLeaseTokenMismatchError,
    JobStateConflictError,
)
_CANCELLATION_RACE_ERRORS = (
    JobCancellationConflictError,
    *_LEASE_LOSS_ERRORS,
    JobNotFoundError,
)


class SingleJobWorkerCycle:
    def __init__(
        self,
        leasing_service: JobLeasingService,
        execution_service: JobExecutionService,
        result_commit_service: JobResultCommitService,
        failure_commit_service: JobFailureCommitService,
        adapter_resolver: WorkerAdapterResolver,
        job_reader: WorkerJobReader,
        cancellation_acknowledger: WorkerCancellationAcknowledger,
        heartbeat_renewer: WorkerHeartbeatRenewer,
        worker_id: str,
        lease_seconds: int = 30,
        heartbeat_interval_seconds: float = 10.0,
        execution_poll_interval_seconds: float = 0.25,
        termination_grace_seconds: float = 5.0,
        force_kill_grace_seconds: float = 2.0,
        monotonic_clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(worker_id, str):
            raise WorkerExecutionContractError("worker_id must be a string")
        normalized_worker_id = worker_id.strip()
        if not normalized_worker_id:
            raise WorkerExecutionContractError("worker_id must not be blank")
        if len(normalized_worker_id) > 200:
            raise WorkerExecutionContractError("worker_id must be 200 characters or fewer")
        if (
            not isinstance(lease_seconds, int)
            or isinstance(lease_seconds, bool)
            or not 1 <= lease_seconds <= 86_400
        ):
            raise WorkerExecutionContractError(
                "lease_seconds must be an integer from 1 through 86400"
            )
        self._validate_positive_interval(
            heartbeat_interval_seconds,
            "heartbeat_interval_seconds",
            maximum=float(lease_seconds),
            maximum_is_exclusive=True,
        )
        self._validate_positive_interval(
            execution_poll_interval_seconds,
            "execution_poll_interval_seconds",
            maximum=60,
        )
        self._validate_nonnegative_interval(
            termination_grace_seconds,
            "termination_grace_seconds",
        )
        self._validate_nonnegative_interval(
            force_kill_grace_seconds,
            "force_kill_grace_seconds",
        )

        self._leasing_service = leasing_service
        self._execution_service = execution_service
        self._result_commit_service = result_commit_service
        self._failure_commit_service = failure_commit_service
        self._adapter_resolver = adapter_resolver
        self._job_reader = job_reader
        self._cancellation_acknowledger = cancellation_acknowledger
        self._heartbeat_renewer = heartbeat_renewer
        self._worker_id = normalized_worker_id
        self._lease_seconds = lease_seconds
        self._heartbeat_interval_seconds = float(heartbeat_interval_seconds)
        self._execution_poll_interval_seconds = float(execution_poll_interval_seconds)
        self._termination_grace_seconds = float(termination_grace_seconds)
        self._force_kill_grace_seconds = float(force_kill_grace_seconds)
        self._monotonic_clock = monotonic_clock
        self._sleeper = sleeper

    def run_one_job(self) -> WorkerCycleResult:
        leased_job = self._leasing_service.lease_next_job(
            worker_id=self._worker_id,
            lease_seconds=self._lease_seconds,
        )
        if leased_job is None:
            return WorkerCycleResult(
                disposition=WorkerCycleDisposition.IDLE,
                job_id=None,
                run_id=None,
                attempt_number=None,
                tool_execution_id=None,
            )

        lease_token = self._validate_leased_job(leased_job)
        try:
            started_job = self._execution_service.start_job(
                job_id=leased_job.id,
                worker_id=self._worker_id,
                lease_token=lease_token,
            )
        except JobCancellationRequestedError:
            return self._acknowledge_cancellation(leased_job, lease_token)
        except _LEASE_LOSS_ERRORS:
            return self._classify_lost_lease(leased_job)
        except JobNotFoundError as exc:
            raise WorkerCycleInvariantError(
                "A leased job disappeared before execution started"
            ) from exc
        self._validate_started_job(leased_job, started_job, lease_token)

        observed_result = self._observe_current_job(started_job, lease_token)
        if observed_result is not None:
            return observed_result

        try:
            adapter = self._resolve_adapter(started_job.adapter_id)
        except WorkerAdapterResolutionError:
            observed_result = self._observe_current_job(started_job, lease_token)
            if observed_result is not None:
                return observed_result
            return self._commit_failure(
                started_job,
                self._adapter_resolution_failure(),
            )

        if isinstance(adapter, ControllableWorkerAdapter):
            controlled_result = self._execute_controlled(
                adapter,
                started_job,
                lease_token,
            )
            if isinstance(controlled_result, WorkerCycleResult):
                return controlled_result
            outcome = controlled_result
        else:
            # Synchronous adapters are intentionally not moved to a helper thread.
            # Their execute() call cannot be interrupted while it is blocking.
            try:
                outcome = adapter.execute(started_job)
            except WorkerExecutionContractError:
                observed_result = self._observe_current_job(started_job, lease_token)
                if observed_result is not None:
                    return observed_result
                raise
            except Exception:
                observed_result = self._observe_current_job(started_job, lease_token)
                if observed_result is not None:
                    return observed_result
                return self._commit_failure(
                    started_job,
                    self._execution_exception_failure(adapter),
                )

        observed_result = self._observe_current_job(started_job, lease_token)
        if observed_result is not None:
            return observed_result

        if isinstance(outcome, WorkerSuccessfulExecution):
            return self._commit_success(started_job, outcome)
        if isinstance(outcome, WorkerFailedExecution):
            return self._commit_failure(started_job, outcome.tool_execution)
        raise WorkerExecutionContractError(
            "Worker adapter returned an unsupported execution outcome"
        )

    def _execute_controlled(
        self,
        adapter: ControllableWorkerAdapter,
        started_job: JobRecord,
        lease_token: str,
    ) -> WorkerExecutionOutcome | WorkerCycleResult:
        try:
            handle = adapter.start(started_job)
        except Exception:
            observed_result = self._observe_current_job(started_job, lease_token)
            if observed_result is not None:
                return observed_result
            return self._commit_failure(
                started_job,
                self._execution_exception_failure(adapter),
            )
        if not isinstance(handle, WorkerExecutionHandle):
            observed_result = self._observe_current_job(started_job, lease_token)
            if observed_result is not None:
                return observed_result
            raise WorkerExecutionContractError(
                "Controlled adapter returned an incompatible execution handle"
            )

        next_heartbeat = self._monotonic_clock() + self._heartbeat_interval_seconds
        try:
            while True:
                try:
                    outcome = handle.poll()
                    if outcome is not None and not isinstance(
                        outcome,
                        (WorkerSuccessfulExecution, WorkerFailedExecution),
                    ):
                        raise WorkerExecutionContractError(
                            "Controlled worker returned an unsupported execution outcome"
                        )
                except Exception:
                    self._stop_controlled_execution(handle)
                    observed_result = self._observe_current_job(
                        started_job,
                        lease_token,
                    )
                    if observed_result is not None:
                        return observed_result
                    return self._commit_failure(
                        started_job,
                        self._execution_exception_failure(adapter),
                    )

                if outcome is not None:
                    return outcome

                try:
                    observed = self._read_current_job(started_job)
                except WorkerCycleInvariantError:
                    self._stop_controlled_execution(handle)
                    raise
                disposition = self._classify_observed_job(
                    observed,
                    started_job,
                    lease_token,
                )
                if disposition is not None:
                    self._stop_controlled_execution(handle)
                    if (
                        disposition is WorkerCycleDisposition.CANCELLED
                        and observed.status is not JobStatus.CANCELLED
                    ):
                        return self._acknowledge_cancellation(
                            started_job,
                            lease_token,
                        )
                    return self._uncommitted_result(
                        disposition,
                        started_job,
                    )

                current_monotonic = self._monotonic_clock()
                if current_monotonic >= next_heartbeat:
                    heartbeat_result = self._renew_heartbeat(
                        handle,
                        started_job,
                        lease_token,
                    )
                    if heartbeat_result is not None:
                        return heartbeat_result
                    next_heartbeat = self._monotonic_clock() + self._heartbeat_interval_seconds

                self._sleeper(self._execution_poll_interval_seconds)
        finally:
            try:
                handle.close()
            except WorkerProcessTerminationError:
                raise
            except Exception as exc:
                raise WorkerProcessTerminationError(
                    "The controlled scanner process could not be cleaned up"
                ) from exc

    def _renew_heartbeat(
        self,
        handle: WorkerExecutionHandle,
        started_job: JobRecord,
        lease_token: str,
    ) -> WorkerCycleResult | None:
        try:
            renewed = self._heartbeat_renewer.renew_lease(
                job_id=started_job.id,
                worker_id=self._worker_id,
                lease_token=lease_token,
                lease_seconds=self._lease_seconds,
            )
        except JobCancellationRequestedError:
            self._stop_controlled_execution(handle)
            return self._acknowledge_cancellation(started_job, lease_token)
        except _LEASE_LOSS_ERRORS:
            self._stop_controlled_execution(handle)
            return self._classify_lost_lease(started_job)
        except JobNotFoundError as exc:
            self._stop_controlled_execution(handle)
            raise WorkerCycleInvariantError(
                "A leased job disappeared during heartbeat renewal"
            ) from exc
        except JobHeartbeatError as exc:
            self._stop_controlled_execution(handle)
            raise WorkerHeartbeatError(
                "The worker could not renew its scanner execution lease"
            ) from exc
        except Exception as exc:
            self._stop_controlled_execution(handle)
            raise WorkerHeartbeatError(
                "The worker could not renew its scanner execution lease"
            ) from exc

        if (
            renewed.id != started_job.id
            or renewed.run_id != started_job.run_id
            or renewed.adapter_id != started_job.adapter_id
            or renewed.attempt_count != started_job.attempt_count
            or renewed.leased_by != self._worker_id
            or renewed.lease_token != lease_token
            or renewed.status is not JobStatus.RUNNING
        ):
            self._stop_controlled_execution(handle)
            raise WorkerCycleInvariantError(
                "Heartbeat renewal returned inconsistent durable job state"
            )
        return None

    def _stop_controlled_execution(
        self,
        handle: WorkerExecutionHandle,
    ) -> None:
        termination_error: Exception | None = None
        try:
            handle.terminate()
        except Exception as exc:
            termination_error = exc
        stopped, poll_error = self._poll_for_stopped_handle(
            handle,
            self._termination_grace_seconds,
        )
        termination_error = poll_error or termination_error
        if stopped:
            return

        try:
            handle.kill()
        except Exception as exc:
            termination_error = exc
        stopped, poll_error = self._poll_for_stopped_handle(
            handle,
            self._force_kill_grace_seconds,
        )
        termination_error = poll_error or termination_error
        if stopped:
            return
        error = WorkerProcessTerminationError(
            "The controlled scanner process could not be confirmed stopped"
        )
        if termination_error is not None:
            raise error from termination_error
        raise error

    def _poll_for_stopped_handle(
        self,
        handle: WorkerExecutionHandle,
        grace_seconds: float,
    ) -> tuple[bool, Exception | None]:
        deadline = self._monotonic_clock() + grace_seconds
        poll_error: Exception | None = None
        while True:
            try:
                if handle.poll() is not None:
                    return True, poll_error
            except Exception as exc:
                poll_error = exc
            current = self._monotonic_clock()
            if current >= deadline:
                return False, poll_error
            self._sleeper(
                min(
                    self._execution_poll_interval_seconds,
                    deadline - current,
                )
            )

    def _observe_current_job(
        self,
        active_job: JobRecord,
        lease_token: str,
    ) -> WorkerCycleResult | None:
        observed = self._read_current_job(active_job)
        disposition = self._classify_observed_job(
            observed,
            active_job,
            lease_token,
        )
        if (
            disposition is WorkerCycleDisposition.CANCELLED
            and observed.status is not JobStatus.CANCELLED
        ):
            return self._acknowledge_cancellation(active_job, lease_token)
        if disposition is None:
            return None
        return self._uncommitted_result(disposition, active_job)

    def _classify_observed_job(
        self,
        observed: JobRecord,
        active_job: JobRecord,
        lease_token: str,
    ) -> WorkerCycleDisposition | None:
        if observed.attempt_count != active_job.attempt_count:
            return WorkerCycleDisposition.LEASE_LOST
        if observed.status is JobStatus.CANCELLED:
            return WorkerCycleDisposition.CANCELLED
        if observed.status not in {JobStatus.LEASED, JobStatus.RUNNING}:
            return WorkerCycleDisposition.LEASE_LOST
        if observed.leased_by != self._worker_id or observed.lease_token != lease_token:
            return WorkerCycleDisposition.LEASE_LOST
        if observed.cancel_requested:
            return WorkerCycleDisposition.CANCELLED
        return None

    def _read_current_job(self, active_job: JobRecord) -> JobRecord:
        try:
            observed = self._job_reader.get_job(active_job.id)
        except JobNotFoundError as exc:
            raise WorkerCycleInvariantError(
                "A leased job disappeared during worker execution"
            ) from exc
        if observed is None:
            raise WorkerCycleInvariantError("A leased job disappeared during worker execution")
        if (
            observed.id != active_job.id
            or observed.run_id != active_job.run_id
            or observed.adapter_id != active_job.adapter_id
        ):
            raise WorkerCycleInvariantError("Job reader returned inconsistent durable job identity")
        return observed

    def _acknowledge_cancellation(
        self,
        active_job: JobRecord,
        lease_token: str,
    ) -> WorkerCycleResult:
        try:
            cancelled = self._cancellation_acknowledger.acknowledge_cancellation(
                job_id=active_job.id,
                worker_id=self._worker_id,
                lease_token=lease_token,
            )
        except _CANCELLATION_RACE_ERRORS:
            return self._classify_lost_lease(active_job)
        except JobCancellationError as exc:
            raise WorkerCancellationError(
                "The worker could not acknowledge job cancellation"
            ) from exc
        except Exception as exc:
            raise WorkerCancellationError(
                "The worker could not acknowledge job cancellation"
            ) from exc

        if (
            cancelled.id != active_job.id
            or cancelled.run_id != active_job.run_id
            or cancelled.attempt_count != active_job.attempt_count
            or cancelled.status is not JobStatus.CANCELLED
        ):
            raise WorkerCycleInvariantError(
                "Cancellation acknowledgement returned inconsistent job state"
            )
        return self._uncommitted_result(
            WorkerCycleDisposition.CANCELLED,
            active_job,
        )

    def _classify_lost_lease(
        self,
        active_job: JobRecord,
    ) -> WorkerCycleResult:
        observed = self._read_current_job(active_job)
        disposition = (
            WorkerCycleDisposition.CANCELLED
            if observed.status is JobStatus.CANCELLED
            else WorkerCycleDisposition.LEASE_LOST
        )
        return self._uncommitted_result(disposition, active_job)

    @staticmethod
    def _uncommitted_result(
        disposition: WorkerCycleDisposition,
        active_job: JobRecord,
    ) -> WorkerCycleResult:
        return WorkerCycleResult(
            disposition=disposition,
            job_id=active_job.id,
            run_id=active_job.run_id,
            attempt_number=active_job.attempt_count,
            tool_execution_id=None,
        )

    def _validate_leased_job(self, job: JobRecord) -> str:
        if job.status is not JobStatus.LEASED:
            raise WorkerCycleInvariantError("Leasing service returned a non-leased job")
        if job.leased_by is None:
            raise WorkerCycleInvariantError("Leased job has no worker ownership")
        if job.leased_by != self._worker_id:
            raise WorkerCycleInvariantError("Leased job belongs to a different worker")
        lease_token = job.lease_token
        if not self._is_canonical_uuid(lease_token):
            raise WorkerCycleInvariantError("Leased job has no valid lease token")
        if job.attempt_count < 1:
            raise WorkerCycleInvariantError("Leased job has an invalid attempt number")
        assert lease_token is not None
        return lease_token

    def _validate_started_job(
        self,
        leased_job: JobRecord,
        started_job: JobRecord,
        lease_token: str,
    ) -> None:
        if (
            started_job.id != leased_job.id
            or started_job.run_id != leased_job.run_id
            or started_job.adapter_id != leased_job.adapter_id
            or started_job.attempt_count != leased_job.attempt_count
        ):
            raise WorkerCycleInvariantError("Execution service changed durable job identity")
        if started_job.status is not JobStatus.RUNNING:
            raise WorkerCycleInvariantError("Execution service did not start the leased job")
        if started_job.leased_by != self._worker_id:
            raise WorkerCycleInvariantError("Execution service changed worker ownership")
        if started_job.lease_token != lease_token:
            raise WorkerCycleInvariantError("Execution service changed lease ownership")

    def _resolve_adapter(
        self,
        adapter_id: str,
    ) -> WorkerAdapter | ControllableWorkerAdapter:
        try:
            adapter = self._adapter_resolver.resolve(adapter_id)
            if not isinstance(
                adapter,
                (WorkerAdapter, ControllableWorkerAdapter),
            ):
                raise TypeError("resolver returned an incompatible adapter")
            if not isinstance(adapter.adapter_id, str) or adapter.adapter_id != adapter_id:
                raise ValueError("resolver returned the wrong adapter")
            if not isinstance(adapter.adapter_version, str) or not adapter.adapter_version.strip():
                raise ValueError("resolver returned an invalid adapter version")
            if not isinstance(adapter.tool_version, str) or not adapter.tool_version.strip():
                raise ValueError("resolver returned an invalid tool version")
        except Exception as exc:
            raise WorkerAdapterResolutionError(
                "The configured worker adapter could not be resolved"
            ) from exc
        return adapter

    def _commit_success(
        self,
        started_job: JobRecord,
        outcome: WorkerSuccessfulExecution,
    ) -> WorkerCycleResult:
        lease_token = self._require_started_token(started_job)
        request = JobResultCommitRequest(
            job_id=started_job.id,
            worker_id=self._worker_id,
            lease_token=lease_token,
            final_status=outcome.final_status,
            report_json=outcome.report_json,
            tool_execution=outcome.tool_execution,
        )
        try:
            result = self._result_commit_service.commit_result(request)
        except JobCancellationRequestedError:
            return self._acknowledge_cancellation(started_job, lease_token)
        except _LEASE_LOSS_ERRORS:
            return self._classify_lost_lease(started_job)
        except JobNotFoundError as exc:
            raise WorkerCycleInvariantError(
                "A leased job disappeared during result commitment"
            ) from exc
        except Exception as exc:
            raise WorkerCommitError("The worker could not commit scanner results") from exc

        self._validate_commit_identity(started_job, result)
        if result.job.status is not outcome.final_status:
            raise WorkerCycleInvariantError(
                "Result commitment returned an inconsistent terminal status"
            )
        tool_execution_id = self._require_execution_id(result.tool_execution_id)
        disposition = {
            JobStatus.SUCCEEDED: WorkerCycleDisposition.SUCCEEDED,
            JobStatus.PARTIAL: WorkerCycleDisposition.PARTIAL,
        }[outcome.final_status]
        return WorkerCycleResult(
            disposition=disposition,
            job_id=result.job.id,
            run_id=result.run_id,
            attempt_number=result.attempt_number,
            tool_execution_id=tool_execution_id,
        )

    def _commit_failure(
        self,
        started_job: JobRecord,
        tool_execution: FailedToolExecutionCommit,
    ) -> WorkerCycleResult:
        lease_token = self._require_started_token(started_job)
        request = JobFailureCommitRequest(
            job_id=started_job.id,
            worker_id=self._worker_id,
            lease_token=lease_token,
            tool_execution=tool_execution,
        )
        try:
            result = self._failure_commit_service.commit_failure(request)
        except JobCancellationRequestedError:
            return self._acknowledge_cancellation(started_job, lease_token)
        except _LEASE_LOSS_ERRORS:
            return self._classify_lost_lease(started_job)
        except JobNotFoundError as exc:
            raise WorkerCycleInvariantError(
                "A leased job disappeared during failure commitment"
            ) from exc
        except Exception as exc:
            raise WorkerCommitError("The worker could not commit scanner failure") from exc

        self._validate_commit_identity(started_job, result)
        tool_execution_id = self._require_execution_id(result.tool_execution_id)
        if result.retry_scheduled:
            if result.job.status is not JobStatus.RETRY_PENDING:
                raise WorkerCycleInvariantError(
                    "Failure commitment returned an inconsistent retry status"
                )
            disposition = WorkerCycleDisposition.RETRY_PENDING
        elif result.job.status is JobStatus.FAILED:
            disposition = WorkerCycleDisposition.FAILED
        else:
            raise WorkerCycleInvariantError(
                "Failure commitment returned an inconsistent terminal status"
            )

        return WorkerCycleResult(
            disposition=disposition,
            job_id=result.job.id,
            run_id=result.run_id,
            attempt_number=result.attempt_number,
            tool_execution_id=tool_execution_id,
        )

    @staticmethod
    def _validate_commit_identity(
        started_job: JobRecord,
        result: JobResultCommitResult | JobFailureCommitResult,
    ) -> None:
        if (
            result.job.id != started_job.id
            or result.run_id != started_job.run_id
            or result.attempt_number != started_job.attempt_count
        ):
            raise WorkerCycleInvariantError("Commit service changed durable job identity")

    @staticmethod
    def _is_canonical_uuid(value: str | None) -> bool:
        if value is None or len(value) != 36 or value != value.lower():
            return False
        try:
            return str(UUID(value)) == value
        except ValueError:
            return False

    @staticmethod
    def _require_started_token(job: JobRecord) -> str:
        if not SingleJobWorkerCycle._is_canonical_uuid(job.lease_token):
            raise WorkerCycleInvariantError("Running job has no valid lease token")
        assert job.lease_token is not None
        return job.lease_token

    @staticmethod
    def _require_execution_id(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise WorkerCycleInvariantError("Commit service returned no tool execution identity")
        return value

    @staticmethod
    def _adapter_resolution_failure() -> FailedToolExecutionCommit:
        return FailedToolExecutionCommit(
            tool_version="unavailable",
            adapter_version="unavailable",
            outcome="adapter_resolution_failed",
            exit_code=None,
            duration_ms=0,
            warning_json=[],
            error="The configured scanner adapter is unavailable.",
            failure_category=JobFailureCategory.NON_RETRYABLE_POLICY,
            retryable=False,
        )

    @staticmethod
    def _execution_exception_failure(
        adapter: WorkerAdapter | ControllableWorkerAdapter,
    ) -> FailedToolExecutionCommit:
        return FailedToolExecutionCommit(
            tool_version=adapter.tool_version,
            adapter_version=adapter.adapter_version,
            outcome="worker_execution_exception",
            exit_code=None,
            duration_ms=0,
            warning_json=[],
            error="The worker encountered an unexpected scanner execution error.",
            failure_category=JobFailureCategory.WORKER_CRASH,
            retryable=True,
        )

    @staticmethod
    def _validate_positive_interval(
        value: float,
        field_name: str,
        *,
        maximum: float,
        maximum_is_exclusive: bool = False,
    ) -> None:
        valid_number = isinstance(value, (int, float)) and not isinstance(value, bool)
        outside_maximum = (
            (value >= maximum if maximum_is_exclusive else value > maximum)
            if valid_number
            else True
        )
        if not valid_number or not value > 0 or outside_maximum:
            comparison = "less than" if maximum_is_exclusive else "at most"
            raise WorkerExecutionContractError(
                f"{field_name} must be greater than zero and {comparison} {maximum:g}"
            )

    @staticmethod
    def _validate_nonnegative_interval(
        value: float,
        field_name: str,
    ) -> None:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 300:
            raise WorkerExecutionContractError(f"{field_name} must be from zero through 300")

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
)
from securescan.jobs import (
    FailedToolExecutionCommit,
    JobCancellationRequestedError,
    JobFailureCommitRequest,
    JobFailureCommitResult,
    JobHeartbeatError,
    JobLeaseExpiredError,
    JobRecord,
    JobResultCommitRequest,
    JobResultCommitResult,
    ToolExecutionCommit,
)
from securescan.worker import (
    SingleJobWorkerCycle,
    WorkerCommitError,
    WorkerCycleDisposition,
    WorkerCycleInvariantError,
    WorkerFailedExecution,
    WorkerHeartbeatError,
    WorkerProcessTerminationError,
    WorkerSuccessfulExecution,
)

WORKER_ID = "worker-cycle-1"
JOB_ID = str(UUID("00000000-0000-4000-8000-000000000101"))
RUN_ID = str(UUID("00000000-0000-4000-8000-000000000102"))
OTHER_JOB_ID = str(UUID("00000000-0000-4000-8000-000000000103"))
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000104"))
OTHER_LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000105"))
NOW = datetime(2044, 1, 2, 3, 4, 5, tzinfo=UTC)


def _job(
    status: JobStatus,
    *,
    job_id: str = JOB_ID,
    leased_by: str | None = WORKER_ID,
    lease_token: str | None = LEASE_TOKEN,
    attempt_count: int = 2,
) -> JobRecord:
    return JobRecord(
        id=job_id,
        run_id=RUN_ID,
        adapter_id="fake-scanner",
        status=status,
        priority=100,
        attempt_count=attempt_count,
        max_attempts=3,
        available_at=NOW,
        leased_by=leased_by,
        lease_expires_at=NOW + timedelta(seconds=30),
        heartbeat_at=NOW,
        cancel_requested=False,
        idempotency_key="a" * 64,
        payload_json={
            "adapter_id": "payload-controlled-adapter",
            "job_id": OTHER_JOB_ID,
            "run_id": OTHER_JOB_ID,
            "attempt_number": 999,
        },
        last_error=None,
        created_at=NOW,
        updated_at=NOW,
        started_at=NOW if status is JobStatus.RUNNING else None,
        finished_at=None,
        lease_token=lease_token,
        cancel_requested_at=None,
    )


def _successful_outcome(
    final_status: JobStatus = JobStatus.SUCCEEDED,
) -> WorkerSuccessfulExecution:
    return WorkerSuccessfulExecution(
        final_status=final_status,
        report_json={"schema_version": "1.0.0", "run_id": RUN_ID},
        tool_execution=ToolExecutionCommit(
            tool_version="7.8.9",
            adapter_version="1.2.3",
            outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
            exit_code=0,
            duration_ms=25,
            warning_json=[],
        ),
    )


def _failed_outcome(*, retryable: bool) -> WorkerFailedExecution:
    return WorkerFailedExecution(
        tool_execution=FailedToolExecutionCommit(
            tool_version="7.8.9",
            adapter_version="1.2.3",
            outcome=ExecutionOutcome.INTERNAL_ERROR.value,
            exit_code=1,
            duration_ms=25,
            warning_json=[],
            error="Controlled scanner failure.",
            failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
            retryable=retryable,
        )
    )


def _result_commit_result(
    status: JobStatus = JobStatus.SUCCEEDED,
    *,
    job_id: str = JOB_ID,
    attempt_number: int = 2,
) -> JobResultCommitResult:
    return JobResultCommitResult(
        job=replace(
            _job(JobStatus.RUNNING),
            id=job_id,
            status=status,
            leased_by=None,
            lease_token=None,
            lease_expires_at=None,
            finished_at=NOW,
        ),
        run_id=RUN_ID,
        tool_execution_id="result-execution-1",
        attempt_number=attempt_number,
        report_json={"schema_version": "1.0.0", "run_id": RUN_ID},
    )


def _failure_commit_result(
    *,
    retry_scheduled: bool,
) -> JobFailureCommitResult:
    status = JobStatus.RETRY_PENDING if retry_scheduled else JobStatus.FAILED
    return JobFailureCommitResult(
        job=replace(
            _job(JobStatus.RUNNING),
            status=status,
            leased_by=None,
            lease_token=None,
            lease_expires_at=None,
            finished_at=None if retry_scheduled else NOW,
        ),
        run_id=RUN_ID,
        tool_execution_id="failure-execution-1",
        attempt_number=2,
        retry_scheduled=retry_scheduled,
        retry_delay_seconds=5 if retry_scheduled else None,
        failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
    )


class _LeasingService:
    def __init__(self, events: list[str], job: JobRecord | None) -> None:
        self.events = events
        self.job = job
        self.calls: list[tuple[str, int]] = []

    def lease_next_job(self, *, worker_id: str, lease_seconds: int) -> JobRecord | None:
        self.events.append("lease")
        self.calls.append((worker_id, lease_seconds))
        return self.job


class _ExecutionService:
    def __init__(
        self,
        events: list[str],
        job: JobRecord,
        error: Exception | None = None,
    ) -> None:
        self.events = events
        self.job = job
        self.error = error
        self.calls: list[tuple[str, str, str]] = []

    def start_job(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> JobRecord:
        self.events.append("start")
        self.calls.append((job_id, worker_id, lease_token))
        if self.error is not None:
            raise self.error
        return self.job


class _JobReader:
    def __init__(self, events: list[str], records: list[JobRecord]) -> None:
        self.events = events
        self.records = records
        self.job_ids: list[str] = []

    def get_job(self, job_id: str) -> JobRecord:
        self.events.append("observe")
        self.job_ids.append(job_id)
        if len(self.records) > 1:
            return self.records.pop(0)
        return self.records[0]


class _CancellationAcknowledger:
    def __init__(
        self,
        events: list[str],
        result: JobRecord,
        error: Exception | None = None,
    ) -> None:
        self.events = events
        self.result = result
        self.error = error
        self.calls: list[tuple[str, str, str]] = []

    def acknowledge_cancellation(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> JobRecord:
        self.events.append("acknowledge")
        self.calls.append((job_id, worker_id, lease_token))
        if self.error is not None:
            raise self.error
        return self.result


class _HeartbeatRenewer:
    def __init__(
        self,
        events: list[str],
        result: JobRecord,
        error: Exception | None = None,
    ) -> None:
        self.events = events
        self.result = result
        self.error = error
        self.calls: list[tuple[str, str, str, int]] = []

    def renew_lease(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        lease_seconds: int = 30,
    ) -> JobRecord:
        self.events.append("heartbeat")
        self.calls.append((job_id, worker_id, lease_token, lease_seconds))
        if self.error is not None:
            raise self.error
        return self.result


class _ResultCommitService:
    def __init__(
        self,
        events: list[str],
        result: JobResultCommitResult,
        error: Exception | None = None,
    ) -> None:
        self.events = events
        self.result = result
        self.error = error
        self.requests: list[JobResultCommitRequest] = []

    def commit_result(self, request: JobResultCommitRequest) -> JobResultCommitResult:
        self.events.append("result_commit")
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.result


class _FailureCommitService:
    def __init__(
        self,
        events: list[str],
        result: JobFailureCommitResult,
        error: Exception | None = None,
    ) -> None:
        self.events = events
        self.result = result
        self.error = error
        self.requests: list[JobFailureCommitRequest] = []

    def commit_failure(self, request: JobFailureCommitRequest) -> JobFailureCommitResult:
        self.events.append("failure_commit")
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.result


class _Adapter:
    adapter_id = "fake-scanner"
    adapter_version = "1.2.3"
    tool_version = "7.8.9"

    def __init__(
        self,
        events: list[str],
        outcome: object,
        error: Exception | None = None,
    ) -> None:
        self.events = events
        self.outcome = outcome
        self.error = error
        self.jobs: list[JobRecord] = []

    def execute(self, job: JobRecord):
        self.events.append("execute")
        self.jobs.append(job)
        if self.error is not None:
            raise self.error
        return self.outcome


class _FakeTime:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class _ManagedHandle:
    def __init__(
        self,
        events: list[str],
        polls: list[object],
        *,
        stop_after_terminate: bool = True,
        stop_after_kill: bool = True,
    ) -> None:
        self.events = events
        self.polls = polls
        self.stop_after_terminate = stop_after_terminate
        self.stop_after_kill = stop_after_kill
        self.terminated = False
        self.killed = False
        self.closed = False
        self.stop_outcome = _failed_outcome(retryable=True)

    def poll(self):
        self.events.append("poll")
        if self.killed and self.stop_after_kill:
            return self.stop_outcome
        if self.terminated and self.stop_after_terminate:
            return self.stop_outcome
        returned = self.polls.pop(0) if len(self.polls) > 1 else self.polls[0]
        if isinstance(returned, Exception):
            raise returned
        return returned

    def terminate(self) -> None:
        self.events.append("terminate")
        self.terminated = True

    def kill(self) -> None:
        self.events.append("kill")
        self.killed = True

    def close(self) -> None:
        self.events.append("close")
        self.closed = True


class _ManagedAdapter(_Adapter):
    def __init__(
        self,
        events: list[str],
        handle: _ManagedHandle,
    ) -> None:
        super().__init__(events, _successful_outcome())
        self.handle = handle
        self.started_jobs: list[JobRecord] = []

    def start(self, job: JobRecord) -> _ManagedHandle:
        self.events.append("adapter_start")
        self.started_jobs.append(job)
        return self.handle


class _Resolver:
    def __init__(
        self,
        events: list[str],
        adapter: _Adapter | _ManagedAdapter,
        error: Exception | None = None,
    ) -> None:
        self.events = events
        self.adapter = adapter
        self.error = error
        self.adapter_ids: list[str] = []

    def resolve(self, adapter_id: str) -> _Adapter | _ManagedAdapter:
        self.events.append("resolve")
        self.adapter_ids.append(adapter_id)
        if self.error is not None:
            raise self.error
        return self.adapter


@dataclass(frozen=True, slots=True)
class _Harness:
    cycle: SingleJobWorkerCycle
    events: list[str]
    leasing: _LeasingService
    execution: _ExecutionService
    result_commit: _ResultCommitService
    failure_commit: _FailureCommitService
    resolver: _Resolver
    adapter: _Adapter | _ManagedAdapter
    reader: _JobReader
    cancellation: _CancellationAcknowledger
    heartbeat: _HeartbeatRenewer


def _harness(
    *,
    leased_job: JobRecord | None = None,
    started_job: JobRecord | None = None,
    outcome: object | None = None,
    result: JobResultCommitResult | None = None,
    failure_result: JobFailureCommitResult | None = None,
    resolver_error: Exception | None = None,
    adapter_error: Exception | None = None,
    execution_error: Exception | None = None,
    result_error: Exception | None = None,
    observations: list[JobRecord] | None = None,
    cancellation_result: JobRecord | None = None,
    heartbeat_error: Exception | None = None,
    managed_handle: _ManagedHandle | None = None,
    fake_time: _FakeTime | None = None,
) -> _Harness:
    events: list[str] = []
    leased = leased_job if leased_job is not None else _job(JobStatus.LEASED)
    started = started_job if started_job is not None else _job(JobStatus.RUNNING)
    adapter: _Adapter | _ManagedAdapter
    if managed_handle is None:
        adapter = _Adapter(
            events,
            outcome if outcome is not None else _successful_outcome(),
            adapter_error,
        )
    else:
        managed_handle.events = events
        adapter = _ManagedAdapter(events, managed_handle)
    resolver = _Resolver(events, adapter, resolver_error)
    leasing = _LeasingService(events, leased)
    execution = _ExecutionService(events, started, execution_error)
    reader = _JobReader(
        events,
        observations if observations is not None else [_job(JobStatus.RUNNING)],
    )
    cancellation = _CancellationAcknowledger(
        events,
        (
            cancellation_result
            if cancellation_result is not None
            else replace(
                started,
                status=JobStatus.CANCELLED,
                leased_by=None,
                lease_token=None,
                lease_expires_at=None,
                finished_at=NOW,
            )
        ),
    )
    heartbeat = _HeartbeatRenewer(
        events,
        started,
        heartbeat_error,
    )
    result_commit = _ResultCommitService(
        events,
        result if result is not None else _result_commit_result(),
        result_error,
    )
    failure_commit = _FailureCommitService(
        events,
        (
            failure_result
            if failure_result is not None
            else _failure_commit_result(retry_scheduled=False)
        ),
    )
    cycle = SingleJobWorkerCycle(
        leasing,
        execution,
        result_commit,
        failure_commit,
        resolver,
        reader,
        cancellation,
        heartbeat,
        worker_id=f" {WORKER_ID} ",
        lease_seconds=45,
        heartbeat_interval_seconds=1,
        execution_poll_interval_seconds=0.5,
        termination_grace_seconds=1,
        force_kill_grace_seconds=1,
        monotonic_clock=(fake_time.monotonic if fake_time is not None else lambda: 0.0),
        sleeper=fake_time.sleep if fake_time is not None else lambda _seconds: None,
    )
    return _Harness(
        cycle,
        events,
        leasing,
        execution,
        result_commit,
        failure_commit,
        resolver,
        adapter,
        reader,
        cancellation,
        heartbeat,
    )


def test_idle_cycle_returns_without_starting_or_executing() -> None:
    harness = _harness()
    harness.leasing.job = None

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.IDLE
    assert result.job_id is None
    assert result.run_id is None
    assert result.attempt_number is None
    assert result.tool_execution_id is None
    assert harness.events == ["lease"]


def test_successful_execution_commits_succeeded_result() -> None:
    harness = _harness(outcome=_successful_outcome())

    result = harness.cycle.run_one_job()

    assert harness.events == [
        "lease",
        "start",
        "observe",
        "resolve",
        "execute",
        "observe",
        "result_commit",
    ]
    assert harness.leasing.calls == [(WORKER_ID, 45)]
    assert harness.resolver.adapter_ids == ["fake-scanner"]
    assert harness.adapter.jobs == [_job(JobStatus.RUNNING)]
    request = harness.result_commit.requests[0]
    assert request.job_id == JOB_ID
    assert request.worker_id == WORKER_ID
    assert request.lease_token == LEASE_TOKEN
    assert harness.adapter.jobs[0].id == JOB_ID
    assert harness.adapter.jobs[0].run_id == RUN_ID
    assert harness.adapter.jobs[0].attempt_count == 2
    assert result.disposition is WorkerCycleDisposition.SUCCEEDED
    assert result.job_id == JOB_ID
    assert result.run_id == RUN_ID
    assert result.attempt_number == 2
    assert result.tool_execution_id == "result-execution-1"
    assert harness.failure_commit.requests == []


def test_partial_execution_commits_partial_result() -> None:
    harness = _harness(
        outcome=_successful_outcome(JobStatus.PARTIAL),
        result=_result_commit_result(JobStatus.PARTIAL),
    )

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.PARTIAL
    assert harness.result_commit.requests[0].final_status is JobStatus.PARTIAL
    assert harness.failure_commit.requests == []


def test_retryable_failure_returns_retry_pending() -> None:
    harness = _harness(
        outcome=_failed_outcome(retryable=True),
        failure_result=_failure_commit_result(retry_scheduled=True),
    )

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.RETRY_PENDING
    assert harness.events == [
        "lease",
        "start",
        "observe",
        "resolve",
        "execute",
        "observe",
        "failure_commit",
    ]
    assert harness.result_commit.requests == []
    assert len(harness.failure_commit.requests) == 1


def test_permanent_failure_returns_failed() -> None:
    harness = _harness(outcome=_failed_outcome(retryable=False))

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.FAILED
    assert result.tool_execution_id == "failure-execution-1"
    assert harness.result_commit.requests == []
    assert len(harness.failure_commit.requests) == 1


def test_leased_job_without_token_raises_invariant_error() -> None:
    harness = _harness(
        leased_job=_job(JobStatus.LEASED, lease_token=None),
    )

    with pytest.raises(WorkerCycleInvariantError) as error:
        harness.cycle.run_one_job()

    assert LEASE_TOKEN not in str(error.value)
    assert harness.events == ["lease"]
    assert harness.execution.calls == []
    assert harness.resolver.adapter_ids == []
    assert harness.result_commit.requests == []
    assert harness.failure_commit.requests == []


def test_adapter_resolution_failure_commits_safe_nonretryable_failure() -> None:
    sensitive_text = "resolver-secret credential=do-not-persist"
    harness = _harness(resolver_error=RuntimeError(sensitive_text))

    result = harness.cycle.run_one_job()

    request = harness.failure_commit.requests[0]
    failure = request.tool_execution
    assert result.disposition is WorkerCycleDisposition.FAILED
    assert harness.events == [
        "lease",
        "start",
        "observe",
        "resolve",
        "observe",
        "failure_commit",
    ]
    assert failure.outcome == "adapter_resolution_failed"
    assert failure.failure_category is JobFailureCategory.NON_RETRYABLE_POLICY
    assert failure.retryable is False
    assert sensitive_text not in failure.error
    assert sensitive_text not in failure.outcome
    assert harness.result_commit.requests == []


def test_unexpected_adapter_exception_commits_safe_retryable_failure() -> None:
    sensitive_text = "scanner-secret=/private/repository"
    harness = _harness(
        adapter_error=RuntimeError(sensitive_text),
        failure_result=_failure_commit_result(retry_scheduled=True),
    )

    result = harness.cycle.run_one_job()

    failure = harness.failure_commit.requests[0].tool_execution
    assert result.disposition is WorkerCycleDisposition.RETRY_PENDING
    assert failure.outcome == "worker_execution_exception"
    assert failure.failure_category is JobFailureCategory.WORKER_CRASH
    assert failure.retryable is True
    assert failure.adapter_version == harness.adapter.adapter_version
    assert failure.tool_version == harness.adapter.tool_version
    assert sensitive_text not in failure.error
    assert sensitive_text not in failure.outcome


def test_result_commit_failure_raises_worker_commit_error_without_failure_commit() -> None:
    commit_error = RuntimeError("database-url=secret")
    harness = _harness(result_error=commit_error)

    with pytest.raises(WorkerCommitError) as error:
        harness.cycle.run_one_job()

    assert error.value.__cause__ is commit_error
    assert LEASE_TOKEN not in str(error.value)
    assert "database-url=secret" not in str(error.value)
    assert harness.events == [
        "lease",
        "start",
        "observe",
        "resolve",
        "execute",
        "observe",
        "result_commit",
    ]
    assert harness.failure_commit.requests == []


def test_inconsistent_commit_result_raises_invariant_error() -> None:
    harness = _harness(
        result=_result_commit_result(job_id=OTHER_JOB_ID),
    )

    with pytest.raises(WorkerCycleInvariantError) as error:
        harness.cycle.run_one_job()

    assert LEASE_TOKEN not in str(error.value)
    assert harness.events == [
        "lease",
        "start",
        "observe",
        "resolve",
        "execute",
        "observe",
        "result_commit",
    ]
    assert len(harness.result_commit.requests) == 1
    assert harness.failure_commit.requests == []


def test_pre_execution_cancellation_is_acknowledged_without_adapter_execution() -> None:
    cancelling = replace(
        _job(JobStatus.RUNNING),
        cancel_requested=True,
        cancel_requested_at=NOW,
    )
    harness = _harness(observations=[cancelling])

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.CANCELLED
    assert result.job_id == JOB_ID
    assert result.run_id == RUN_ID
    assert result.attempt_number == 2
    assert result.tool_execution_id is None
    assert harness.events == ["lease", "start", "observe", "acknowledge"]
    assert harness.cancellation.calls == [(JOB_ID, WORKER_ID, LEASE_TOKEN)]
    assert harness.resolver.adapter_ids == []
    assert harness.adapter.jobs == []
    assert harness.result_commit.requests == []
    assert harness.failure_commit.requests == []


def test_start_racing_with_cancellation_is_acknowledged() -> None:
    harness = _harness(
        execution_error=JobCancellationRequestedError(JOB_ID),
    )

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.CANCELLED
    assert result.tool_execution_id is None
    assert harness.events == ["lease", "start", "acknowledge"]
    assert harness.cancellation.calls == [(JOB_ID, WORKER_ID, LEASE_TOKEN)]
    assert harness.resolver.adapter_ids == []
    assert harness.adapter.jobs == []
    assert harness.result_commit.requests == []
    assert harness.failure_commit.requests == []


def test_post_execution_cancellation_discards_successful_outcome() -> None:
    cancelling = replace(
        _job(JobStatus.RUNNING),
        cancel_requested=True,
        cancel_requested_at=NOW,
    )
    harness = _harness(
        observations=[_job(JobStatus.RUNNING), cancelling],
    )

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.CANCELLED
    assert result.tool_execution_id is None
    assert harness.events == [
        "lease",
        "start",
        "observe",
        "resolve",
        "execute",
        "observe",
        "acknowledge",
    ]
    assert harness.result_commit.requests == []
    assert harness.failure_commit.requests == []


def test_result_commit_cancellation_race_is_acknowledged() -> None:
    harness = _harness(
        result_error=JobCancellationRequestedError(JOB_ID),
    )

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.CANCELLED
    assert result.tool_execution_id is None
    assert harness.events == [
        "lease",
        "start",
        "observe",
        "resolve",
        "execute",
        "observe",
        "result_commit",
        "acknowledge",
    ]
    assert len(harness.result_commit.requests) == 1
    assert harness.failure_commit.requests == []


def test_expired_lease_during_commit_returns_lease_lost() -> None:
    harness = _harness(
        result_error=JobLeaseExpiredError(JOB_ID, NOW, NOW + timedelta(seconds=1)),
    )

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.LEASE_LOST
    assert result.job_id == JOB_ID
    assert result.run_id == RUN_ID
    assert result.attempt_number == 2
    assert result.tool_execution_id is None
    assert harness.events[-2:] == ["result_commit", "observe"]
    assert harness.cancellation.calls == []
    assert harness.failure_commit.requests == []


def test_new_attempt_fences_old_worker_before_commit() -> None:
    first_attempt_leased = _job(JobStatus.LEASED, attempt_count=1)
    first_attempt_running = _job(JobStatus.RUNNING, attempt_count=1)
    second_attempt = _job(
        JobStatus.RUNNING,
        attempt_count=2,
        lease_token=OTHER_LEASE_TOKEN,
    )
    harness = _harness(
        leased_job=first_attempt_leased,
        started_job=first_attempt_running,
        observations=[first_attempt_running, second_attempt],
    )

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.LEASE_LOST
    assert result.attempt_number == 1
    assert result.tool_execution_id is None
    assert harness.adapter.jobs == [first_attempt_running]
    assert harness.result_commit.requests == []
    assert harness.failure_commit.requests == []
    assert not hasattr(result, "lease_token")
    assert LEASE_TOKEN not in repr(result)
    assert OTHER_LEASE_TOKEN not in repr(result)


def test_controllable_adapter_success_renews_heartbeat_and_commits() -> None:
    fake_time = _FakeTime()
    handle = _ManagedHandle(
        [],
        [None, None, None, _successful_outcome()],
    )
    harness = _harness(
        managed_handle=handle,
        fake_time=fake_time,
    )

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.SUCCEEDED
    assert len(harness.heartbeat.calls) == 1
    assert harness.heartbeat.calls[0] == (JOB_ID, WORKER_ID, LEASE_TOKEN, 45)
    assert isinstance(harness.adapter, _ManagedAdapter)
    assert harness.adapter.started_jobs == [_job(JobStatus.RUNNING)]
    assert harness.adapter.jobs == []
    assert len(harness.result_commit.requests) == 1
    assert handle.closed is True


def test_live_cancellation_terminates_then_acknowledges() -> None:
    fake_time = _FakeTime()
    handle = _ManagedHandle([], [None])
    cancelling = replace(
        _job(JobStatus.RUNNING),
        cancel_requested=True,
        cancel_requested_at=NOW,
    )
    harness = _harness(
        managed_handle=handle,
        fake_time=fake_time,
        observations=[_job(JobStatus.RUNNING), cancelling],
    )

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.CANCELLED
    assert result.tool_execution_id is None
    assert harness.events.index("terminate") < harness.events.index("acknowledge")
    assert harness.events[harness.events.index("terminate") + 1] == "poll"
    assert handle.closed is True
    assert harness.result_commit.requests == []
    assert harness.failure_commit.requests == []


def test_live_cancellation_escalates_to_kill() -> None:
    fake_time = _FakeTime()
    handle = _ManagedHandle(
        [],
        [None],
        stop_after_terminate=False,
    )
    cancelling = replace(
        _job(JobStatus.RUNNING),
        cancel_requested=True,
        cancel_requested_at=NOW,
    )
    harness = _harness(
        managed_handle=handle,
        fake_time=fake_time,
        observations=[_job(JobStatus.RUNNING), cancelling],
    )

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.CANCELLED
    assert handle.terminated is True
    assert handle.killed is True
    assert harness.events.index("kill") < harness.events.index("acknowledge")
    assert harness.result_commit.requests == []
    assert harness.failure_commit.requests == []


def test_heartbeat_lease_loss_terminates_and_returns_lease_lost() -> None:
    fake_time = _FakeTime()
    handle = _ManagedHandle([], [None])
    harness = _harness(
        managed_handle=handle,
        fake_time=fake_time,
        heartbeat_error=JobLeaseExpiredError(
            JOB_ID,
            NOW,
            NOW + timedelta(seconds=1),
        ),
    )

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.LEASE_LOST
    assert result.tool_execution_id is None
    assert handle.terminated is True
    assert handle.closed is True
    assert harness.cancellation.calls == []
    assert harness.result_commit.requests == []
    assert harness.failure_commit.requests == []


def test_unexpected_heartbeat_failure_stops_process_and_raises() -> None:
    fake_time = _FakeTime()
    heartbeat_error = JobHeartbeatError("database-url=private")
    handle = _ManagedHandle([], [None])
    harness = _harness(
        managed_handle=handle,
        fake_time=fake_time,
        heartbeat_error=heartbeat_error,
    )

    with pytest.raises(WorkerHeartbeatError) as error:
        harness.cycle.run_one_job()

    assert error.value.__cause__ is heartbeat_error
    assert "database-url=private" not in str(error.value)
    assert LEASE_TOKEN not in str(error.value)
    assert handle.terminated is True
    assert handle.closed is True
    assert harness.result_commit.requests == []
    assert harness.failure_commit.requests == []


def test_unstoppable_execution_does_not_acknowledge_cancellation() -> None:
    fake_time = _FakeTime()
    handle = _ManagedHandle(
        [],
        [None],
        stop_after_terminate=False,
        stop_after_kill=False,
    )
    cancelling = replace(
        _job(JobStatus.RUNNING),
        cancel_requested=True,
        cancel_requested_at=NOW,
    )
    harness = _harness(
        managed_handle=handle,
        fake_time=fake_time,
        observations=[_job(JobStatus.RUNNING), cancelling],
    )

    with pytest.raises(WorkerProcessTerminationError) as error:
        harness.cycle.run_one_job()

    assert LEASE_TOKEN not in str(error.value)
    assert handle.terminated is True
    assert handle.killed is True
    assert handle.closed is True
    assert harness.cancellation.calls == []
    assert harness.result_commit.requests == []
    assert harness.failure_commit.requests == []


def test_poll_exception_commits_safe_failure_after_confirmed_stop() -> None:
    fake_time = _FakeTime()
    sensitive_text = "scanner-output credential=private"
    handle = _ManagedHandle([], [RuntimeError(sensitive_text)])
    harness = _harness(
        managed_handle=handle,
        fake_time=fake_time,
        failure_result=_failure_commit_result(retry_scheduled=True),
    )

    result = harness.cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.RETRY_PENDING
    assert handle.terminated is True
    assert handle.closed is True
    failure = harness.failure_commit.requests[0].tool_execution
    assert failure.outcome == "worker_execution_exception"
    assert failure.failure_category is JobFailureCategory.WORKER_CRASH
    assert failure.retryable is True
    assert sensitive_text not in failure.error
    assert sensitive_text not in failure.outcome
    assert LEASE_TOKEN not in failure.error
    assert harness.result_commit.requests == []

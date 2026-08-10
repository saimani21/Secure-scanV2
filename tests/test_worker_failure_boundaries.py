from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from securescan.domain.enums import ExecutionOutcome, JobFailureCategory, JobStatus
from securescan.jobs import (
    FailedToolExecutionCommit,
    JobFailureCommitRequest,
    JobHeartbeatError,
    JobRecord,
    JobResultCommitRequest,
    ToolExecutionCommit,
)
from securescan.worker import (
    SingleJobWorkerCycle,
    WorkerCommitError,
    WorkerCycleDisposition,
    WorkerFailedExecution,
    WorkerHeartbeatError,
    WorkerProcessTerminationError,
    WorkerSuccessfulExecution,
)

WORKER_ID = "fault-boundary-worker"
OTHER_WORKER_ID = "replacement-worker"
JOB_ID = str(UUID("00000000-0000-4000-8000-000000000701"))
RUN_ID = str(UUID("00000000-0000-4000-8000-000000000702"))
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000703"))
OTHER_LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000704"))
NOW = datetime(2054, 2, 3, 4, 5, 6, tzinfo=UTC)


def _job(
    status: JobStatus,
    *,
    attempt_count: int = 1,
    worker_id: str | None = WORKER_ID,
    lease_token: str | None = LEASE_TOKEN,
    cancel_requested: bool = False,
) -> JobRecord:
    return JobRecord(
        id=JOB_ID,
        run_id=RUN_ID,
        adapter_id="controlled-scanner",
        status=status,
        priority=10,
        attempt_count=attempt_count,
        max_attempts=3,
        available_at=NOW,
        leased_by=worker_id,
        lease_expires_at=NOW + timedelta(minutes=1),
        heartbeat_at=NOW,
        cancel_requested=cancel_requested,
        idempotency_key="7" * 64,
        payload_json={"repository_credential": "must-not-leak"},
        last_error=None,
        created_at=NOW,
        updated_at=NOW,
        started_at=NOW if status is JobStatus.RUNNING else None,
        finished_at=None,
        lease_token=lease_token,
        cancel_requested_at=NOW if cancel_requested else None,
    )


def _successful_outcome() -> WorkerSuccessfulExecution:
    return WorkerSuccessfulExecution(
        final_status=JobStatus.SUCCEEDED,
        report_json={"schema_version": "1.0.0", "run_id": RUN_ID},
        tool_execution=ToolExecutionCommit(
            tool_version="1",
            adapter_version="1",
            outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
            exit_code=0,
            duration_ms=5,
            warning_json=[],
        ),
    )


def _timeout_outcome() -> WorkerFailedExecution:
    return WorkerFailedExecution(
        tool_execution=FailedToolExecutionCommit(
            tool_version="1",
            adapter_version="1",
            outcome=ExecutionOutcome.TIMEOUT.value,
            exit_code=None,
            duration_ms=5,
            warning_json=[],
            error="Controlled scanner timed out.",
            failure_category=JobFailureCategory.TIMEOUT,
            retryable=True,
        )
    )


class _FakeTime:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class _Handle:
    def __init__(
        self,
        outcome,
        *,
        stop_after_terminate: bool = True,
        stop_after_kill: bool = True,
    ) -> None:
        self.outcome = outcome
        self.stop_after_terminate = stop_after_terminate
        self.stop_after_kill = stop_after_kill
        self.terminate_calls = 0
        self.kill_calls = 0
        self.poll_calls = 0
        self.close_calls = 0
        self.completion_confirmed = False

    def poll(self):
        self.poll_calls += 1
        if self.kill_calls and self.stop_after_kill:
            self.completion_confirmed = True
            return _timeout_outcome()
        if self.terminate_calls and self.stop_after_terminate:
            self.completion_confirmed = True
            return _timeout_outcome()
        return self.outcome

    def terminate(self) -> None:
        self.terminate_calls += 1

    def kill(self) -> None:
        self.kill_calls += 1

    def close(self) -> None:
        self.close_calls += 1


class _Adapter:
    adapter_id = "controlled-scanner"
    adapter_version = "1"
    tool_version = "1"

    def __init__(self, handle: _Handle) -> None:
        self.handle = handle
        self.start_calls = 0

    def start(self, job: JobRecord) -> _Handle:
        self.start_calls += 1
        return self.handle


class _Resolver:
    def __init__(self, adapter: _Adapter) -> None:
        self.adapter = adapter

    def resolve(self, adapter_id: str) -> _Adapter:
        assert adapter_id == self.adapter.adapter_id
        return self.adapter


class _LeasingService:
    def __init__(self, job: JobRecord) -> None:
        self.job = job

    def lease_next_job(self, *, worker_id: str, lease_seconds: int) -> JobRecord:
        assert worker_id == WORKER_ID
        assert lease_seconds == 30
        return self.job


class _ExecutionService:
    def __init__(self, job: JobRecord) -> None:
        self.job = job

    def start_job(self, *, job_id: str, worker_id: str, lease_token: str) -> JobRecord:
        assert (job_id, worker_id, lease_token) == (JOB_ID, WORKER_ID, LEASE_TOKEN)
        return self.job


class _JobReader:
    def __init__(self, records: list[JobRecord]) -> None:
        self.records = records
        self.calls = 0

    def get_job(self, job_id: str) -> JobRecord:
        assert job_id == JOB_ID
        index = min(self.calls, len(self.records) - 1)
        self.calls += 1
        return self.records[index]


class _CancellationAcknowledger:
    def __init__(self) -> None:
        self.calls = 0

    def acknowledge_cancellation(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> JobRecord:
        self.calls += 1
        assert (job_id, worker_id, lease_token) == (JOB_ID, WORKER_ID, LEASE_TOKEN)
        return replace(
            _job(JobStatus.RUNNING, cancel_requested=True),
            status=JobStatus.CANCELLED,
            leased_by=None,
            lease_token=None,
            lease_expires_at=None,
            finished_at=NOW,
        )


class _HeartbeatRenewer:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls = 0

    def renew_lease(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        lease_seconds: int = 30,
    ) -> JobRecord:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return _job(JobStatus.RUNNING)


class _ResultCommitService:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.requests: list[JobResultCommitRequest] = []

    def commit_result(self, request: JobResultCommitRequest):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        raise AssertionError("Unexpected successful result commitment")


class _FailureCommitService:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.requests: list[JobFailureCommitRequest] = []

    def commit_failure(self, request: JobFailureCommitRequest):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        raise AssertionError("Unexpected successful failure commitment")


def _cycle(
    handle: _Handle,
    observations: list[JobRecord],
    *,
    result_error: Exception | None = None,
    failure_error: Exception | None = None,
    heartbeat_error: Exception | None = None,
) -> tuple[
    SingleJobWorkerCycle,
    _ResultCommitService,
    _FailureCommitService,
    _CancellationAcknowledger,
    _HeartbeatRenewer,
]:
    fake_time = _FakeTime()
    result_commit = _ResultCommitService(result_error)
    failure_commit = _FailureCommitService(failure_error)
    cancellation = _CancellationAcknowledger()
    heartbeat = _HeartbeatRenewer(heartbeat_error)
    cycle = SingleJobWorkerCycle(
        _LeasingService(_job(JobStatus.LEASED)),
        _ExecutionService(_job(JobStatus.RUNNING)),
        result_commit,
        failure_commit,
        _Resolver(_Adapter(handle)),
        _JobReader(observations),
        cancellation,
        heartbeat,
        worker_id=WORKER_ID,
        lease_seconds=30,
        heartbeat_interval_seconds=1,
        execution_poll_interval_seconds=0.5,
        termination_grace_seconds=1,
        force_kill_grace_seconds=1,
        monotonic_clock=fake_time.monotonic,
        sleeper=fake_time.sleep,
    )
    return cycle, result_commit, failure_commit, cancellation, heartbeat


def test_result_commit_failure_does_not_fall_back_to_failure_commit() -> None:
    sensitive = RuntimeError(f"postgresql://admin:secret@db SQL lease_token={LEASE_TOKEN}")
    handle = _Handle(_successful_outcome())
    cycle, result_commit, failure_commit, cancellation, _ = _cycle(
        handle,
        [_job(JobStatus.RUNNING)],
        result_error=sensitive,
    )

    with pytest.raises(WorkerCommitError) as error:
        cycle.run_one_job()

    assert error.value.__cause__ is sensitive
    assert len(result_commit.requests) == 1
    assert failure_commit.requests == []
    assert cancellation.calls == 0
    assert handle.close_calls == 1
    assert "postgresql://" not in str(error.value)
    assert "secret" not in str(error.value)
    assert LEASE_TOKEN not in str(error.value)


def test_failure_commit_failure_is_not_retried_inside_cycle() -> None:
    sensitive = RuntimeError("scanner stdout credential=private")
    handle = _Handle(_timeout_outcome())
    cycle, result_commit, failure_commit, cancellation, _ = _cycle(
        handle,
        [_job(JobStatus.RUNNING)],
        failure_error=sensitive,
    )

    with pytest.raises(WorkerCommitError) as error:
        cycle.run_one_job()

    assert error.value.__cause__ is sensitive
    assert len(failure_commit.requests) == 1
    assert result_commit.requests == []
    assert cancellation.calls == 0
    assert handle.close_calls == 1
    assert "scanner stdout" not in str(error.value)
    assert "credential" not in str(error.value)


def test_unexpected_heartbeat_failure_stops_execution_without_commit() -> None:
    heartbeat_error = JobHeartbeatError("database-url=private SQL")
    handle = _Handle(None)
    cycle, result_commit, failure_commit, cancellation, heartbeat = _cycle(
        handle,
        [_job(JobStatus.RUNNING)],
        heartbeat_error=heartbeat_error,
    )

    with pytest.raises(WorkerHeartbeatError) as error:
        cycle.run_one_job()

    assert error.value.__cause__ is heartbeat_error
    assert heartbeat.calls == 1
    assert handle.terminate_calls == 1
    assert handle.kill_calls == 0
    assert handle.completion_confirmed is True
    assert handle.close_calls == 1
    assert result_commit.requests == []
    assert failure_commit.requests == []
    assert cancellation.calls == 0


def test_unstoppable_execution_never_acknowledges_cancellation() -> None:
    handle = _Handle(
        None,
        stop_after_terminate=False,
        stop_after_kill=False,
    )
    cycle, result_commit, failure_commit, cancellation, _ = _cycle(
        handle,
        [
            _job(JobStatus.RUNNING),
            _job(JobStatus.RUNNING, cancel_requested=True),
        ],
    )

    with pytest.raises(WorkerProcessTerminationError) as error:
        cycle.run_one_job()

    assert handle.terminate_calls == 1
    assert handle.kill_calls == 1
    assert handle.completion_confirmed is False
    assert handle.close_calls == 1
    assert cancellation.calls == 0
    assert result_commit.requests == []
    assert failure_commit.requests == []
    assert LEASE_TOKEN not in str(error.value)
    assert "repository_credential" not in str(error.value)


def test_timeout_outcome_is_discarded_when_cancellation_wins_before_commit() -> None:
    handle = _Handle(_timeout_outcome())
    cycle, result_commit, failure_commit, cancellation, _ = _cycle(
        handle,
        [
            _job(JobStatus.RUNNING),
            _job(JobStatus.RUNNING, cancel_requested=True),
        ],
    )

    result = cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.CANCELLED
    assert result.tool_execution_id is None
    assert cancellation.calls == 1
    assert result_commit.requests == []
    assert failure_commit.requests == []
    assert handle.close_calls == 1


def test_completed_outcome_is_discarded_when_new_attempt_fences_worker() -> None:
    handle = _Handle(_successful_outcome())
    replacement_attempt = _job(
        JobStatus.RUNNING,
        attempt_count=2,
        worker_id=OTHER_WORKER_ID,
        lease_token=OTHER_LEASE_TOKEN,
    )
    cycle, result_commit, failure_commit, cancellation, _ = _cycle(
        handle,
        [_job(JobStatus.RUNNING), replacement_attempt],
    )

    result = cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.LEASE_LOST
    assert result.attempt_number == 1
    assert result.tool_execution_id is None
    assert result_commit.requests == []
    assert failure_commit.requests == []
    assert cancellation.calls == 0
    assert not hasattr(result, "lease_token")
    assert LEASE_TOKEN not in repr(result)
    assert OTHER_LEASE_TOKEN not in repr(result)
    assert handle.close_calls == 1

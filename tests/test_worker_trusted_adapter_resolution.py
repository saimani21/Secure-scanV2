from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from securescan.adapters.sandbox_policy import (
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
)
from securescan.adapters.trusted_registry import (
    TrustedAdapterDefinition,
    TrustedAdapterRegistry,
    TrustedAdapterResolver,
)
from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
)
from securescan.jobs import (
    JobFailureCommitResult,
    JobRecord,
    JobResultCommitResult,
    ToolExecutionCommit,
)
from securescan.worker import (
    SingleJobWorkerCycle,
    WorkerCycleDisposition,
    WorkerSuccessfulExecution,
)

WORKER_ID = "trusted-registry-worker"
JOB_ID = str(UUID("00000000-0000-4000-8000-000000008001"))
RUN_ID = str(UUID("00000000-0000-4000-8000-000000008002"))
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000008003"))
NOW = datetime(2058, 1, 2, 3, 4, 5, tzinfo=UTC)


def _job(status: JobStatus, *, adapter_id: str = "trusted-fake") -> JobRecord:
    return JobRecord(
        id=JOB_ID,
        run_id=RUN_ID,
        adapter_id=adapter_id,
        status=status,
        priority=100,
        attempt_count=1,
        max_attempts=3,
        available_at=NOW,
        leased_by=WORKER_ID,
        lease_expires_at=NOW + timedelta(seconds=30),
        heartbeat_at=NOW,
        cancel_requested=False,
        idempotency_key="8" * 64,
        payload_json={
            "image_reference": "attacker.example/tool:latest",
            "command_prefix": ["sh", "-c", "steal-secrets"],
            "network_mode": "host",
            "run_as_uid": 0,
            "environment": {"TOKEN": "sensitive"},
            "timeout_seconds": 999999,
        },
        last_error=None,
        created_at=NOW,
        updated_at=NOW,
        started_at=NOW if status is JobStatus.RUNNING else None,
        finished_at=None,
        lease_token=LEASE_TOKEN,
        cancel_requested_at=None,
    )


def _outcome() -> WorkerSuccessfulExecution:
    return WorkerSuccessfulExecution(
        final_status=JobStatus.SUCCEEDED,
        report_json={"schema_version": "1.0.0", "run_id": RUN_ID},
        tool_execution=ToolExecutionCommit(
            tool_version="1",
            adapter_version="1",
            outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
            exit_code=0,
            duration_ms=1,
            warning_json=[],
        ),
    )


class _WorkerAdapter:
    adapter_id = "trusted-fake"
    adapter_version = "1"
    tool_version = "1"

    def __init__(self) -> None:
        self.executed_jobs: list[JobRecord] = []

    def execute(self, job: JobRecord) -> WorkerSuccessfulExecution:
        self.executed_jobs.append(job)
        return _outcome()


def _definition(factory) -> TrustedAdapterDefinition:
    return TrustedAdapterDefinition(
        adapter_id="trusted-fake",
        display_name="Trusted fake",
        tool_name="trusted-fake",
        tool_version="1",
        backend=SandboxExecutionBackend.TEST_ONLY,
        policy=SandboxExecutionPolicy(backend=SandboxExecutionBackend.TEST_ONLY),
        factory=factory,
        test_only=True,
    )


class _Leasing:
    def __init__(self, job: JobRecord) -> None:
        self.job = job

    def lease_next_job(self, *, worker_id: str, lease_seconds: int) -> JobRecord:
        assert (worker_id, lease_seconds) == (WORKER_ID, 30)
        return self.job


class _Execution:
    def __init__(self, job: JobRecord) -> None:
        self.job = job

    def start_job(self, *, job_id: str, worker_id: str, lease_token: str) -> JobRecord:
        assert (job_id, worker_id, lease_token) == (JOB_ID, WORKER_ID, LEASE_TOKEN)
        return self.job


class _Reader:
    def __init__(self, job: JobRecord) -> None:
        self.job = job

    def get_job(self, job_id: str) -> JobRecord:
        assert job_id == JOB_ID
        return self.job


class _ResultCommit:
    def __init__(self, job: JobRecord) -> None:
        self.job = job
        self.requests = []

    def commit_result(self, request) -> JobResultCommitResult:
        self.requests.append(request)
        return JobResultCommitResult(
            job=replace(
                self.job,
                status=JobStatus.SUCCEEDED,
                leased_by=None,
                lease_token=None,
                lease_expires_at=None,
                finished_at=NOW,
            ),
            run_id=RUN_ID,
            tool_execution_id="trusted-execution",
            attempt_number=1,
            report_json=request.report_json,
        )


class _FailureCommit:
    def __init__(self, job: JobRecord) -> None:
        self.job = job
        self.requests = []

    def commit_failure(self, request) -> JobFailureCommitResult:
        self.requests.append(request)
        return JobFailureCommitResult(
            job=replace(
                self.job,
                status=JobStatus.FAILED,
                leased_by=None,
                lease_token=None,
                lease_expires_at=None,
                finished_at=NOW,
            ),
            run_id=RUN_ID,
            tool_execution_id="trusted-failure",
            attempt_number=1,
            retry_scheduled=False,
            retry_delay_seconds=None,
            failure_category=JobFailureCategory.NON_RETRYABLE_POLICY,
        )


class _Cancellation:
    def acknowledge_cancellation(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> JobRecord:
        raise AssertionError("Cancellation must not be acknowledged")


class _Heartbeat:
    def renew_lease(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        lease_seconds: int = 30,
    ) -> JobRecord:
        raise AssertionError("Synchronous execution must not heartbeat")


def _cycle(
    adapter_id: str,
    registry: TrustedAdapterRegistry,
) -> tuple[SingleJobWorkerCycle, _ResultCommit, _FailureCommit]:
    leased = _job(JobStatus.LEASED, adapter_id=adapter_id)
    running = _job(JobStatus.RUNNING, adapter_id=adapter_id)
    result_commit = _ResultCommit(running)
    failure_commit = _FailureCommit(running)
    cycle = SingleJobWorkerCycle(
        _Leasing(leased),
        _Execution(running),
        result_commit,
        failure_commit,
        TrustedAdapterResolver(registry),
        _Reader(running),
        _Cancellation(),
        _Heartbeat(),
        worker_id=WORKER_ID,
        lease_seconds=30,
    )
    return cycle, result_commit, failure_commit


def test_worker_resolver_returns_registered_adapter_without_executing_it() -> None:
    adapter = _WorkerAdapter()
    factory_calls = 0

    def factory() -> _WorkerAdapter:
        nonlocal factory_calls
        factory_calls += 1
        return adapter

    definition = _definition(factory)
    resolver = TrustedAdapterResolver(TrustedAdapterRegistry((definition,)))

    assert resolver.resolve("trusted-fake") is adapter
    assert factory_calls == 1
    assert adapter.executed_jobs == []
    with pytest.raises(FrozenInstanceError):
        definition.command_prefix = ("changed",)  # type: ignore[misc]


def test_worker_cycle_uses_trusted_adapter_and_commits_success() -> None:
    adapter = _WorkerAdapter()
    definition = _definition(lambda: adapter)
    registry = TrustedAdapterRegistry((definition,))
    cycle, result_commit, failure_commit = _cycle("trusted-fake", registry)

    result = cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.SUCCEEDED
    assert len(adapter.executed_jobs) == 1
    assert len(result_commit.requests) == 1
    assert failure_commit.requests == []
    assert definition.image_reference is None
    assert definition.command_prefix == ()
    assert definition.policy.network_mode.value == "disabled"
    assert adapter.executed_jobs[0].payload_json["image_reference"].endswith(":latest")


def test_worker_cycle_unknown_adapter_fails_before_execution() -> None:
    adapter = _WorkerAdapter()
    factory_calls = 0

    def factory() -> _WorkerAdapter:
        nonlocal factory_calls
        factory_calls += 1
        return adapter

    registry = TrustedAdapterRegistry((_definition(factory),))
    submitted = "unknown-sensitive-adapter"
    cycle, result_commit, failure_commit = _cycle(submitted, registry)

    result = cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.FAILED
    assert factory_calls == 0
    assert adapter.executed_jobs == []
    assert result_commit.requests == []
    assert len(failure_commit.requests) == 1
    failure = failure_commit.requests[0].tool_execution
    assert failure.outcome == "adapter_resolution_failed"
    assert failure.failure_category is JobFailureCategory.NON_RETRYABLE_POLICY
    assert failure.retryable is False
    assert submitted not in failure.error
    assert "attacker.example" not in failure.error

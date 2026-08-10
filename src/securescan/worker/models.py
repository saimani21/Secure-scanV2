from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from securescan.domain.enums import JobStatus
from securescan.jobs.failure_commit import FailedToolExecutionCommit
from securescan.jobs.models import JobRecord
from securescan.jobs.result_commit import ToolExecutionCommit


class WorkerCycleError(RuntimeError):
    """Raised when single-job worker orchestration fails."""


class WorkerExecutionContractError(WorkerCycleError):
    """Raised when worker configuration or an adapter outcome is invalid."""


class WorkerCycleInvariantError(WorkerCycleError):
    """Raised when a durable service violates the worker-cycle contract."""


class WorkerAdapterResolutionError(WorkerCycleError):
    """Raised internally when the configured adapter cannot be resolved."""


class WorkerCommitError(WorkerCycleError):
    """Raised when a durable result or failure commitment fails."""


class WorkerCancellationError(WorkerCycleError):
    """Raised when cancellation acknowledgement persistence fails unexpectedly."""


class WorkerHeartbeatError(WorkerCycleError):
    """Raised when heartbeat persistence fails unexpectedly."""


class WorkerProcessTerminationError(WorkerCycleError):
    """Raised when a controlled execution cannot be confirmed stopped."""


@dataclass(frozen=True, slots=True)
class WorkerSuccessfulExecution:
    final_status: JobStatus
    report_json: dict[str, Any]
    tool_execution: ToolExecutionCommit

    def __post_init__(self) -> None:
        if not isinstance(self.final_status, JobStatus) or self.final_status not in {
            JobStatus.SUCCEEDED,
            JobStatus.PARTIAL,
        }:
            raise WorkerExecutionContractError(
                "Successful worker execution must end as succeeded or partial"
            )
        if not isinstance(self.report_json, dict):
            raise WorkerExecutionContractError("Successful worker report must be a mapping")
        if not isinstance(self.tool_execution, ToolExecutionCommit):
            raise WorkerExecutionContractError("Successful worker execution metadata is invalid")
        object.__setattr__(self, "report_json", deepcopy(self.report_json))


@dataclass(frozen=True, slots=True)
class WorkerFailedExecution:
    tool_execution: FailedToolExecutionCommit

    def __post_init__(self) -> None:
        if not isinstance(self.tool_execution, FailedToolExecutionCommit):
            raise WorkerExecutionContractError("Failed worker execution metadata is invalid")


WorkerExecutionOutcome = WorkerSuccessfulExecution | WorkerFailedExecution


@runtime_checkable
class WorkerExecutionHandle(Protocol):
    def poll(self) -> WorkerExecutionOutcome | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def close(self) -> None: ...


@runtime_checkable
class WorkerAdapter(Protocol):
    adapter_id: str
    adapter_version: str
    tool_version: str

    def execute(
        self,
        job: JobRecord,
    ) -> WorkerExecutionOutcome: ...


@runtime_checkable
class ControllableWorkerAdapter(Protocol):
    adapter_id: str
    adapter_version: str
    tool_version: str

    def start(
        self,
        job: JobRecord,
    ) -> WorkerExecutionHandle: ...


class WorkerAdapterResolver(Protocol):
    def resolve(
        self,
        adapter_id: str,
    ) -> WorkerAdapter | ControllableWorkerAdapter: ...


class WorkerJobReader(Protocol):
    def get_job(
        self,
        job_id: str,
    ) -> JobRecord: ...


class WorkerCancellationAcknowledger(Protocol):
    def acknowledge_cancellation(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> JobRecord: ...


class WorkerHeartbeatRenewer(Protocol):
    def renew_lease(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        lease_seconds: int = 30,
    ) -> JobRecord: ...


class WorkerCycleDisposition(StrEnum):
    IDLE = "idle"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    RETRY_PENDING = "retry_pending"
    FAILED = "failed"
    CANCELLED = "cancelled"
    LEASE_LOST = "lease_lost"


@dataclass(frozen=True, slots=True)
class WorkerCycleResult:
    disposition: WorkerCycleDisposition
    job_id: str | None
    run_id: str | None
    attempt_number: int | None
    tool_execution_id: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, WorkerCycleDisposition):
            raise WorkerExecutionContractError("Worker disposition is invalid")
        identities = (self.job_id, self.run_id, self.attempt_number)
        if self.disposition is WorkerCycleDisposition.IDLE:
            if any(value is not None for value in (*identities, self.tool_execution_id)):
                raise WorkerExecutionContractError(
                    "An idle worker result cannot contain job identity"
                )
        elif any(value is None for value in identities):
            raise WorkerExecutionContractError("A non-idle worker result requires job identity")
        elif self.disposition in {
            WorkerCycleDisposition.CANCELLED,
            WorkerCycleDisposition.LEASE_LOST,
        }:
            if self.tool_execution_id is not None:
                raise WorkerExecutionContractError(
                    "An uncommitted worker result cannot contain tool execution identity"
                )
        elif not isinstance(self.tool_execution_id, str) or not self.tool_execution_id.strip():
            raise WorkerExecutionContractError(
                "A committed worker result requires tool execution identity"
            )

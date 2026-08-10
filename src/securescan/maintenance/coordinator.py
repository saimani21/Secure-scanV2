from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from securescan.jobs.cancellation import JobCancellationService
from securescan.jobs.lease_recovery import JobLeaseRecoveryService
from securescan.jobs.retry_promotion import JobRetryPromotionService


class MaintenanceOperationName(StrEnum):
    RETRY_PROMOTION = "retry_promotion"
    LEASE_RECOVERY = "lease_recovery"
    CANCELLATION_REAPER = "cancellation_reaper"


@runtime_checkable
class MaintenanceOperation(Protocol):
    def run(self, batch_size: int) -> int: ...


class MaintenanceCoordinatorConfigurationError(ValueError):
    """Raised when maintenance coordinator configuration is invalid."""


class MaintenanceOperationContractError(RuntimeError):
    """Raised when a maintenance operation violates its count contract."""


def _validated_affected_count(count: object) -> int:
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise MaintenanceOperationContractError(
            "Maintenance operation returned an invalid affected-job count"
        )
    return count


class RetryPromotionOperation:
    def __init__(self, service: JobRetryPromotionService) -> None:
        self._service = service

    def run(self, batch_size: int) -> int:
        return _validated_affected_count(len(self._service.promote_due_retries(limit=batch_size)))


class LeaseRecoveryOperation:
    def __init__(self, service: JobLeaseRecoveryService) -> None:
        self._service = service

    def run(self, batch_size: int) -> int:
        return _validated_affected_count(len(self._service.recover_expired_jobs(limit=batch_size)))


class CancellationReaperOperation:
    def __init__(self, service: JobCancellationService) -> None:
        self._service = service

    def run(self, batch_size: int) -> int:
        return _validated_affected_count(
            len(self._service.finalize_expired_cancellations(limit=batch_size))
        )


@dataclass(frozen=True, slots=True)
class MaintenanceTaskConfiguration:
    name: MaintenanceOperationName
    interval_seconds: float
    batch_size: int

    def __post_init__(self) -> None:
        if not isinstance(self.name, MaintenanceOperationName):
            raise MaintenanceCoordinatorConfigurationError("Maintenance operation name is invalid")
        if (
            isinstance(self.interval_seconds, bool)
            or not isinstance(self.interval_seconds, (int, float))
            or not 0 < self.interval_seconds <= 86_400
        ):
            raise MaintenanceCoordinatorConfigurationError(
                "Maintenance interval must be greater than zero and at most 86400"
            )
        if (
            isinstance(self.batch_size, bool)
            or not isinstance(self.batch_size, int)
            or not 1 <= self.batch_size <= 10_000
        ):
            raise MaintenanceCoordinatorConfigurationError(
                "Maintenance batch size must be from 1 through 10000"
            )


@dataclass(frozen=True, slots=True)
class MaintenanceTask:
    configuration: MaintenanceTaskConfiguration
    operation: MaintenanceOperation

    def __post_init__(self) -> None:
        if not isinstance(self.configuration, MaintenanceTaskConfiguration):
            raise MaintenanceCoordinatorConfigurationError(
                "Maintenance task configuration is invalid"
            )
        if not isinstance(self.operation, MaintenanceOperation):
            raise MaintenanceCoordinatorConfigurationError("Maintenance task operation is invalid")


@dataclass(frozen=True, slots=True)
class MaintenanceOperationResult:
    name: MaintenanceOperationName
    attempted: bool
    affected_jobs: int
    failed: bool
    error_type: str | None

    def __post_init__(self) -> None:
        valid_count = (
            isinstance(self.affected_jobs, int)
            and not isinstance(self.affected_jobs, bool)
            and self.affected_jobs >= 0
        )
        valid = (
            isinstance(self.name, MaintenanceOperationName)
            and isinstance(self.attempted, bool)
            and isinstance(self.failed, bool)
            and valid_count
        )
        if not valid:
            raise MaintenanceOperationContractError("Maintenance operation result is invalid")
        if not self.attempted:
            valid = self.affected_jobs == 0 and not self.failed and self.error_type is None
        elif self.failed:
            valid = (
                self.affected_jobs == 0
                and isinstance(self.error_type, str)
                and bool(self.error_type)
                and self.error_type.isidentifier()
            )
        else:
            valid = self.error_type is None
        if not valid:
            raise MaintenanceOperationContractError(
                "Maintenance operation result state is inconsistent"
            )


@dataclass(frozen=True, slots=True)
class MaintenancePassResult:
    operations: tuple[MaintenanceOperationResult, ...]
    total_affected_jobs: int
    failures: int

    def __post_init__(self) -> None:
        valid_operations = (
            isinstance(self.operations, tuple)
            and len(self.operations) == len(MaintenanceOperationName)
            and all(isinstance(result, MaintenanceOperationResult) for result in self.operations)
        )
        valid_counts = all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in (self.total_affected_jobs, self.failures)
        )
        if (
            not valid_operations
            or not valid_counts
            or tuple(result.name for result in self.operations) != tuple(MaintenanceOperationName)
            or self.total_affected_jobs != sum(result.affected_jobs for result in self.operations)
            or self.failures != sum(result.failed for result in self.operations)
        ):
            raise MaintenanceOperationContractError("Maintenance pass result is inconsistent")


class MaintenanceCoordinatorExitReason(StrEnum):
    STOP_REQUESTED = "stop_requested"
    MAX_PASSES_REACHED = "max_passes_reached"


@dataclass(frozen=True, slots=True)
class MaintenanceCoordinatorResult:
    exit_reason: MaintenanceCoordinatorExitReason
    passes: int
    operation_attempts: int
    affected_jobs: int
    failures: int

    def __post_init__(self) -> None:
        counters = (
            self.passes,
            self.operation_attempts,
            self.affected_jobs,
            self.failures,
        )
        if not isinstance(self.exit_reason, MaintenanceCoordinatorExitReason) or any(
            isinstance(counter, bool) or not isinstance(counter, int) or counter < 0
            for counter in counters
        ):
            raise MaintenanceOperationContractError("Maintenance coordinator result is invalid")


class MaintenanceCoordinator:
    def __init__(
        self,
        tasks: Sequence[MaintenanceTask],
        stop_event: threading.Event,
        monotonic_clock: Callable[[], float] = time.monotonic,
        waiter: Callable[[float], bool] | None = None,
        max_sleep_seconds: float = 1.0,
        max_passes: int | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if isinstance(tasks, (str, bytes)) or not isinstance(tasks, Sequence):
            raise MaintenanceCoordinatorConfigurationError(
                "tasks must be a maintenance task sequence"
            )
        task_by_name: dict[MaintenanceOperationName, MaintenanceTask] = {}
        for task in tasks:
            if not isinstance(task, MaintenanceTask):
                raise MaintenanceCoordinatorConfigurationError(
                    "tasks contains an invalid maintenance task"
                )
            name = task.configuration.name
            if name in task_by_name:
                raise MaintenanceCoordinatorConfigurationError(
                    "Maintenance operation names must be unique"
                )
            task_by_name[name] = task
        if set(task_by_name) != set(MaintenanceOperationName):
            raise MaintenanceCoordinatorConfigurationError(
                "Exactly one task for each maintenance operation is required"
            )
        if not isinstance(stop_event, threading.Event):
            raise MaintenanceCoordinatorConfigurationError("stop_event must be a threading event")
        if not callable(monotonic_clock):
            raise MaintenanceCoordinatorConfigurationError("monotonic_clock must be callable")
        if waiter is not None and not callable(waiter):
            raise MaintenanceCoordinatorConfigurationError("waiter must be callable")
        if (
            isinstance(max_sleep_seconds, bool)
            or not isinstance(max_sleep_seconds, (int, float))
            or not 0 < max_sleep_seconds <= 3600
        ):
            raise MaintenanceCoordinatorConfigurationError(
                "max_sleep_seconds must be greater than zero and at most 3600"
            )
        if max_passes is not None and (
            isinstance(max_passes, bool)
            or not isinstance(max_passes, int)
            or not 1 <= max_passes <= 1_000_000
        ):
            raise MaintenanceCoordinatorConfigurationError(
                "max_passes must be None or an integer from 1 through 1000000"
            )
        if logger is not None and not isinstance(logger, logging.Logger):
            raise MaintenanceCoordinatorConfigurationError("logger must be a logging logger")

        self._tasks = tuple(task_by_name[name] for name in MaintenanceOperationName)
        self._stop_event = stop_event
        self._monotonic_clock = monotonic_clock
        self._waiter = waiter or stop_event.wait
        self._max_sleep_seconds = float(max_sleep_seconds)
        self._max_passes = max_passes
        self._logger = logger or logging.getLogger(__name__)
        self._next_deadlines = {name: float("-inf") for name in MaintenanceOperationName}

    def run_due_operations(self) -> MaintenancePassResult:
        selection_time = self._monotonic_clock()
        results: list[MaintenanceOperationResult] = []
        for task in self._tasks:
            configuration = task.configuration
            if selection_time < self._next_deadlines[configuration.name]:
                results.append(
                    MaintenanceOperationResult(
                        name=configuration.name,
                        attempted=False,
                        affected_jobs=0,
                        failed=False,
                        error_type=None,
                    )
                )
                continue

            try:
                affected_jobs = _validated_affected_count(
                    task.operation.run(configuration.batch_size)
                )
                operation_result = MaintenanceOperationResult(
                    name=configuration.name,
                    attempted=True,
                    affected_jobs=affected_jobs,
                    failed=False,
                    error_type=None,
                )
            except Exception as exc:
                error_type = type(exc).__name__
                self._logger.warning(
                    "Maintenance operation failed; operation=%s error_type=%s",
                    configuration.name.value,
                    error_type,
                )
                operation_result = MaintenanceOperationResult(
                    name=configuration.name,
                    attempted=True,
                    affected_jobs=0,
                    failed=True,
                    error_type=error_type,
                )
            self._next_deadlines[configuration.name] = (
                self._monotonic_clock() + configuration.interval_seconds
            )
            results.append(operation_result)

        operations = tuple(results)
        return MaintenancePassResult(
            operations=operations,
            total_affected_jobs=sum(result.affected_jobs for result in operations),
            failures=sum(result.failed for result in operations),
        )

    def run(self) -> MaintenanceCoordinatorResult:
        passes = 0
        operation_attempts = 0
        affected_jobs = 0
        failures = 0

        def result(
            exit_reason: MaintenanceCoordinatorExitReason,
        ) -> MaintenanceCoordinatorResult:
            return MaintenanceCoordinatorResult(
                exit_reason=exit_reason,
                passes=passes,
                operation_attempts=operation_attempts,
                affected_jobs=affected_jobs,
                failures=failures,
            )

        while True:
            if self._stop_event.is_set():
                return result(MaintenanceCoordinatorExitReason.STOP_REQUESTED)

            pass_result = self.run_due_operations()
            passes += 1
            operation_attempts += sum(operation.attempted for operation in pass_result.operations)
            affected_jobs += pass_result.total_affected_jobs
            failures += pass_result.failures

            if self._stop_event.is_set():
                return result(MaintenanceCoordinatorExitReason.STOP_REQUESTED)
            if self._max_passes is not None and passes >= self._max_passes:
                return result(MaintenanceCoordinatorExitReason.MAX_PASSES_REACHED)

            current = self._monotonic_clock()
            nearest_deadline = min(self._next_deadlines.values())
            wait_seconds = min(
                max(0.0, nearest_deadline - current),
                self._max_sleep_seconds,
            )
            shutdown_requested = self._waiter(wait_seconds)
            if not isinstance(shutdown_requested, bool):
                raise MaintenanceOperationContractError(
                    "Maintenance waiter returned an invalid result"
                )
            if shutdown_requested:
                return result(MaintenanceCoordinatorExitReason.STOP_REQUESTED)

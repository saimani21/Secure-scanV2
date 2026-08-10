from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from securescan.worker.models import (
    WorkerCycleDisposition,
    WorkerCycleResult,
)


@runtime_checkable
class WorkerCycleRunner(Protocol):
    def run_one_job(self) -> WorkerCycleResult: ...


class WorkerDaemonExitReason(StrEnum):
    STOP_REQUESTED = "stop_requested"
    MAX_CYCLES_REACHED = "max_cycles_reached"
    ERROR_LIMIT_REACHED = "error_limit_reached"


class WorkerDaemonConfigurationError(ValueError):
    """Raised when worker daemon configuration is invalid."""


class WorkerDaemonRuntimeError(RuntimeError):
    """Raised when an internal worker daemon invariant is violated."""


@dataclass(frozen=True, slots=True)
class WorkerDaemonResult:
    exit_reason: WorkerDaemonExitReason
    cycles_attempted: int
    completed_cycles: int
    processed_cycles: int
    idle_cycles: int
    cancelled_cycles: int
    lease_lost_cycles: int
    errors: int
    peak_consecutive_errors: int

    def __post_init__(self) -> None:
        if not isinstance(self.exit_reason, WorkerDaemonExitReason):
            raise WorkerDaemonRuntimeError("Worker daemon exit reason is invalid")
        counters = (
            self.cycles_attempted,
            self.completed_cycles,
            self.processed_cycles,
            self.idle_cycles,
            self.cancelled_cycles,
            self.lease_lost_cycles,
            self.errors,
            self.peak_consecutive_errors,
        )
        if any(
            isinstance(counter, bool) or not isinstance(counter, int) or counter < 0
            for counter in counters
        ):
            raise WorkerDaemonRuntimeError("Worker daemon counters are invalid")


class WorkerDaemon:
    def __init__(
        self,
        cycle: WorkerCycleRunner,
        stop_event: threading.Event,
        idle_delay_seconds: float = 1.0,
        error_backoff_initial_seconds: float = 1.0,
        error_backoff_multiplier: float = 2.0,
        error_backoff_max_seconds: float = 30.0,
        max_consecutive_errors: int | None = 10,
        max_cycles: int | None = None,
        waiter: Callable[[float], bool] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if not isinstance(cycle, WorkerCycleRunner):
            raise WorkerDaemonConfigurationError("cycle must satisfy the worker cycle contract")
        if not isinstance(stop_event, threading.Event):
            raise WorkerDaemonConfigurationError("stop_event must be a threading event")
        self._validate_number(
            idle_delay_seconds,
            "idle_delay_seconds",
            minimum=0,
            maximum=3600,
        )
        self._validate_number(
            error_backoff_initial_seconds,
            "error_backoff_initial_seconds",
            minimum=0,
            maximum=3600,
        )
        self._validate_number(
            error_backoff_multiplier,
            "error_backoff_multiplier",
            minimum=1,
            maximum=100,
        )
        self._validate_number(
            error_backoff_max_seconds,
            "error_backoff_max_seconds",
            minimum=float(error_backoff_initial_seconds),
            maximum=86_400,
        )
        self._validate_optional_limit(
            max_consecutive_errors,
            "max_consecutive_errors",
        )
        self._validate_optional_limit(max_cycles, "max_cycles")
        if waiter is not None and not callable(waiter):
            raise WorkerDaemonConfigurationError("waiter must be callable")
        if logger is not None and not isinstance(logger, logging.Logger):
            raise WorkerDaemonConfigurationError("logger must be a logging logger")

        self._cycle = cycle
        self._stop_event = stop_event
        self._idle_delay_seconds = float(idle_delay_seconds)
        self._error_backoff_initial_seconds = float(error_backoff_initial_seconds)
        self._error_backoff_multiplier = float(error_backoff_multiplier)
        self._error_backoff_max_seconds = float(error_backoff_max_seconds)
        self._max_consecutive_errors = max_consecutive_errors
        self._max_cycles = max_cycles
        self._waiter = waiter or stop_event.wait
        self._logger = logger or logging.getLogger(__name__)

    def run(self) -> WorkerDaemonResult:
        cycles_attempted = 0
        completed_cycles = 0
        processed_cycles = 0
        idle_cycles = 0
        cancelled_cycles = 0
        lease_lost_cycles = 0
        errors = 0
        consecutive_errors = 0
        peak_consecutive_errors = 0

        def result(exit_reason: WorkerDaemonExitReason) -> WorkerDaemonResult:
            return WorkerDaemonResult(
                exit_reason=exit_reason,
                cycles_attempted=cycles_attempted,
                completed_cycles=completed_cycles,
                processed_cycles=processed_cycles,
                idle_cycles=idle_cycles,
                cancelled_cycles=cancelled_cycles,
                lease_lost_cycles=lease_lost_cycles,
                errors=errors,
                peak_consecutive_errors=peak_consecutive_errors,
            )

        while True:
            if self._stop_event.is_set():
                return result(WorkerDaemonExitReason.STOP_REQUESTED)
            if self._max_cycles is not None and cycles_attempted >= self._max_cycles:
                return result(WorkerDaemonExitReason.MAX_CYCLES_REACHED)

            cycles_attempted += 1
            try:
                cycle_result = self._cycle.run_one_job()
            except Exception as exc:
                errors += 1
                consecutive_errors += 1
                peak_consecutive_errors = max(
                    peak_consecutive_errors,
                    consecutive_errors,
                )
                backoff = self._error_backoff(consecutive_errors)
                self._logger.warning(
                    "Worker cycle failed; error_type=%s backoff_seconds=%s",
                    type(exc).__name__,
                    backoff,
                )
                if self._stop_event.is_set():
                    return result(WorkerDaemonExitReason.STOP_REQUESTED)
                if (
                    self._max_consecutive_errors is not None
                    and consecutive_errors >= self._max_consecutive_errors
                ):
                    return result(WorkerDaemonExitReason.ERROR_LIMIT_REACHED)
                if self._max_cycles is not None and cycles_attempted >= self._max_cycles:
                    return result(WorkerDaemonExitReason.MAX_CYCLES_REACHED)
                if self._wait(backoff):
                    return result(WorkerDaemonExitReason.STOP_REQUESTED)
                continue
            if not isinstance(cycle_result, WorkerCycleResult):
                raise WorkerDaemonRuntimeError("Worker cycle returned an invalid result")

            completed_cycles += 1
            consecutive_errors = 0
            disposition = cycle_result.disposition
            if disposition is WorkerCycleDisposition.IDLE:
                idle_cycles += 1
            else:
                processed_cycles += 1
                if disposition is WorkerCycleDisposition.CANCELLED:
                    cancelled_cycles += 1
                elif disposition is WorkerCycleDisposition.LEASE_LOST:
                    lease_lost_cycles += 1

            if self._stop_event.is_set():
                return result(WorkerDaemonExitReason.STOP_REQUESTED)
            if self._max_cycles is not None and cycles_attempted >= self._max_cycles:
                return result(WorkerDaemonExitReason.MAX_CYCLES_REACHED)
            if disposition is WorkerCycleDisposition.IDLE and self._wait(self._idle_delay_seconds):
                return result(WorkerDaemonExitReason.STOP_REQUESTED)

    def _error_backoff(self, consecutive_errors: int) -> float:
        backoff = self._error_backoff_initial_seconds
        if backoff == 0 or consecutive_errors == 1:
            return backoff
        for _ in range(consecutive_errors - 1):
            if self._error_backoff_multiplier == 1:
                return backoff
            if (
                backoff >= self._error_backoff_max_seconds
                or backoff > self._error_backoff_max_seconds / self._error_backoff_multiplier
            ):
                return self._error_backoff_max_seconds
            backoff *= self._error_backoff_multiplier
        return min(backoff, self._error_backoff_max_seconds)

    def _wait(self, timeout_seconds: float) -> bool:
        requested = self._waiter(timeout_seconds)
        if not isinstance(requested, bool):
            raise WorkerDaemonRuntimeError("Worker daemon waiter returned an invalid result")
        return requested

    @staticmethod
    def _validate_number(
        value: float,
        field_name: str,
        *,
        minimum: float,
        maximum: float,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not minimum <= value <= maximum
        ):
            raise WorkerDaemonConfigurationError(
                f"{field_name} must be from {minimum:g} through {maximum:g}"
            )

    @staticmethod
    def _validate_optional_limit(
        value: int | None,
        field_name: str,
    ) -> None:
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1_000_000
        ):
            raise WorkerDaemonConfigurationError(
                f"{field_name} must be None or an integer from 1 through 1000000"
            )

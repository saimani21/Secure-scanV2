from __future__ import annotations

import logging
import threading
from collections.abc import Iterable

from securescan.worker import (
    WorkerCycleDisposition,
    WorkerCycleResult,
    WorkerDaemon,
    WorkerDaemonExitReason,
)


def _cycle_result(
    disposition: WorkerCycleDisposition,
) -> WorkerCycleResult:
    if disposition is WorkerCycleDisposition.IDLE:
        return WorkerCycleResult(disposition, None, None, None, None)
    tool_execution_id = (
        None
        if disposition
        in {
            WorkerCycleDisposition.CANCELLED,
            WorkerCycleDisposition.LEASE_LOST,
        }
        else "execution-id"
    )
    return WorkerCycleResult(
        disposition,
        "job-id",
        "run-id",
        1,
        tool_execution_id,
    )


class _Cycle:
    def __init__(
        self,
        outcomes: Iterable[WorkerCycleResult | Exception],
        stop_event: threading.Event | None = None,
    ) -> None:
        self.outcomes = list(outcomes)
        self.stop_event = stop_event
        self.calls = 0

    def run_one_job(self) -> WorkerCycleResult:
        returned = self.outcomes[self.calls]
        self.calls += 1
        if self.stop_event is not None:
            self.stop_event.set()
        if isinstance(returned, Exception):
            raise returned
        return returned


class _Waiter:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def __call__(self, timeout: float) -> bool:
        self.timeouts.append(timeout)
        return False


def test_worker_daemon_stops_without_running_when_event_is_pre_set() -> None:
    stop_event = threading.Event()
    stop_event.set()
    cycle = _Cycle([_cycle_result(WorkerCycleDisposition.IDLE)])

    result = WorkerDaemon(cycle, stop_event).run()

    assert result.exit_reason is WorkerDaemonExitReason.STOP_REQUESTED
    assert result.cycles_attempted == 0
    assert result.completed_cycles == 0
    assert result.errors == 0
    assert cycle.calls == 0


def test_worker_daemon_idles_interruptibly() -> None:
    waiter = _Waiter()
    cycle = _Cycle(
        [
            _cycle_result(WorkerCycleDisposition.IDLE),
            _cycle_result(WorkerCycleDisposition.IDLE),
        ]
    )

    result = WorkerDaemon(
        cycle,
        threading.Event(),
        idle_delay_seconds=3,
        max_cycles=2,
        waiter=waiter,
    ).run()

    assert result.exit_reason is WorkerDaemonExitReason.MAX_CYCLES_REACHED
    assert result.cycles_attempted == 2
    assert result.completed_cycles == 2
    assert result.idle_cycles == 2
    assert result.processed_cycles == 0
    assert waiter.timeouts == [3]


def test_worker_daemon_processes_non_idle_cycles_without_idle_delay() -> None:
    waiter = _Waiter()
    cycle = _Cycle(
        [
            _cycle_result(WorkerCycleDisposition.SUCCEEDED),
            _cycle_result(WorkerCycleDisposition.CANCELLED),
            _cycle_result(WorkerCycleDisposition.LEASE_LOST),
        ]
    )

    result = WorkerDaemon(
        cycle,
        threading.Event(),
        max_cycles=3,
        waiter=waiter,
    ).run()

    assert result.processed_cycles == 3
    assert result.cancelled_cycles == 1
    assert result.lease_lost_cycles == 1
    assert result.idle_cycles == 0
    assert waiter.timeouts == []


def test_worker_daemon_applies_exponential_error_backoff_with_cap(
    caplog,
) -> None:
    waiter = _Waiter()
    sensitive_text = "lease-token=private database-url=secret"
    cycle = _Cycle([RuntimeError(sensitive_text) for _ in range(5)])
    logger = logging.getLogger("securescan.worker.daemon.backoff-test")

    with caplog.at_level(logging.WARNING, logger=logger.name):
        result = WorkerDaemon(
            cycle,
            threading.Event(),
            error_backoff_initial_seconds=1,
            error_backoff_multiplier=2,
            error_backoff_max_seconds=4,
            max_consecutive_errors=None,
            max_cycles=5,
            waiter=waiter,
            logger=logger,
        ).run()

    assert result.errors == 5
    assert result.peak_consecutive_errors == 5
    assert waiter.timeouts == [1, 2, 4, 4]
    assert sensitive_text not in caplog.text
    assert "RuntimeError" in caplog.text


def test_successful_cycle_resets_consecutive_error_backoff() -> None:
    waiter = _Waiter()
    cycle = _Cycle(
        [
            RuntimeError("first"),
            _cycle_result(WorkerCycleDisposition.SUCCEEDED),
            RuntimeError("second"),
            _cycle_result(WorkerCycleDisposition.SUCCEEDED),
        ]
    )

    result = WorkerDaemon(
        cycle,
        threading.Event(),
        error_backoff_initial_seconds=3,
        max_consecutive_errors=None,
        max_cycles=4,
        waiter=waiter,
    ).run()

    assert result.errors == 2
    assert result.completed_cycles == 2
    assert result.peak_consecutive_errors == 1
    assert waiter.timeouts == [3, 3]


def test_worker_daemon_stops_at_consecutive_error_limit() -> None:
    waiter = _Waiter()
    cycle = _Cycle([RuntimeError("failure") for _ in range(4)])

    result = WorkerDaemon(
        cycle,
        threading.Event(),
        max_consecutive_errors=3,
        waiter=waiter,
    ).run()

    assert result.exit_reason is WorkerDaemonExitReason.ERROR_LIMIT_REACHED
    assert result.cycles_attempted == 3
    assert result.errors == 3
    assert cycle.calls == 3
    assert waiter.timeouts == [1, 2]


def test_stop_requested_during_active_cycle_drains_without_next_cycle() -> None:
    stop_event = threading.Event()
    cycle = _Cycle(
        [
            _cycle_result(WorkerCycleDisposition.SUCCEEDED),
            _cycle_result(WorkerCycleDisposition.SUCCEEDED),
        ],
        stop_event,
    )

    result = WorkerDaemon(cycle, stop_event).run()

    assert result.exit_reason is WorkerDaemonExitReason.STOP_REQUESTED
    assert result.cycles_attempted == 1
    assert result.completed_cycles == 1
    assert result.processed_cycles == 1
    assert cycle.calls == 1

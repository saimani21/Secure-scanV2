from __future__ import annotations

import logging
import threading
from collections.abc import Iterable

from securescan.maintenance import (
    MaintenanceCoordinator,
    MaintenanceCoordinatorExitReason,
    MaintenanceOperationName,
    MaintenanceTask,
    MaintenanceTaskConfiguration,
)
from securescan.worker import (
    WorkerCycleDisposition,
    WorkerCycleResult,
    WorkerDaemon,
    WorkerDaemonExitReason,
)


def _cycle_result(disposition: WorkerCycleDisposition) -> WorkerCycleResult:
    if disposition is WorkerCycleDisposition.IDLE:
        return WorkerCycleResult(disposition, None, None, None, None)
    execution_id = (
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
        execution_id,
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
        outcome = self.outcomes[self.calls]
        self.calls += 1
        if self.stop_event is not None:
            self.stop_event.set()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class _SequencedOperation:
    def __init__(self, outcomes: Iterable[int | Exception]) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    def run(self, batch_size: int) -> int:
        assert batch_size == 10
        index = min(self.calls, len(self.outcomes) - 1)
        self.calls += 1
        outcome = self.outcomes[index]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _maintenance_tasks(
    operations: tuple[_SequencedOperation, _SequencedOperation, _SequencedOperation],
    *,
    intervals: tuple[float, float, float],
) -> list[MaintenanceTask]:
    return [
        MaintenanceTask(
            MaintenanceTaskConfiguration(name, interval, 10),
            operation,
        )
        for name, interval, operation in zip(
            MaintenanceOperationName,
            intervals,
            operations,
            strict=True,
        )
    ]


def test_worker_daemon_recovers_after_transient_cycle_errors() -> None:
    waits: list[float] = []
    cycle = _Cycle(
        [
            RuntimeError("first transient failure"),
            RuntimeError("second transient failure"),
            _cycle_result(WorkerCycleDisposition.SUCCEEDED),
            _cycle_result(WorkerCycleDisposition.IDLE),
        ]
    )

    result = WorkerDaemon(
        cycle,
        threading.Event(),
        error_backoff_initial_seconds=1,
        error_backoff_multiplier=2,
        max_consecutive_errors=None,
        max_cycles=4,
        waiter=lambda timeout: waits.append(timeout) or False,
    ).run()

    assert result.exit_reason is WorkerDaemonExitReason.MAX_CYCLES_REACHED
    assert result.cycles_attempted == 4
    assert result.completed_cycles == 2
    assert result.processed_cycles == 1
    assert result.idle_cycles == 1
    assert result.errors == 2
    assert result.peak_consecutive_errors == 2
    assert waits == [1, 2]


def test_worker_daemon_stop_during_error_backoff_is_interruptible() -> None:
    stop_event = threading.Event()
    waits: list[float] = []
    cycle = _Cycle([RuntimeError("transient failure")])

    def waiter(timeout: float) -> bool:
        waits.append(timeout)
        stop_event.set()
        return True

    result = WorkerDaemon(
        cycle,
        stop_event,
        waiter=waiter,
        max_consecutive_errors=None,
    ).run()

    assert result.exit_reason is WorkerDaemonExitReason.STOP_REQUESTED
    assert result.cycles_attempted == 1
    assert result.completed_cycles == 0
    assert result.errors == 1
    assert cycle.calls == 1
    assert waits == [1]


def test_worker_daemon_stop_during_active_cycle_drains_current_result() -> None:
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


def test_maintenance_failure_can_succeed_on_later_due_pass(caplog) -> None:
    sensitive = "postgresql://admin:secret@database lease-token=private"
    clock = _Clock()
    failed_then_succeeded = _SequencedOperation([RuntimeError(sensitive), 4])
    later_operation = _SequencedOperation([2])
    final_operation = _SequencedOperation([3])
    logger = logging.getLogger("securescan.resilience.maintenance.retry")
    coordinator = MaintenanceCoordinator(
        _maintenance_tasks(
            (failed_then_succeeded, later_operation, final_operation),
            intervals=(5, 10, 10),
        ),
        threading.Event(),
        monotonic_clock=clock,
        logger=logger,
    )

    with caplog.at_level(logging.WARNING, logger=logger.name):
        first = coordinator.run_due_operations()
        clock.value = 4
        before_due = coordinator.run_due_operations()
        clock.value = 5
        second = coordinator.run_due_operations()

    assert first.operations[0].failed is True
    assert first.total_affected_jobs == 5
    assert all(not operation.attempted for operation in before_due.operations)
    assert second.operations[0].failed is False
    assert second.operations[0].affected_jobs == 4
    assert failed_then_succeeded.calls == 2
    assert later_operation.calls == 1
    assert final_operation.calls == 1
    assert sensitive not in caplog.text


def test_maintenance_repeated_failure_does_not_busy_spin() -> None:
    clock = _Clock()
    waits: list[float] = []
    failing = _SequencedOperation([RuntimeError("persistent failure")])
    other = _SequencedOperation([0])
    final = _SequencedOperation([0])

    def waiter(timeout: float) -> bool:
        waits.append(timeout)
        clock.value += timeout
        return False

    result = MaintenanceCoordinator(
        _maintenance_tasks(
            (failing, other, final),
            intervals=(2, 100, 100),
        ),
        threading.Event(),
        monotonic_clock=clock,
        waiter=waiter,
        max_sleep_seconds=1,
        max_passes=7,
    ).run()

    assert result.exit_reason is MaintenanceCoordinatorExitReason.MAX_PASSES_REACHED
    assert result.passes == 7
    assert failing.calls == 4
    assert other.calls == 1
    assert final.calls == 1
    assert waits == [1, 1, 1, 1, 1, 1]
    assert all(wait > 0 for wait in waits)


def test_safe_runtime_logs_never_include_exception_messages(caplog) -> None:
    sensitive = (
        "postgresql://admin:secret@database "
        "lease-token=00000000-private repository_password=hunter2"
    )
    daemon_logger = logging.getLogger("securescan.resilience.daemon.privacy")
    maintenance_logger = logging.getLogger("securescan.resilience.maintenance.privacy")
    operations = (
        _SequencedOperation([RuntimeError(sensitive)]),
        _SequencedOperation([0]),
        _SequencedOperation([0]),
    )

    with caplog.at_level(logging.WARNING):
        WorkerDaemon(
            _Cycle([RuntimeError(sensitive)]),
            threading.Event(),
            max_cycles=1,
            logger=daemon_logger,
        ).run()
        MaintenanceCoordinator(
            _maintenance_tasks(operations, intervals=(1, 1, 1)),
            threading.Event(),
            logger=maintenance_logger,
        ).run_due_operations()

    assert "Worker cycle failed" in caplog.text
    assert "Maintenance operation failed" in caplog.text
    assert "RuntimeError" in caplog.text
    assert "postgresql://" not in caplog.text
    assert "lease-token" not in caplog.text
    assert "repository_password" not in caplog.text
    assert "hunter2" not in caplog.text

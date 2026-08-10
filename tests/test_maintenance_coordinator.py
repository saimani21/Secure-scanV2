from __future__ import annotations

import logging
import threading

import pytest

from securescan.maintenance import (
    MaintenanceCoordinator,
    MaintenanceCoordinatorExitReason,
    MaintenanceOperationContractError,
    MaintenanceOperationName,
    MaintenanceTask,
    MaintenanceTaskConfiguration,
)


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class _Operation:
    def __init__(
        self,
        name: MaintenanceOperationName,
        events: list[MaintenanceOperationName],
        result: object = 0,
    ) -> None:
        self.name = name
        self.events = events
        self.result = result
        self.batch_sizes: list[int] = []

    def run(self, batch_size: int) -> int:
        self.events.append(self.name)
        self.batch_sizes.append(batch_size)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _tasks(
    events: list[MaintenanceOperationName],
    *,
    intervals: tuple[float, float, float] = (1, 1, 1),
    batch_sizes: tuple[int, int, int] = (10, 10, 10),
    results: tuple[object, object, object] = (0, 0, 0),
) -> tuple[list[MaintenanceTask], list[_Operation]]:
    operations = [
        _Operation(name, events, result)
        for name, result in zip(MaintenanceOperationName, results, strict=True)
    ]
    tasks = [
        MaintenanceTask(
            MaintenanceTaskConfiguration(name, interval, batch_size),
            operation,
        )
        for name, interval, batch_size, operation in zip(
            MaintenanceOperationName,
            intervals,
            batch_sizes,
            operations,
            strict=True,
        )
    ]
    return tasks, operations


def test_first_maintenance_pass_runs_all_operations_in_order() -> None:
    events: list[MaintenanceOperationName] = []
    tasks, _ = _tasks(events, results=(1, 2, 3))
    coordinator = MaintenanceCoordinator(tasks, threading.Event())

    result = coordinator.run_due_operations()

    assert events == list(MaintenanceOperationName)
    assert tuple(operation.name for operation in result.operations) == tuple(
        MaintenanceOperationName
    )
    assert all(operation.attempted for operation in result.operations)
    assert result.total_affected_jobs == 6
    assert result.failures == 0


def test_not_due_operations_are_skipped() -> None:
    events: list[MaintenanceOperationName] = []
    tasks, _ = _tasks(events)
    coordinator = MaintenanceCoordinator(
        tasks,
        threading.Event(),
        monotonic_clock=lambda: 0,
    )
    coordinator.run_due_operations()

    result = coordinator.run_due_operations()

    assert len(events) == 3
    assert all(not operation.attempted for operation in result.operations)
    assert result.total_affected_jobs == 0


def test_operations_follow_independent_intervals() -> None:
    events: list[MaintenanceOperationName] = []
    clock = _Clock()
    tasks, _ = _tasks(events, intervals=(1, 2, 3))
    coordinator = MaintenanceCoordinator(
        tasks,
        threading.Event(),
        monotonic_clock=clock,
    )
    coordinator.run_due_operations()
    events.clear()
    clock.value = 2

    result = coordinator.run_due_operations()

    assert events == [
        MaintenanceOperationName.RETRY_PROMOTION,
        MaintenanceOperationName.LEASE_RECOVERY,
    ]
    assert [operation.attempted for operation in result.operations] == [
        True,
        True,
        False,
    ]


def test_operation_failure_does_not_block_other_operations(caplog) -> None:
    events: list[MaintenanceOperationName] = []
    sensitive_text = "database-url=secret lease-token=private"
    tasks, _ = _tasks(
        events,
        results=(RuntimeError(sensitive_text), 2, 3),
    )
    logger = logging.getLogger("securescan.maintenance.failure-test")
    coordinator = MaintenanceCoordinator(
        tasks,
        threading.Event(),
        logger=logger,
    )

    with caplog.at_level(logging.WARNING, logger=logger.name):
        result = coordinator.run_due_operations()

    assert events == list(MaintenanceOperationName)
    assert result.operations[0].failed is True
    assert result.operations[0].error_type == "RuntimeError"
    assert result.total_affected_jobs == 5
    assert sensitive_text not in caplog.text


def test_batch_sizes_are_forwarded_exactly() -> None:
    events: list[MaintenanceOperationName] = []
    tasks, operations = _tasks(events, batch_sizes=(11, 22, 33))

    MaintenanceCoordinator(tasks, threading.Event()).run_due_operations()

    assert [operation.batch_sizes for operation in operations] == [[11], [22], [33]]


@pytest.mark.parametrize("invalid_count", [True, -1])
def test_invalid_operation_count_is_isolated_as_contract_failure(
    invalid_count: object,
) -> None:
    events: list[MaintenanceOperationName] = []
    tasks, _ = _tasks(events, results=(invalid_count, 2, 3))

    result = MaintenanceCoordinator(
        tasks,
        threading.Event(),
    ).run_due_operations()

    assert events == list(MaintenanceOperationName)
    assert result.operations[0].failed is True
    assert result.operations[0].error_type == MaintenanceOperationContractError.__name__
    assert result.total_affected_jobs == 5


def test_coordinator_stops_without_pass_when_event_is_pre_set() -> None:
    events: list[MaintenanceOperationName] = []
    tasks, _ = _tasks(events)
    stop_event = threading.Event()
    stop_event.set()

    result = MaintenanceCoordinator(tasks, stop_event).run()

    assert result.exit_reason is MaintenanceCoordinatorExitReason.STOP_REQUESTED
    assert result.passes == 0
    assert result.operation_attempts == 0
    assert result.affected_jobs == 0
    assert events == []


def test_coordinator_waits_for_nearest_deadline_and_respects_max_passes() -> None:
    events: list[MaintenanceOperationName] = []
    clock = _Clock()
    waits: list[float] = []
    tasks, _ = _tasks(events, intervals=(5, 7, 9))

    def waiter(timeout: float) -> bool:
        waits.append(timeout)
        clock.value += timeout
        return False

    result = MaintenanceCoordinator(
        tasks,
        threading.Event(),
        monotonic_clock=clock,
        waiter=waiter,
        max_sleep_seconds=2,
        max_passes=4,
    ).run()

    assert result.exit_reason is MaintenanceCoordinatorExitReason.MAX_PASSES_REACHED
    assert result.passes == 4
    assert waits == [2, 2, 1]
    assert all(wait > 0 for wait in waits)

from __future__ import annotations

import pytest

from securescan.domain.enums import JobStatus, RunStatus
from securescan.runs import RunAggregationError, aggregate_run_status


@pytest.mark.parametrize(
    ("active_status", "expected"),
    [
        (JobStatus.SUBMITTED, RunStatus.QUEUED),
        (JobStatus.QUEUED, RunStatus.QUEUED),
        (JobStatus.LEASED, RunStatus.RUNNING),
        (JobStatus.RUNNING, RunStatus.RUNNING),
        (JobStatus.RETRY_PENDING, RunStatus.QUEUED),
    ],
)
def test_any_active_job_keeps_run_active(
    active_status: JobStatus,
    expected: RunStatus,
) -> None:
    assert aggregate_run_status([JobStatus.SUCCEEDED, active_status]) is expected


def test_all_succeeded_jobs_complete_run() -> None:
    assert aggregate_run_status([JobStatus.SUCCEEDED] * 3) is RunStatus.COMPLETED


def test_all_cancelled_jobs_cancel_run() -> None:
    assert aggregate_run_status([JobStatus.CANCELLED] * 2) is RunStatus.CANCELLED


def test_all_failed_jobs_fail_run() -> None:
    assert aggregate_run_status([JobStatus.FAILED] * 2) is RunStatus.FAILED
    with pytest.raises(RunAggregationError):
        aggregate_run_status([])


def test_partial_job_makes_terminal_mixture_partial() -> None:
    assert (
        aggregate_run_status([JobStatus.PARTIAL, JobStatus.FAILED, JobStatus.CANCELLED])
        is RunStatus.PARTIAL
    )


@pytest.mark.parametrize(
    "statuses",
    [
        [JobStatus.SUCCEEDED, JobStatus.FAILED],
        [JobStatus.SUCCEEDED, JobStatus.CANCELLED],
        [JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED],
    ],
)
def test_success_mixed_with_failure_or_cancellation_is_partial(
    statuses: list[JobStatus],
) -> None:
    assert aggregate_run_status(statuses) is RunStatus.PARTIAL


def test_failed_and_cancelled_without_success_is_failed() -> None:
    assert aggregate_run_status([JobStatus.FAILED, JobStatus.CANCELLED]) is RunStatus.FAILED

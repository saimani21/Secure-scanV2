from __future__ import annotations

import pytest

from securescan.domain.enums import JobStatus
from securescan.domain.job_state import (
    InvalidJobTransition,
    allowed_job_transitions,
    is_terminal_job_status,
    validate_job_transition,
)


@pytest.mark.parametrize(
    ("current", "requested"),
    [
        (JobStatus.SUBMITTED, JobStatus.QUEUED),
        (JobStatus.QUEUED, JobStatus.LEASED),
        (JobStatus.LEASED, JobStatus.RUNNING),
        (JobStatus.LEASED, JobStatus.RETRY_PENDING),
        (JobStatus.LEASED, JobStatus.FAILED),
        (JobStatus.LEASED, JobStatus.CANCELLED),
        (JobStatus.RUNNING, JobStatus.SUCCEEDED),
        (JobStatus.RUNNING, JobStatus.PARTIAL),
        (JobStatus.RUNNING, JobStatus.RETRY_PENDING),
        (JobStatus.RUNNING, JobStatus.CANCELLED),
        (JobStatus.RETRY_PENDING, JobStatus.QUEUED),
        (JobStatus.RETRY_PENDING, JobStatus.CANCELLED),
        (JobStatus.SUBMITTED, JobStatus.CANCELLED),
        (JobStatus.QUEUED, JobStatus.CANCELLED),
    ],
)
def test_legal_job_transitions_are_accepted(
    current: JobStatus,
    requested: JobStatus,
):
    validate_job_transition(current, requested)


@pytest.mark.parametrize(
    ("current", "requested"),
    [
        (JobStatus.SUBMITTED, JobStatus.RUNNING),
        (JobStatus.QUEUED, JobStatus.SUCCEEDED),
        (JobStatus.LEASED, JobStatus.SUCCEEDED),
        (JobStatus.RETRY_PENDING, JobStatus.RUNNING),
        (JobStatus.SUCCEEDED, JobStatus.QUEUED),
        (JobStatus.FAILED, JobStatus.RETRY_PENDING),
        (JobStatus.CANCELLED, JobStatus.RUNNING),
    ],
)
def test_illegal_job_transitions_are_rejected(
    current: JobStatus,
    requested: JobStatus,
):
    with pytest.raises(
        InvalidJobTransition,
        match="Illegal job transition",
    ):
        validate_job_transition(current, requested)


def test_terminal_job_statuses_have_no_outgoing_transitions():
    for status in (
        JobStatus.SUCCEEDED,
        JobStatus.PARTIAL,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    ):
        assert is_terminal_job_status(status)
        assert allowed_job_transitions(status) == frozenset()

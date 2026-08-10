from __future__ import annotations

from securescan.domain.enums import JobStatus


class InvalidJobTransition(ValueError):
    """Raised when a job attempts an illegal lifecycle transition."""


TERMINAL_JOB_STATUSES = frozenset(
    {
        JobStatus.SUCCEEDED,
        JobStatus.PARTIAL,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    }
)

ALLOWED_JOB_TRANSITIONS: dict[JobStatus, frozenset[JobStatus]] = {
    JobStatus.SUBMITTED: frozenset(
        {
            JobStatus.QUEUED,
            JobStatus.CANCELLED,
        }
    ),
    JobStatus.QUEUED: frozenset(
        {
            JobStatus.LEASED,
            JobStatus.CANCELLED,
        }
    ),
    JobStatus.LEASED: frozenset(
        {
            JobStatus.RUNNING,
            JobStatus.RETRY_PENDING,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
        }
    ),
    JobStatus.RUNNING: frozenset(
        {
            JobStatus.SUCCEEDED,
            JobStatus.PARTIAL,
            JobStatus.RETRY_PENDING,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
        }
    ),
    JobStatus.RETRY_PENDING: frozenset(
        {
            JobStatus.QUEUED,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
        }
    ),
    JobStatus.SUCCEEDED: frozenset(),
    JobStatus.PARTIAL: frozenset(),
    JobStatus.FAILED: frozenset(),
    JobStatus.CANCELLED: frozenset(),
}


def is_terminal_job_status(status: JobStatus) -> bool:
    return status in TERMINAL_JOB_STATUSES


def allowed_job_transitions(status: JobStatus) -> frozenset[JobStatus]:
    return ALLOWED_JOB_TRANSITIONS[status]


def validate_job_transition(
    current: JobStatus,
    requested: JobStatus,
) -> None:
    if requested not in allowed_job_transitions(current):
        allowed = ", ".join(
            sorted(
                status.value
                for status in allowed_job_transitions(current)
            )
        )
        allowed_display = allowed or "none"

        raise InvalidJobTransition(
            f"Illegal job transition: "
            f"{current.value} -> {requested.value}; "
            f"allowed transitions: {allowed_display}"
        )
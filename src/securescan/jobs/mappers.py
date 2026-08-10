from copy import deepcopy
from datetime import UTC, datetime

from securescan.domain.enums import JobStatus
from securescan.jobs.models import JobRecord
from securescan.persistence.database import JobRow


def _normalize_utc_datetime(
    value: datetime | None,
) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def job_record_from_row(row: JobRow) -> JobRecord:
    return JobRecord(
        id=row.id,
        run_id=row.run_id,
        adapter_id=row.adapter_id,
        status=JobStatus(row.status),
        priority=row.priority,
        attempt_count=row.attempt_count,
        max_attempts=row.max_attempts,
        available_at=_normalize_utc_datetime(row.available_at),
        leased_by=row.leased_by,
        lease_expires_at=_normalize_utc_datetime(row.lease_expires_at),
        heartbeat_at=_normalize_utc_datetime(row.heartbeat_at),
        cancel_requested=row.cancel_requested,
        idempotency_key=row.idempotency_key,
        payload_json=deepcopy(row.payload_json),
        last_error=row.last_error,
        created_at=_normalize_utc_datetime(row.created_at),
        updated_at=_normalize_utc_datetime(row.updated_at),
        started_at=_normalize_utc_datetime(row.started_at),
        finished_at=_normalize_utc_datetime(row.finished_at),
        lease_token=row.lease_token,
        cancel_requested_at=_normalize_utc_datetime(row.cancel_requested_at),
    )

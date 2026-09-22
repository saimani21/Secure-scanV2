from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from securescan.api.main import app
from securescan.config import get_settings
from securescan.domain.enums import JobStatus, RunStatus, TargetType
from securescan.jobs import (
    JobCancellationService,
    JobExecutionService,
    JobFinalizationService,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
)

LEASE_TIME = datetime(2043, 2, 3, 4, 5, 6, tzinfo=UTC)
START_TIME = LEASE_TIME + timedelta(seconds=2)
CANCELLATION_TIME = LEASE_TIME + timedelta(seconds=5)
FINISH_TIME = LEASE_TIME + timedelta(seconds=10)
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-0000000000d1"))
WORKER_ID = "cancellation-api-worker"

PUBLIC_CANCELLATION_FIELDS = {
    "job_id",
    "run_id",
    "status",
    "cancel_requested",
    "cancel_requested_at",
    "finished_at",
    "immediate",
    "already_requested",
}
INTERNAL_CANCELLATION_FIELDS = {
    "leased_by",
    "lease_token",
    "lease_expires_at",
    "heartbeat_at",
    "payload_json",
    "last_error",
    "worker_id",
}


@dataclass(frozen=True, slots=True)
class _CancellationApiContext:
    client: TestClient
    session_factory: sessionmaker[Session]
    target_id: str


@pytest.fixture
def cancellation_api_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initialized_api_runtime_storage: None,
) -> Iterator[_CancellationApiContext]:
    database_url = f"sqlite:///{tmp_path / 'job-cancellation-api.db'}"
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()

    try:
        with TestClient(app) as client:
            session_factory = sessionmaker(
                bind=app.state.database_engine,
                expire_on_commit=False,
            )
            app.state.job_cancellation_service = JobCancellationService(
                session_factory,
                clock=lambda: CANCELLATION_TIME,
            )
            with session_factory.begin() as session:
                project = ProjectRow(name="Job cancellation API test")
                target = TargetRow(
                    project=project,
                    target_type=TargetType.SOURCE_REPOSITORY.value,
                    content_digest="d" * 64,
                    source_path="/tmp/cancellation-api-target",
                )
                session.add(target)
                session.flush()
                target_id = target.id

            yield _CancellationApiContext(client, session_factory, target_id)
    finally:
        get_settings.cache_clear()


def _submit_job(
    context: _CancellationApiContext,
    idempotency_key: str,
) -> dict:
    response = context.client.post(
        "/v1/jobs",
        json={
            "target_id": context.target_id,
            "adapter_id": "fake-scanner",
            "idempotency_key": idempotency_key,
            "payload_json": {"mode": "findings"},
        },
    )
    assert response.status_code == 202
    return response.json()


def _prepare_running_job(
    context: _CancellationApiContext,
    idempotency_key: str,
) -> dict:
    submitted = _submit_job(context, idempotency_key)
    app.state.job_repository.transition_job(
        job_id=submitted["job_id"],
        expected_status=JobStatus.QUEUED,
        requested_status=JobStatus.LEASED,
    )
    with context.session_factory.begin() as session:
        job = session.get(JobRow, submitted["job_id"])
        run = session.get(AnalysisRunRow, submitted["run_id"])
        assert job is not None
        assert run is not None
        job.leased_by = WORKER_ID
        job.lease_token = LEASE_TOKEN
        job.lease_expires_at = LEASE_TIME + timedelta(seconds=60)
        job.heartbeat_at = LEASE_TIME
        job.attempt_count = 1
        run.status = RunStatus.RUNNING.value
    JobExecutionService(
        context.session_factory,
        clock=lambda: START_TIME,
    ).start_job(
        submitted["job_id"],
        WORKER_ID,
        LEASE_TOKEN,
    )
    return submitted


def test_cancel_queued_job_returns_202_and_cancels_immediately(
    cancellation_api_context: _CancellationApiContext,
) -> None:
    submitted = _submit_job(cancellation_api_context, "1" * 64)

    response = cancellation_api_context.client.post(
        f"/v1/jobs/{submitted['job_id']}/cancel"
    )

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == JobStatus.CANCELLED.value
    assert body["immediate"] is True
    assert body["already_requested"] is False
    assert body["cancel_requested"] is True
    assert body["cancel_requested_at"]
    assert body["finished_at"]
    with cancellation_api_context.session_factory() as session:
        job = session.get(JobRow, submitted["job_id"])
        run = session.get(AnalysisRunRow, submitted["run_id"])
        assert job is not None
        assert run is not None
        assert job.status == JobStatus.CANCELLED.value
        assert run.status == RunStatus.CANCELLED.value


def test_cancel_running_job_returns_202_and_records_request(
    cancellation_api_context: _CancellationApiContext,
) -> None:
    submitted = _prepare_running_job(cancellation_api_context, "2" * 64)

    response = cancellation_api_context.client.post(
        f"/v1/jobs/{submitted['job_id']}/cancel"
    )

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == JobStatus.RUNNING.value
    assert body["immediate"] is False
    assert body["already_requested"] is False
    assert body["cancel_requested"] is True
    assert body["cancel_requested_at"]
    assert body["finished_at"] is None
    with cancellation_api_context.session_factory() as session:
        job = session.get(JobRow, submitted["job_id"])
        run = session.get(AnalysisRunRow, submitted["run_id"])
        assert job is not None
        assert run is not None
        assert job.leased_by == WORKER_ID
        assert job.lease_token == LEASE_TOKEN
        assert job.lease_expires_at is not None
        assert run.status == RunStatus.RUNNING.value


def test_repeated_cancel_request_is_idempotent(
    cancellation_api_context: _CancellationApiContext,
) -> None:
    submitted = _prepare_running_job(cancellation_api_context, "3" * 64)
    cancellation_url = f"/v1/jobs/{submitted['job_id']}/cancel"

    first = cancellation_api_context.client.post(cancellation_url)
    second = cancellation_api_context.client.post(cancellation_url)

    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json()["already_requested"] is False
    assert second.json()["already_requested"] is True
    assert first.json()["immediate"] is False
    assert second.json()["immediate"] is False
    assert first.json()["cancel_requested_at"] == second.json()["cancel_requested_at"]
    with cancellation_api_context.session_factory() as session:
        job = session.get(JobRow, submitted["job_id"])
        assert job is not None
        assert job.status == JobStatus.RUNNING.value
        assert job.attempt_count == 1
        assert job.cancel_requested is True


def test_cancel_already_cancelled_job_is_idempotent(
    cancellation_api_context: _CancellationApiContext,
) -> None:
    submitted = _submit_job(cancellation_api_context, "4" * 64)
    cancellation_url = f"/v1/jobs/{submitted['job_id']}/cancel"

    first = cancellation_api_context.client.post(cancellation_url)
    second = cancellation_api_context.client.post(cancellation_url)

    assert first.status_code == 202
    assert second.status_code == 202
    assert second.json()["status"] == JobStatus.CANCELLED.value
    assert second.json()["immediate"] is True
    assert second.json()["already_requested"] is True
    assert first.json()["finished_at"] == second.json()["finished_at"]


def test_cancel_unknown_job_returns_404(
    cancellation_api_context: _CancellationApiContext,
) -> None:
    response = cancellation_api_context.client.post(f"/v1/jobs/{uuid4()}/cancel")

    assert response.status_code == 404
    assert response.json()["detail"] == {
        "code": "JOB_NOT_FOUND",
        "message": "Job was not found.",
    }


def test_cancel_malformed_job_id_returns_422(
    cancellation_api_context: _CancellationApiContext,
) -> None:
    response = cancellation_api_context.client.post("/v1/jobs/not-a-uuid/cancel")

    assert response.status_code == 422
    with cancellation_api_context.session_factory() as session:
        job_count = session.scalar(select(func.count()).select_from(JobRow))
        run_count = session.scalar(select(func.count()).select_from(AnalysisRunRow))
        assert job_count == 0
        assert run_count == 0


def test_cancel_succeeded_job_returns_409(
    cancellation_api_context: _CancellationApiContext,
) -> None:
    submitted = _prepare_running_job(cancellation_api_context, "5" * 64)
    JobFinalizationService(
        cancellation_api_context.session_factory,
        clock=lambda: FINISH_TIME,
    ).finalize_job(
        submitted["job_id"],
        WORKER_ID,
        LEASE_TOKEN,
        JobStatus.SUCCEEDED,
    )
    with cancellation_api_context.session_factory() as session:
        before = session.get(JobRow, submitted["job_id"])
        assert before is not None
        finished_at = before.finished_at

    response = cancellation_api_context.client.post(
        f"/v1/jobs/{submitted['job_id']}/cancel"
    )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "JOB_CANCELLATION_CONFLICT"
    with cancellation_api_context.session_factory() as session:
        after = session.get(JobRow, submitted["job_id"])
        assert after is not None
        assert after.status == JobStatus.SUCCEEDED.value
        assert after.finished_at == finished_at


def test_cancellation_api_hides_internal_fields_and_creates_no_execution(
    cancellation_api_context: _CancellationApiContext,
) -> None:
    submitted = _submit_job(cancellation_api_context, "6" * 64)

    response = cancellation_api_context.client.post(
        f"/v1/jobs/{submitted['job_id']}/cancel"
    )

    assert response.status_code == 202
    response_fields = set(response.json())
    assert response_fields == PUBLIC_CANCELLATION_FIELDS
    assert response_fields.isdisjoint(INTERNAL_CANCELLATION_FIELDS)
    with cancellation_api_context.session_factory() as session:
        job = session.get(JobRow, submitted["job_id"])
        run = session.get(AnalysisRunRow, submitted["run_id"])
        execution_count = session.scalar(select(func.count()).select_from(ToolExecutionRow))
        assert job is not None
        assert run is not None
        assert execution_count == 0
        assert job.status == JobStatus.CANCELLED.value
        assert job.payload_json == {"mode": "findings"}
        assert run.status == RunStatus.CANCELLED.value
        assert run.report_json is None

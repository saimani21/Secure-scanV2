from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from securescan.api.main import app
from securescan.config import get_settings
from securescan.domain.enums import JobStatus, TargetType
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
)

PUBLIC_JOB_FIELDS = {
    "job_id",
    "run_id",
    "adapter_id",
    "status",
    "priority",
    "attempt_count",
    "max_attempts",
    "available_at",
    "cancel_requested",
    "idempotency_key",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
}
INTERNAL_JOB_FIELDS = {
    "payload_json",
    "leased_by",
    "lease_token",
    "lease_expires_at",
    "heartbeat_at",
    "last_error",
}


@pytest.fixture
def job_status_api_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[TestClient, sessionmaker[Session], str]]:
    database_url = f"sqlite:///{tmp_path / 'job-status-api.db'}"
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()

    try:
        with TestClient(app) as client:
            session_factory = sessionmaker(
                bind=app.state.database_engine,
                expire_on_commit=False,
            )
            with session_factory.begin() as session:
                project = ProjectRow(name="Job status API test")
                target = TargetRow(
                    project=project,
                    target_type=TargetType.SOURCE_REPOSITORY.value,
                    content_digest="f" * 64,
                    source_path="/tmp/status-api-target",
                )
                session.add(target)
                session.flush()
                target_id = target.id

            yield client, session_factory, target_id
    finally:
        get_settings.cache_clear()


def _submit_job(
    client: TestClient,
    target_id: str,
    idempotency_key: str,
) -> dict:
    response = client.post(
        "/v1/jobs",
        json={
            "target_id": target_id,
            "adapter_id": "fake-scanner",
            "idempotency_key": idempotency_key,
            "payload_json": {"mode": "findings"},
        },
    )
    assert response.status_code == 202
    return response.json()


def test_get_job_returns_queued_job(
    job_status_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, _, target_id = job_status_api_context
    submitted = _submit_job(client, target_id, "a" * 64)

    response = client.get(f"/v1/jobs/{submitted['job_id']}")

    assert response.status_code == 200
    body = response.json()
    assert body["job_id"] == submitted["job_id"]
    assert body["run_id"] == submitted["run_id"]
    assert body["adapter_id"] == "fake-scanner"
    assert body["status"] == JobStatus.QUEUED.value
    assert body["attempt_count"] == 0
    assert body["cancel_requested"] is False
    assert body["available_at"]
    assert body["created_at"]
    assert body["updated_at"]


def test_get_unknown_job_returns_404(
    job_status_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, _, _ = job_status_api_context

    response = client.get(f"/v1/jobs/{uuid4()}")

    assert response.status_code == 404
    assert response.json()["detail"] == {
        "code": "JOB_NOT_FOUND",
        "message": "Job was not found.",
    }


def test_get_malformed_job_id_returns_422(
    job_status_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, _, _ = job_status_api_context

    response = client.get("/v1/jobs/not-a-uuid")

    assert response.status_code == 422


def test_get_job_reflects_repository_transition(
    job_status_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, _, target_id = job_status_api_context
    submitted = _submit_job(client, target_id, "b" * 64)
    client.app.state.job_repository.transition_job(
        job_id=submitted["job_id"],
        expected_status=JobStatus.QUEUED,
        requested_status=JobStatus.LEASED,
    )

    response = client.get(f"/v1/jobs/{submitted['job_id']}")

    assert response.status_code == 200
    assert response.json()["status"] == JobStatus.LEASED.value


def test_get_job_does_not_execute_scanner(
    job_status_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, session_factory, target_id = job_status_api_context
    submitted = _submit_job(client, target_id, "c" * 64)

    response = client.get(f"/v1/jobs/{submitted['job_id']}")

    assert response.status_code == 200
    assert response.json()["status"] == JobStatus.QUEUED.value

    with session_factory() as session:
        run = session.get(AnalysisRunRow, submitted["run_id"])
        job = session.get(JobRow, submitted["job_id"])
        execution_count = session.scalar(select(func.count()).select_from(ToolExecutionRow))
        assert run is not None
        assert job is not None
        assert execution_count == 0
        assert run.report_json is None
        assert job.status == JobStatus.QUEUED.value


def test_get_job_hides_internal_fields(
    job_status_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, _, target_id = job_status_api_context
    submitted = _submit_job(client, target_id, "d" * 64)

    response = client.get(f"/v1/jobs/{submitted['job_id']}")

    assert response.status_code == 200
    response_fields = set(response.json())
    assert response_fields == PUBLIC_JOB_FIELDS
    assert response_fields.isdisjoint(INTERNAL_JOB_FIELDS)

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
from securescan.domain.enums import JobStatus, RunStatus, TargetType
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
)


@pytest.fixture
def job_api_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initialized_api_runtime_storage: None,
) -> Iterator[tuple[TestClient, sessionmaker[Session], str]]:
    database_url = f"sqlite:///{tmp_path / 'job-api.db'}"
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()

    try:
        with TestClient(app) as client:
            session_factory = sessionmaker(
                bind=app.state.database_engine,
                expire_on_commit=False,
            )
            with session_factory.begin() as session:
                project = ProjectRow(name="Job API test")
                target = TargetRow(
                    project=project,
                    target_type=TargetType.SOURCE_REPOSITORY.value,
                    content_digest="c" * 64,
                    source_path="/tmp/api-target",
                )
                session.add(target)
                session.flush()
                target_id = target.id

            yield client, session_factory, target_id
    finally:
        get_settings.cache_clear()


def test_post_job_returns_202_and_queued_job(
    job_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, session_factory, target_id = job_api_context
    idempotency_key = "2" * 64

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
    body = response.json()
    assert body["run_id"]
    assert body["job_id"]
    assert body["status"] == JobStatus.QUEUED.value
    assert body["created"] is True
    assert body["idempotency_key"] == idempotency_key

    with session_factory() as session:
        runs = list(session.scalars(select(AnalysisRunRow)))
        jobs = list(session.scalars(select(JobRow)))
        assert len(runs) == 1
        assert len(jobs) == 1
        assert runs[0].status == RunStatus.QUEUED.value
        assert jobs[0].status == JobStatus.QUEUED.value


def test_identical_post_returns_existing_job(
    job_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, session_factory, target_id = job_api_context
    request_json = {
        "target_id": target_id,
        "adapter_id": "fake-scanner",
        "idempotency_key": "3" * 64,
        "payload_json": {"mode": "findings"},
    }

    first = client.post("/v1/jobs", json=request_json)
    second = client.post("/v1/jobs", json=request_json)

    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json()["created"] is True
    assert second.json()["created"] is False
    assert second.json()["run_id"] == first.json()["run_id"]
    assert second.json()["job_id"] == first.json()["job_id"]

    with session_factory() as session:
        run_count = session.scalar(select(func.count()).select_from(AnalysisRunRow))
        job_count = session.scalar(select(func.count()).select_from(JobRow))
        assert run_count == 1
        assert job_count == 1


def test_reused_key_with_different_payload_returns_409(
    job_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, session_factory, target_id = job_api_context
    idempotency_key = "4" * 64
    original = {
        "target_id": target_id,
        "adapter_id": "fake-scanner",
        "idempotency_key": idempotency_key,
        "payload_json": {"mode": "original"},
    }
    client.post("/v1/jobs", json=original)

    conflicting = {
        **original,
        "payload_json": {"mode": "different"},
    }
    response = client.post("/v1/jobs", json=conflicting)

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "IDEMPOTENCY_CONFLICT"

    with session_factory() as session:
        run_count = session.scalar(select(func.count()).select_from(AnalysisRunRow))
        jobs = list(session.scalars(select(JobRow)))
        assert run_count == 1
        assert len(jobs) == 1
        assert jobs[0].payload_json == {"mode": "original"}


def test_unknown_target_returns_404(
    job_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, session_factory, _ = job_api_context

    response = client.post(
        "/v1/jobs",
        json={
            "target_id": str(uuid4()),
            "adapter_id": "fake-scanner",
            "idempotency_key": "5" * 64,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "TARGET_NOT_FOUND"

    with session_factory() as session:
        run_count = session.scalar(select(func.count()).select_from(AnalysisRunRow))
        job_count = session.scalar(select(func.count()).select_from(JobRow))
        assert run_count == 0
        assert job_count == 0


def test_invalid_priority_returns_422(
    job_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, session_factory, target_id = job_api_context

    response = client.post(
        "/v1/jobs",
        json={
            "target_id": target_id,
            "adapter_id": "fake-scanner",
            "idempotency_key": "6" * 64,
            "priority": -1,
        },
    )

    assert response.status_code == 422

    with session_factory() as session:
        run_count = session.scalar(select(func.count()).select_from(AnalysisRunRow))
        job_count = session.scalar(select(func.count()).select_from(JobRow))
        assert run_count == 0
        assert job_count == 0


def test_unknown_request_field_returns_422(
    job_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, session_factory, target_id = job_api_context

    response = client.post(
        "/v1/jobs",
        json={
            "target_id": target_id,
            "adapter_id": "fake-scanner",
            "idempotency_key": "7" * 64,
            "unexpected": "field",
        },
    )

    assert response.status_code == 422

    with session_factory() as session:
        run_count = session.scalar(select(func.count()).select_from(AnalysisRunRow))
        job_count = session.scalar(select(func.count()).select_from(JobRow))
        assert run_count == 0
        assert job_count == 0


def test_job_submission_does_not_execute_scanner(
    job_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, session_factory, target_id = job_api_context

    response = client.post(
        "/v1/jobs",
        json={
            "target_id": target_id,
            "adapter_id": "fake-scanner",
            "idempotency_key": "8" * 64,
        },
    )

    assert response.status_code == 202

    with session_factory() as session:
        runs = list(session.scalars(select(AnalysisRunRow)))
        jobs = list(session.scalars(select(JobRow)))
        execution_count = session.scalar(select(func.count()).select_from(ToolExecutionRow))
        assert len(runs) == 1
        assert len(jobs) == 1
        assert jobs[0].status == JobStatus.QUEUED.value
        assert execution_count == 0
        assert runs[0].report_json is None


@pytest.mark.parametrize(
    "payload_json",
    (
        {"__securescan_internal_source_execution__": {}},
        {"nested": {"__securescan_internal_future__": {}}},
    ),
)
def test_public_api_rejects_reserved_internal_payload_namespace(
    job_api_context: tuple[TestClient, sessionmaker[Session], str],
    payload_json: dict,
) -> None:
    client, session_factory, target_id = job_api_context

    response = client.post(
        "/v1/jobs",
        json={
            "target_id": target_id,
            "adapter_id": "semgrep-ce",
            "idempotency_key": "9" * 64,
            "payload_json": payload_json,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == {
        "code": "RESERVED_JOB_PAYLOAD",
        "message": "Reserved internal job payload is not allowed",
    }
    with session_factory() as session:
        assert session.query(AnalysisRunRow).count() == 0
        assert session.query(JobRow).count() == 0

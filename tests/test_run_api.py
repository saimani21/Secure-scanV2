from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from securescan.api.main import app
from securescan.config import get_settings
from securescan.domain.enums import (
    ExecutionOutcome,
    JobStatus,
    RunStatus,
    TargetType,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
)
from securescan.runs import RunQueryPersistenceError

NOW = datetime(2048, 2, 3, 4, 5, 6, tzinfo=UTC)


@pytest.fixture
def run_api_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initialized_api_runtime_storage: None,
) -> Iterator[tuple[TestClient, sessionmaker[Session], str]]:
    database_url = f"sqlite:///{tmp_path / 'run-api.db'}"
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()

    try:
        with TestClient(app) as client:
            factory = sessionmaker(
                bind=app.state.database_engine,
                expire_on_commit=False,
            )
            with factory.begin() as session:
                project = ProjectRow(name="Run API test")
                target = TargetRow(
                    project=project,
                    target_type=TargetType.SOURCE_REPOSITORY.value,
                    content_digest="e" * 64,
                    source_path="/tmp/run-api",
                )
                run = AnalysisRunRow(
                    target=target,
                    status=RunStatus.COMPLETED.value,
                    report_json={
                        "schema_version": "1.0.0",
                        "canonical": {"stored": True},
                    },
                    created_at=NOW,
                )
                job = JobRow(
                    run=run,
                    adapter_id="fake-scanner",
                    status=JobStatus.SUCCEEDED.value,
                    priority=10,
                    attempt_count=1,
                    max_attempts=3,
                    available_at=NOW,
                    leased_by="private-worker",
                    lease_token=str(uuid4()),
                    heartbeat_at=NOW,
                    idempotency_key="r" * 64,
                    payload_json={"credential": "private"},
                    created_at=NOW,
                    updated_at=NOW,
                    finished_at=NOW,
                )
                execution = ToolExecutionRow(
                    run=run,
                    job_id=job.id,
                    attempt_number=1,
                    adapter_id="fake-scanner",
                    adapter_version="1",
                    tool_version="1",
                    outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
                    exit_code=0,
                    duration_ms=10,
                    warning_json=[{"scanner_output": "private"}],
                    error="raw scanner output",
                )
                session.add(execution)
                session.flush()
                run_id = run.id
            yield client, factory, run_id
    finally:
        get_settings.cache_clear()


def test_get_run_returns_safe_summary(
    run_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, _, run_id = run_api_context

    response = client.get(f"/v1/runs/{run_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == run_id
    assert body["status"] == RunStatus.COMPLETED.value
    assert body["total_jobs"] == 1
    assert body["succeeded_jobs"] == 1
    assert body["has_report"] is True
    assert "report_json" not in body


def test_get_run_unknown_returns_structured_404(
    run_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, _, _ = run_api_context

    response = client.get(f"/v1/runs/{uuid4()}")

    assert response.status_code == 404
    assert response.json()["detail"] == {
        "code": "RUN_NOT_FOUND",
        "message": "Analysis run was not found.",
    }


def test_get_run_malformed_uuid_returns_422(
    run_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, _, _ = run_api_context

    assert client.get("/v1/runs/not-a-uuid").status_code == 422


def test_list_run_jobs_returns_pagination_and_hides_worker_internals(
    run_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, _, run_id = run_api_context

    response = client.get(f"/v1/runs/{run_id}/jobs?limit=10&offset=0")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["limit"] == 10
    item = body["items"][0]
    serialized = response.text
    for private_field in (
        "lease_token",
        "leased_by",
        "lease_expires_at",
        "heartbeat_at",
        "payload_json",
        "last_error",
        "idempotency_key",
    ):
        assert private_field not in item
    assert "private-worker" not in serialized
    assert "credential" not in serialized


def test_list_executions_hides_raw_execution_internals(
    run_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, _, run_id = run_api_context

    response = client.get(f"/v1/runs/{run_id}/executions")

    assert response.status_code == 200
    assert response.json()["total"] == 1
    item = response.json()["items"][0]
    assert "warning_json" not in item
    assert "error" not in item
    assert "stdout" not in item
    assert "stderr" not in item
    assert "raw scanner output" not in response.text


def test_get_report_returns_canonical_json(
    run_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, _, run_id = run_api_context

    response = client.get(f"/v1/runs/{run_id}/report")

    assert response.status_code == 200
    assert response.json() == {
        "run_id": run_id,
        "status": RunStatus.COMPLETED.value,
        "report_json": {
            "schema_version": "1.0.0",
            "canonical": {"stored": True},
        },
    }


def test_get_report_before_commit_returns_structured_409(
    run_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, factory, run_id = run_api_context
    with factory.begin() as session:
        run = session.get(AnalysisRunRow, run_id)
        assert run is not None
        run.report_json = None

    response = client.get(f"/v1/runs/{run_id}/report")

    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "RUN_REPORT_NOT_READY",
        "message": "The analysis report is not available yet.",
    }


def test_run_query_persistence_failure_returns_generic_503(
    run_api_context: tuple[TestClient, sessionmaker[Session], str],
) -> None:
    client, _, run_id = run_api_context

    class _UnavailableQuery:
        def get_run(self, _run_id: str):
            raise RunQueryPersistenceError from RuntimeError("SQL database-url=private")

    client.app.state.run_query_service = _UnavailableQuery()
    response = client.get(f"/v1/runs/{run_id}")

    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "RUN_QUERY_UNAVAILABLE",
        "message": "Analysis results are temporarily unavailable.",
    }
    assert "SQL" not in response.text
    assert "database-url" not in response.text

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from securescan.api.main import app
from securescan.config import get_settings
from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    RunStatus,
    TargetType,
)
from securescan.observability.context import CORRELATION_ID_HEADER
from securescan.observability.readiness import DatabaseReadinessSnapshot, ReadinessReason
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"
NOW = datetime(2052, 2, 3, 4, 5, 6, tzinfo=UTC)
SENSITIVE_VALUES = (
    "postgresql://",
    "SELECT ",
    "revision_id",
    "f4a8c2d17b65",
    "worker-private",
    "lease-token-private",
    "target-private",
    "raw database error",
)


@dataclass(frozen=True, slots=True)
class _ObservabilityApiContext:
    client: TestClient
    session_factory: sessionmaker[Session]


@pytest.fixture
def observability_api_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initialized_api_runtime_storage: None,
) -> Iterator[_ObservabilityApiContext]:
    database_url = f"sqlite:///{tmp_path / 'observability-api.db'}"
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("SECURESCAN_ALLOW_SQLITE_SCHEMA_BOOTSTRAP", "false")
    get_settings.cache_clear()
    config = Config(str(ALEMBIC_INI_PATH))
    config.set_main_option("script_location", str(MIGRATIONS_PATH))
    command.upgrade(config, "head")

    try:
        with TestClient(app) as client:
            factory = sessionmaker(
                bind=app.state.database_engine,
                expire_on_commit=False,
            )
            yield _ObservabilityApiContext(client, factory)
    finally:
        get_settings.cache_clear()


def _assert_safe_response(response, expected_request_id: str | None = None) -> None:
    response_request_id = response.headers[CORRELATION_ID_HEADER]
    if expected_request_id is not None:
        assert response_request_id == expected_request_id
    else:
        assert response_request_id
    for sensitive_value in SENSITIVE_VALUES:
        assert sensitive_value not in response.text


def test_liveness_does_not_require_database_check(
    observability_api_context: _ObservabilityApiContext,
) -> None:
    class _FailIfChecked:
        def check(self):
            raise AssertionError("Liveness queried database readiness")

    observability_api_context.client.app.state.database_readiness_service = _FailIfChecked()
    response = observability_api_context.client.get(
        "/health/live",
        headers={CORRELATION_ID_HEADER: "liveness-request"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
    _assert_safe_response(response, "liveness-request")


def test_ready_endpoint_returns_200_for_current_schema(
    observability_api_context: _ObservabilityApiContext,
) -> None:
    response = observability_api_context.client.get(
        "/health/ready",
        headers={CORRELATION_ID_HEADER: "readiness-request"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["database_reachable"] is True
    assert response.json()["schema_at_head"] is True
    assert response.json()["reason"] == ReadinessReason.READY.value
    assert set(response.json()) == {
        "status",
        "database_reachable",
        "schema_at_head",
        "reason",
        "checked_at",
    }
    _assert_safe_response(response, "readiness-request")


def test_ready_endpoint_returns_safe_503_for_unready_schema(
    observability_api_context: _ObservabilityApiContext,
) -> None:
    class _UnreadyService:
        def check(self) -> DatabaseReadinessSnapshot:
            return DatabaseReadinessSnapshot(
                ready=False,
                database_reachable=True,
                schema_at_head=False,
                reason=ReadinessReason.SCHEMA_OUTDATED,
                current_head_count=1,
                expected_head_count=1,
                checked_at=NOW,
            )

    observability_api_context.client.app.state.database_readiness_service = _UnreadyService()
    response = observability_api_context.client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "database_reachable": True,
        "schema_at_head": False,
        "reason": ReadinessReason.SCHEMA_OUTDATED.value,
        "checked_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    _assert_safe_response(response)


def test_metrics_endpoint_returns_safe_aggregates(
    observability_api_context: _ObservabilityApiContext,
) -> None:
    with observability_api_context.session_factory.begin() as session:
        project = ProjectRow(name="Observability API")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="c" * 64,
            source_path="/tmp/target-private",
        )
        run = AnalysisRunRow(
            target=target,
            status=RunStatus.FAILED.value,
            created_at=NOW,
        )
        job = JobRow(
            run=run,
            adapter_id="scanner",
            status=JobStatus.FAILED.value,
            idempotency_key=uuid4().hex + uuid4().hex,
            payload_json={"lease-token-private": True},
            available_at=NOW,
            created_at=NOW,
            updated_at=NOW,
            finished_at=NOW,
        )
        session.add(
            ToolExecutionRow(
                run=run,
                job_id=job.id,
                adapter_id="scanner",
                tool_version="1",
                adapter_version="1",
                outcome=ExecutionOutcome.INVALID_OUTPUT.value,
                duration_ms=25,
                failure_category=JobFailureCategory.NON_RETRYABLE_PARSER.value,
                retryable=False,
                error="raw database error",
            )
        )

    response = observability_api_context.client.get("/v1/operations/metrics")

    assert response.status_code == 200
    body = response.json()
    assert body["total_runs"] == 1
    assert body["failed_jobs"] == 1
    assert body["total_tool_executions"] == 1
    assert body["permanent_tool_failures"] == 1
    assert body["average_execution_duration_ms"] == 25.0
    assert body["failures_by_category"] == {JobFailureCategory.NON_RETRYABLE_PARSER.value: 1}
    _assert_safe_response(response)


def test_existing_health_ready_and_version_routes_remain_compatible(
    observability_api_context: _ObservabilityApiContext,
) -> None:
    request_id = "compatibility-request"
    responses = (
        observability_api_context.client.get(
            "/health",
            headers={CORRELATION_ID_HEADER: request_id},
        ),
        observability_api_context.client.get(
            "/ready",
            headers={CORRELATION_ID_HEADER: request_id},
        ),
        observability_api_context.client.get(
            "/version",
            headers={CORRELATION_ID_HEADER: request_id},
        ),
    )

    assert responses[0].status_code == 200
    assert responses[0].json() == {"status": "ok"}
    assert responses[1].status_code == 200
    assert responses[1].json()["status"] == "ready"
    assert responses[2].status_code == 200
    assert responses[2].json() == {"version": "0.1.0"}
    for response in responses:
        _assert_safe_response(response, request_id)

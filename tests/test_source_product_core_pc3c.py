from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError
from sqlalchemy import func, select

from securescan.api.main import app as main_app
from securescan.api.main import lifespan
from securescan.api.source_scan_routes import (
    cancel_scan,
    get_coverage,
    get_report,
    get_scan,
    list_components,
    list_dependencies,
    list_findings,
    list_gaps,
    router,
    submit_scan,
)
from securescan.api.source_scan_schemas import ScanSubmissionRequest
from securescan.config import get_settings
from securescan.orchestration.coordinator import SourceOrchestrationCoordinatorService
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    frozen_source_v1_authority_roster,
)
from securescan.orchestration.service import (
    SourceOrchestrationService,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceFindingLifecycleEventRow,
    SourceFindingLifecycleRow,
    SourceFindingOccurrenceRow,
    SourceLineageRunRow,
    SourceOrchestrationRow,
    SourceScanSubmissionRow,
    TargetRow,
)
from securescan.product_core import (
    InvalidScanFilterError,
    InvalidScanPaginationError,
    ProductCoreNotReadyError,
    ScanNotFoundError,
    ScanNotPublishedError,
    SourcePreparedScanRequest,
    SourceProductStatus,
    SourceScanQueryPersistenceError,
    SourceScanQueryService,
    SourceScanSubmissionService,
    SourceTrustedTargetSubmissionService,
)
from tests.test_source_orchestration_s6b import (
    _CONTROLLED_SECRET,
    _RUN_ID,
    _Environment,
)
from tests.test_source_product_core_pc3b import _Context, _context


@dataclass
class _SubmissionContext:
    environment: _Environment
    submissions: SourceScanSubmissionService
    bridge: SourceTrustedTargetSubmissionService
    queries: SourceScanQueryService
    project_id: str
    trusted_target_id: str


def _app() -> FastAPI:
    application = FastAPI()
    application.include_router(router)
    return application


def _submission_context(tmp_path: Path) -> _SubmissionContext:
    environment = _Environment(tmp_path)
    submissions = SourceScanSubmissionService(
        environment.factory,
        environment.store,
        environment.workspace_manager,
    )
    with environment.factory() as session:
        original = session.get(AnalysisRunRow, str(_RUN_ID))
        assert original is not None
        original_target = session.get(TargetRow, original.target_id)
        assert original_target is not None
        project_id = original_target.project_id
    lineage = submissions.create_lineage(project_id=project_id)
    trusted = submissions.submit_prepared(
        SourcePreparedScanRequest(
            project_id=project_id,
            lineage_id=lineage.lineage_id,
            workspace=environment.workspace,
            profile=environment.profile,
            plan=environment.plan,
            idempotency_key="a" * 64,
            deadline_at=datetime.now(UTC) + timedelta(hours=2),
        )
    )
    with environment.factory() as session:
        trusted_run = session.get(AnalysisRunRow, trusted.run_id)
        assert trusted_run is not None
        trusted_target_id = trusted_run.target_id
    orchestration = SourceOrchestrationService(
        environment.factory,
        environment.store,
        frozen_source_v1_authority_roster(),
    )
    return _SubmissionContext(
        environment=environment,
        submissions=submissions,
        bridge=SourceTrustedTargetSubmissionService(
            environment.factory, submissions, orchestration
        ),
        queries=SourceScanQueryService(environment.factory, environment.store),
        project_id=project_id,
        trusted_target_id=trusted_target_id,
    )


def _submission_body(context: _SubmissionContext, **changes: object) -> dict[str, object]:
    body: dict[str, object] = {
        "project_id": context.project_id,
        "trusted_target_id": context.trusted_target_id,
        "idempotency_key": "b" * 64,
        "deadline_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }
    body.update(changes)
    return body


def _completed(tmp_path: Path) -> _Context:
    context = _context(tmp_path)
    assert context.runner.finalize_ready().finalized_count == 1
    return context


def test_submission_uses_opaque_target_new_lineage_and_replays(tmp_path: Path) -> None:
    context = _submission_context(tmp_path)
    try:
        body = ScanSubmissionRequest.model_validate(_submission_body(context))
        first = submit_scan(body, context.bridge, context.queries)
        replay = submit_scan(body, context.bridge, context.queries)

        assert first == replay
        assert first.status is SourceProductStatus.RUNNING
        assert first.submission_sequence_number == 1
        rendered = first.model_dump_json()
        assert context.environment.workspace.root_directory.as_posix() not in rendered
        assert context.environment.workspace.workspace_id not in rendered
    finally:
        context.environment.close()


def test_submission_accepts_explicit_same_project_lineage(tmp_path: Path) -> None:
    context = _submission_context(tmp_path)
    try:
        lineage = context.submissions.create_lineage(project_id=context.project_id)
        body = ScanSubmissionRequest.model_validate(
            _submission_body(context, lineage_id=lineage.lineage_id)
        )
        result = submit_scan(body, context.bridge, context.queries)
        assert result.lineage_id == lineage.lineage_id
    finally:
        context.environment.close()


@pytest.mark.parametrize(
    ("changes", "expected_status", "expected_code"),
    [
        (
            {"trusted_target_id": "99999999-9999-4999-8999-999999999999"},
            404,
            "TARGET_NOT_FOUND",
        ),
        (
            {"project_id": "99999999-9999-4999-8999-999999999999"},
            409,
            "CONFLICT",
        ),
        (
            {"lineage_id": "99999999-9999-4999-8999-999999999999"},
            404,
            "LINEAGE_NOT_FOUND",
        ),
    ],
)
def test_submission_rejects_untrusted_or_mismatched_identity(
    tmp_path: Path,
    changes: dict[str, object],
    expected_status: int,
    expected_code: str,
) -> None:
    context = _submission_context(tmp_path)
    try:
        body = ScanSubmissionRequest.model_validate(_submission_body(context, **changes))
        with pytest.raises(HTTPException) as raised:
            submit_scan(body, context.bridge, context.queries)
        assert raised.value.status_code == expected_status
        assert raised.value.detail["code"] == expected_code
    finally:
        context.environment.close()


@pytest.mark.parametrize(
    "unsafe_field", ["path", "source_path", "repository_path", "workspace_root"]
)
def test_submission_schema_rejects_host_path_fields(tmp_path: Path, unsafe_field: str) -> None:
    context = _submission_context(tmp_path)
    try:
        body = _submission_body(context)
        body[unsafe_field] = "/etc"
        with pytest.raises(ValidationError):
            ScanSubmissionRequest.model_validate(body)
    finally:
        context.environment.close()


def test_successful_read_views_are_safe_explicit_projections(tmp_path: Path) -> None:
    context = _completed(tmp_path)
    try:
        run_id = UUID(context.run_id)
        responses = (
            get_scan(run_id, context.queries),
            list_findings(run_id, context.queries),
            list_components(run_id, context.queries, limit=1, offset=0),
            list_dependencies(run_id, context.queries, limit=1, offset=0),
            get_coverage(run_id, context.queries),
            list_gaps(run_id, context.queries, authority="gitleaks", limit=1, offset=0),
            get_report(run_id, context.queries),
        )
        rendered = "".join(response.model_dump_json() for response in responses)
        assert _CONTROLLED_SECRET.decode() not in rendered
        for forbidden in (
            "stdout_bytes",
            "stderr_bytes",
            "attempt_token",
            "lease_token",
            "cleanup_receipt",
            context.environment.workspace.root_directory.as_posix(),
            context.environment.store.root.as_posix(),
        ):
            assert forbidden not in rendered
        assert responses[1].total == 1
        assert responses[2].limit == responses[5].limit == 1
        assert responses[6].report["scope"]["source_run_id"] == context.run_id
    finally:
        context.environment.close()


def test_http_get_functions_do_not_mutate_product_core(tmp_path: Path) -> None:
    context = _completed(tmp_path)
    try:

        def snapshot() -> tuple[object, ...]:
            with context.environment.factory() as session:
                submission = session.get(SourceScanSubmissionRow, context.run_id)
                parent = session.get(SourceOrchestrationRow, context.run_id)
                assert submission is not None and parent is not None
                tables = (
                    SourceLineageRunRow,
                    SourceFindingOccurrenceRow,
                    SourceFindingLifecycleRow,
                    SourceFindingLifecycleEventRow,
                )
                counts = tuple(
                    int(session.scalar(select(func.count()).select_from(table)) or 0)
                    for table in tables
                )
                return (*counts, submission.finalized_at, parent.state_version)

        before = snapshot()
        run_id = UUID(context.run_id)
        get_scan(run_id, context.queries)
        list_findings(run_id, context.queries)
        list_components(run_id, context.queries)
        list_dependencies(run_id, context.queries)
        get_coverage(run_id, context.queries)
        list_gaps(run_id, context.queries)
        get_report(run_id, context.queries)
        assert snapshot() == before
    finally:
        context.environment.close()


@pytest.mark.parametrize("product_status", tuple(SourceProductStatus))
def test_status_route_preserves_every_product_status(
    product_status: SourceProductStatus,
) -> None:
    summary = SimpleNamespace(
        run_id="22222222-2222-4222-8222-222222222222",
        target_id="33333333-3333-4333-8333-333333333333",
        project_id="44444444-4444-4444-8444-444444444444",
        lineage_id="55555555-5555-4555-8555-555555555555",
        submission_sequence_number=1,
        predecessor_run_id=None,
        product_status=product_status,
        created_at=datetime(2026, 9, 9, tzinfo=UTC),
        published_at=None,
        finalized_at=None,
        indexed=False,
        lifecycle_evaluated=False,
        finding_count=0,
        priority_counts={},
        category_counts={},
        coverage_complete=None,
        coverage_counts={},
        gap_count=None,
    )
    queries = SimpleNamespace(get_scan=lambda _run_id: summary)
    response = get_scan(UUID(summary.run_id), queries)
    assert response.product_status is product_status


@pytest.mark.parametrize(
    ("error", "expected_status", "code", "finding_route"),
    [
        (ScanNotFoundError(), 404, "SCAN_NOT_FOUND", False),
        (ScanNotPublishedError(), 409, "SCAN_NOT_PUBLISHED", False),
        (ProductCoreNotReadyError(), 409, "PRODUCT_CORE_NOT_READY", True),
        (InvalidScanFilterError(), 422, "INVALID_FILTER", True),
        (InvalidScanPaginationError(), 422, "INVALID_PAGINATION", True),
        (SourceScanQueryPersistenceError(), 503, "QUERY_UNAVAILABLE", False),
    ],
)
def test_http_query_errors_are_fixed_and_safe(
    error: Exception, expected_status: int, code: str, finding_route: bool
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise error

    queries = SimpleNamespace(get_report=fail, list_findings=fail)
    run_id = UUID("22222222-2222-4222-8222-222222222222")
    with pytest.raises(HTTPException) as raised:
        list_findings(run_id, queries) if finding_route else get_report(run_id, queries)
    assert raised.value.status_code == expected_status
    assert raised.value.detail["code"] == code
    assert "Traceback" not in str(raised.value.detail)


def test_filters_and_pagination_are_passed_to_query_service() -> None:
    calls: list[dict[str, object]] = []

    def findings(_run_id: str, **kwargs: object) -> None:
        calls.append(kwargs)
        raise InvalidScanFilterError

    with pytest.raises(HTTPException) as raised:
        list_findings(
            UUID("22222222-2222-4222-8222-222222222222"),
            SimpleNamespace(list_findings=findings),
            authority="unknown",
            category="CODE_SECURITY",
            priority="HIGH",
            lifecycle_state="NEW",
            limit=201,
            offset=4,
        )
    assert raised.value.status_code == 422
    assert calls == [
        {
            "authority": "unknown",
            "category": "CODE_SECURITY",
            "priority": "HIGH",
            "lifecycle_state": "NEW",
            "limit": 201,
            "offset": 4,
        }
    ]


def test_cancel_reuses_coordinator_and_terminal_replay_is_idempotent() -> None:
    run_id = "22222222-2222-4222-8222-222222222222"
    coordinator = SimpleNamespace(
        request_cancellation=lambda value: SimpleNamespace(
            run_id=value, lifecycle_state=OrchestrationLifecycleState.TERMINAL
        )
    )
    queries = SimpleNamespace(
        get_scan=lambda _value: SimpleNamespace(product_status=SourceProductStatus.COMPLETED)
    )
    response = cancel_scan(UUID(run_id), coordinator, queries)
    assert response.model_dump(mode="json") == {
        "run_id": run_id,
        "status": "COMPLETED",
        "cancellation_requested": False,
        "already_terminal": True,
    }


def test_cancel_reports_accepted_active_cancellation() -> None:
    run_id = "22222222-2222-4222-8222-222222222222"
    coordinator = SimpleNamespace(
        request_cancellation=lambda value: SimpleNamespace(
            run_id=value,
            lifecycle_state=OrchestrationLifecycleState.CANCELLATION_REQUESTED,
        )
    )
    queries = SimpleNamespace(
        get_scan=lambda _value: SimpleNamespace(product_status=SourceProductStatus.CANCELLED)
    )
    response = cancel_scan(UUID(run_id), coordinator, queries)
    assert response.cancellation_requested is True
    assert response.already_terminal is False
    assert response.status is SourceProductStatus.CANCELLED


def test_normal_pc3a_scan_cancellation_uses_durable_coordinator(tmp_path: Path) -> None:
    context = _submission_context(tmp_path)
    try:
        body = ScanSubmissionRequest.model_validate(_submission_body(context))
        submission = submit_scan(body, context.bridge, context.queries)
        coordinator = SourceOrchestrationCoordinatorService(
            context.environment.factory,
            context.environment.store,
            frozen_source_v1_authority_roster(),
            context.environment.projections,
        )

        response = cancel_scan(UUID(submission.run_id), coordinator, context.queries)

        assert response.status is SourceProductStatus.CANCELLED
        assert response.cancellation_requested is True
        assert response.already_terminal is False
    finally:
        context.environment.close()


def test_non_public_orchestration_cannot_be_mutated_by_cancel_route(
    tmp_path: Path,
) -> None:
    environment = _Environment(tmp_path)
    try:
        queries = SourceScanQueryService(environment.factory, environment.store)

        def state() -> tuple[bool, datetime | None, str, int]:
            with environment.factory() as session:
                row = session.get(SourceOrchestrationRow, str(_RUN_ID))
                assert row is not None
                return (
                    row.cancel_requested,
                    row.cancel_requested_at,
                    row.lifecycle_state,
                    row.state_version,
                )

        before = state()

        def forbidden(_run_id: str) -> None:
            pytest.fail("cancellation was called before public scan validation")

        with pytest.raises(HTTPException) as raised:
            cancel_scan(
                _RUN_ID,
                SimpleNamespace(request_cancellation=forbidden),
                queries,
            )

        assert raised.value.status_code == 404
        assert raised.value.detail == {
            "code": "SCAN_NOT_FOUND",
            "message": "Source scan was not found",
        }
        assert state() == before
    finally:
        environment.close()


def test_cancel_not_found_is_safe() -> None:
    def missing(_run_id: str) -> None:
        raise ScanNotFoundError

    def forbidden(_run_id: str) -> None:
        pytest.fail("cancellation was called for a nonexistent public scan")

    with pytest.raises(HTTPException) as raised:
        cancel_scan(
            UUID("22222222-2222-4222-8222-222222222222"),
            SimpleNamespace(request_cancellation=forbidden),
            SimpleNamespace(get_scan=missing),
        )
    assert raised.value.status_code == 404
    assert raised.value.detail["code"] == "SCAN_NOT_FOUND"


def test_openapi_contains_expected_public_scan_operations() -> None:
    document = _app().openapi()
    expected = {
        "/v1/scans": {"post"},
        "/v1/scans/{run_id}": {"get"},
        "/v1/scans/{run_id}/findings": {"get"},
        "/v1/scans/{run_id}/components": {"get"},
        "/v1/scans/{run_id}/dependencies": {"get"},
        "/v1/scans/{run_id}/coverage": {"get"},
        "/v1/scans/{run_id}/gaps": {"get"},
        "/v1/scans/{run_id}/report": {"get"},
        "/v1/scans/{run_id}/cancel": {"post"},
    }
    assert {path: set(document["paths"][path]) for path in expected} == expected
    assert "202" in document["paths"]["/v1/scans"]["post"]["responses"]


def test_main_lifespan_composes_pc3c_application_services(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", f"sqlite:///{tmp_path / 'api.db'}")
    monkeypatch.setenv("SECURESCAN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    monkeypatch.setenv("SECURESCAN_SOURCE_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("SECURESCAN_SOURCE_PROJECTION_ROOT", str(tmp_path / "projections"))
    get_settings.cache_clear()

    async def verify() -> None:
        async with lifespan(main_app):
            for name in (
                "source_trusted_target_submission_service",
                "source_scan_query_service",
                "source_orchestration_coordinator_service",
            ):
                assert getattr(main_app.state, name, None) is not None
            assert "/v1/scans" in main_app.openapi()["paths"]

    try:
        asyncio.run(verify())
    finally:
        get_settings.cache_clear()

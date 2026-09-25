from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from unified_evidence_fixtures import syft_native

from securescan.evidence import EvidenceAuthority, adapt_syft_result
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceFindingLifecycleEventRow,
    SourceFindingLifecycleRow,
    SourceFindingOccurrenceRow,
    SourceLineageRunRow,
    SourceOrchestrationRow,
    SourceScanSubmissionRow,
    SourceTargetLineageRow,
    TargetRow,
)
from securescan.product_core import (
    InvalidScanFilterError,
    InvalidScanPaginationError,
    ProductCoreNotReadyError,
    ProductFinalizationOutcome,
    ProductFinalizationRunnerError,
    ScanNotFoundError,
    ScanNotPublishedError,
    SourceProductFinalizationRunner,
    SourceProductStatus,
    SourceScanQueryPersistenceError,
    SourceScanQueryService,
    SourceScanSubmissionService,
    SourceStageProgressState,
)
from securescan.product_core.dependencies import DependencyProjectionMaterial
from tests.test_source_orchestration_s6b import _CONTROLLED_SECRET, _RUN_ID, _Environment
from tests.test_source_product_core_pc1 import _clone_published_run, _publish_environment
from tests.test_source_product_core_pc2 import _clone_gitleaks_runtime, _vulnerable_osv_report

_FINALIZED_AT = datetime(2026, 9, 8, tzinfo=UTC)
_SECOND_RUN = "cccccccc-1111-4111-8111-cccccccccccc"


@dataclass
class _Context:
    environment: _Environment
    submissions: SourceScanSubmissionService
    runner: SourceProductFinalizationRunner
    queries: SourceScanQueryService
    lineage_id: str
    run_id: str


def _context(tmp_path: Path, *, published: bool = True) -> _Context:
    environment = _Environment(tmp_path)
    if published:
        _publish_environment(environment)
    with environment.factory.begin() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert run is not None
        target = session.get(TargetRow, run.target_id)
        assert target is not None
        target.source_path = environment.workspace.workspace_id
        project_id = target.project_id
    submissions = SourceScanSubmissionService(
        environment.factory,
        environment.store,
        environment.workspace_manager,
        clock=lambda: _FINALIZED_AT,
    )
    lineage = submissions.create_lineage(project_id=project_id)
    submission = submissions.reserve(
        run_id=str(_RUN_ID),
        lineage_id=lineage.lineage_id,
        intake_ref=environment.workspace.workspace_id,
    )
    return _Context(
        environment=environment,
        submissions=submissions,
        runner=SourceProductFinalizationRunner(environment.factory, submissions),
        queries=SourceScanQueryService(environment.factory, environment.store),
        lineage_id=lineage.lineage_id,
        run_id=submission.run_id,
    )


@pytest.fixture
def pending_context(tmp_path: Path):
    context = _context(tmp_path)
    try:
        yield context
    finally:
        context.environment.close()


@pytest.fixture
def completed_context(pending_context: _Context) -> _Context:
    result = pending_context.runner.finalize_ready()
    assert result.finalized_count == 1
    return pending_context


def _with_osv_stage_state(
    context: _Context,
    progress_state: SourceStageProgressState,
    *,
    reason_code: str | None = None,
):
    stages = context.queries.get_stages(context.run_id)
    matches = tuple(
        stage
        for stage in stages.stages
        if stage.authority == "osv.dev"
        and stage.capability == "dependency_advisory_matching"
    )
    assert len(matches) == 1
    return replace(
        stages,
        stages=tuple(
            replace(
                stage,
                progress_state=progress_state,
                coverage_states=(),
                reason_code=reason_code,
            )
            if stage is matches[0]
            else stage
            for stage in stages.stages
        ),
    )


def _add_second(context: _Context, monkeypatch: pytest.MonkeyPatch) -> None:
    first_report = context.submissions._index._rebuild_trusted_report(context.run_id)
    second_report = _clone_published_run(
        context.environment, first_report, _SECOND_RUN
    )
    _clone_gitleaks_runtime(context.environment, _SECOND_RUN, 71)
    context.submissions.reserve(
        run_id=_SECOND_RUN,
        lineage_id=context.lineage_id,
        intake_ref=context.environment.workspace.workspace_id,
    )
    reports = {context.run_id: first_report, _SECOND_RUN: second_report}
    monkeypatch.setattr(
        context.submissions._index, "_rebuild_trusted_report", reports.__getitem__
    )
    monkeypatch.setattr(
        context.submissions._lifecycle, "_trusted_report", reports.__getitem__
    )
    monkeypatch.setattr(
        context.queries._index,
        "load_verified_published_report",
        lambda *, run_id: reports[run_id],
    )


def test_runner_has_no_work_without_publication(tmp_path: Path) -> None:
    context = _context(tmp_path, published=False)
    try:
        result = context.runner.finalize_ready()
        assert result.examined_count == result.finalized_count == 0
        assert result.outcomes == ()
    finally:
        context.environment.close()


def test_runner_finalizes_one_published_submission_and_replay_converges(
    pending_context: _Context,
) -> None:
    first = pending_context.runner.finalize_ready()
    replay = pending_context.runner.finalize_ready()

    assert first.examined_count == first.finalized_count == 1
    assert first.outcomes[0].outcome is ProductFinalizationOutcome.FINALIZED
    assert replay.examined_count == 0
    with pending_context.environment.factory() as session:
        submission = session.get(SourceScanSubmissionRow, pending_context.run_id)
        membership = session.get(SourceLineageRunRow, pending_context.run_id)
        assert submission is not None and submission.finalized_at is not None
        assert membership is not None and membership.lifecycle_evaluated_at is not None


def test_runner_reports_already_finalized_for_a_stale_discovery(
    completed_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        completed_context.runner, "_discover", lambda _limit: (completed_context.run_id,)
    )
    result = completed_context.runner.finalize_ready()
    assert result.already_finalized_count == 1
    assert result.outcomes[0].outcome is ProductFinalizationOutcome.ALREADY_FINALIZED


@pytest.mark.parametrize("limit", [0, -1, 201, True, "1"])
def test_runner_rejects_unbounded_or_invalid_limits(
    pending_context: _Context, limit: object
) -> None:
    with pytest.raises(ProductFinalizationRunnerError):
        pending_context.runner.finalize_ready(limit=limit)  # type: ignore[arg-type]


def test_runner_keeps_successor_not_ready_when_predecessor_is_unpublished(
    pending_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    _add_second(pending_context, monkeypatch)
    with pending_context.environment.factory.begin() as session:
        first_parent = session.get(SourceOrchestrationRow, pending_context.run_id)
        assert first_parent is not None
        first_parent.published_at = None

    result = pending_context.runner.finalize_ready()

    assert [item.run_id for item in result.outcomes] == [_SECOND_RUN]
    assert result.not_ready_count == 1
    assert result.outcomes[0].outcome is ProductFinalizationOutcome.NOT_READY
    with pending_context.environment.factory() as session:
        second = session.get(SourceScanSubmissionRow, _SECOND_RUN)
        assert second is not None
        assert second.submission_sequence_number == 2
        assert second.predecessor_run_id == pending_context.run_id
        assert second.finalized_at is None


def test_runner_processes_predecessor_then_successor_in_reserved_order(
    pending_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    _add_second(pending_context, monkeypatch)
    result = pending_context.runner.finalize_ready(limit=2)

    assert [(item.run_id, item.outcome) for item in result.outcomes] == [
        (pending_context.run_id, ProductFinalizationOutcome.FINALIZED),
        (_SECOND_RUN, ProductFinalizationOutcome.FINALIZED),
    ]
    with pending_context.environment.factory() as session:
        rows = tuple(
            session.scalars(
                select(SourceLineageRunRow)
                .where(SourceLineageRunRow.lineage_id == pending_context.lineage_id)
                .order_by(SourceLineageRunRow.sequence_number)
            )
        )
    assert [(row.run_id, row.sequence_number) for row in rows] == [
        (pending_context.run_id, 1),
        (_SECOND_RUN, 2),
    ]


def test_runner_limit_bounds_discovery_in_deterministic_order(
    pending_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    _add_second(pending_context, monkeypatch)
    assert pending_context.runner._discover(1) == (pending_context.run_id,)


def test_blocked_lineage_cannot_starve_ready_work_in_another_lineage(
    pending_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = pending_context.submissions._index._rebuild_trusted_report(
        pending_context.run_id
    )
    blocked_run_ids = tuple(
        f"aaaaaaaa-2222-4222-8222-{ordinal:012d}" for ordinal in range(2, 7)
    )
    for run_id in blocked_run_ids:
        _clone_published_run(pending_context.environment, original, run_id)
        pending_context.submissions.reserve(
            run_id=run_id,
            lineage_id=pending_context.lineage_id,
            intake_ref=pending_context.environment.workspace.workspace_id,
        )

    ready_run_id = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
    ready_report = _clone_published_run(
        pending_context.environment, original, ready_run_id
    )
    _clone_gitleaks_runtime(pending_context.environment, ready_run_id, 81)
    with pending_context.environment.factory() as session:
        run = session.get(AnalysisRunRow, pending_context.run_id)
        assert run is not None
        target = session.get(TargetRow, run.target_id)
        assert target is not None
        project_id = target.project_id
    ready_lineage = pending_context.submissions.create_lineage(project_id=project_id)
    pending_context.submissions.reserve(
        run_id=ready_run_id,
        lineage_id=ready_lineage.lineage_id,
        intake_ref=pending_context.environment.workspace.workspace_id,
    )
    with pending_context.environment.factory.begin() as session:
        predecessor = session.get(SourceOrchestrationRow, pending_context.run_id)
        assert predecessor is not None
        predecessor.published_at = None

    reports = {ready_run_id: ready_report}
    monkeypatch.setattr(
        pending_context.submissions._index,
        "_rebuild_trusted_report",
        reports.__getitem__,
    )
    monkeypatch.setattr(
        pending_context.submissions._lifecycle,
        "_trusted_report",
        reports.__getitem__,
    )

    result = pending_context.runner.finalize_ready(limit=2)

    assert result.outcomes[0].run_id == ready_run_id
    assert result.outcomes[0].outcome is ProductFinalizationOutcome.FINALIZED
    assert result.outcomes[1].run_id in blocked_run_ids
    assert result.outcomes[1].outcome is ProductFinalizationOutcome.NOT_READY
    with pending_context.environment.factory() as session:
        ready = session.get(SourceScanSubmissionRow, ready_run_id)
        blocked = tuple(
            session.get(SourceScanSubmissionRow, run_id) for run_id in blocked_run_ids
        )
        assert ready is not None and ready.finalized_at is not None
        assert all(item is not None and item.finalized_at is None for item in blocked)
        assert [item.submission_sequence_number for item in blocked if item] == [
            2,
            3,
            4,
            5,
            6,
        ]


def test_runner_isolates_failure_without_corrupting_publication(
    pending_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*, run_id: str):
        raise RuntimeError(run_id)

    monkeypatch.setattr(pending_context.submissions, "finalize", fail)
    result = pending_context.runner.finalize_ready()
    assert result.failed_count == 1
    with pending_context.environment.factory() as session:
        parent = session.get(SourceOrchestrationRow, pending_context.run_id)
        submission = session.get(SourceScanSubmissionRow, pending_context.run_id)
        assert parent is not None and parent.published_at is not None
        assert submission is not None and submission.finalized_at is None


def test_query_reports_not_found_and_unpublished(tmp_path: Path) -> None:
    context = _context(tmp_path, published=False)
    try:
        with pytest.raises(ScanNotFoundError):
            context.queries.get_scan("99999999-9999-4999-8999-999999999999")
        with pytest.raises(ScanNotPublishedError):
            context.queries.get_report(context.run_id)
        assert context.queries.get_scan(context.run_id).product_status is (
            SourceProductStatus.RUNNING
        )
    finally:
        context.environment.close()


def test_query_distinguishes_queued_pending_and_completed(
    tmp_path: Path, pending_context: _Context
) -> None:
    queued_root = tmp_path / "queued"
    queued_root.mkdir()
    unpublished = _context(queued_root, published=False)
    try:
        with unpublished.environment.factory.begin() as session:
            parent = session.get(SourceOrchestrationRow, unpublished.run_id)
            assert parent is not None
            parent.lifecycle_state = "PREPARED"
        assert unpublished.queries.get_scan(unpublished.run_id).product_status is (
            SourceProductStatus.QUEUED
        )
    finally:
        unpublished.environment.close()

    assert pending_context.queries.get_scan(pending_context.run_id).product_status is (
        SourceProductStatus.PUBLISHED_PENDING_FINALIZATION
    )
    pending_context.runner.finalize_ready()
    summary = pending_context.queries.get_scan(pending_context.run_id)
    assert summary.product_status is SourceProductStatus.COMPLETED
    assert summary.indexed and summary.lifecycle_evaluated


@pytest.mark.parametrize(
    ("terminal_outcome", "expected"),
    [
        ("CANCELLED", SourceProductStatus.CANCELLED),
        ("FAILED", SourceProductStatus.FAILED),
    ],
)
def test_query_uses_durable_cancelled_and_failed_outcomes(
    tmp_path: Path, terminal_outcome: str, expected: SourceProductStatus
) -> None:
    context = _context(tmp_path, published=False)
    try:
        with context.environment.factory.begin() as session:
            parent = session.get(SourceOrchestrationRow, context.run_id)
            assert parent is not None
            parent.lifecycle_state = "TERMINAL"
            parent.terminal_outcome = terminal_outcome
        assert context.queries.get_scan(context.run_id).product_status is expected
    finally:
        context.environment.close()


def test_query_exposes_blocked_predecessor_status(
    pending_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    _add_second(pending_context, monkeypatch)
    assert pending_context.queries.get_scan(_SECOND_RUN).product_status is (
        SourceProductStatus.BLOCKED_BY_PREDECESSOR
    )


def test_query_rejects_submission_membership_identity_contradiction(
    completed_context: _Context,
) -> None:
    alternate_lineage_id = "dddddddd-3333-4333-8333-dddddddddddd"
    with completed_context.environment.factory.begin() as session:
        submission = session.get(SourceScanSubmissionRow, completed_context.run_id)
        run = session.get(AnalysisRunRow, completed_context.run_id)
        assert submission is not None and run is not None
        target = session.get(TargetRow, run.target_id)
        assert target is not None
        session.add(
            SourceTargetLineageRow(
                lineage_id=alternate_lineage_id,
                project_id=target.project_id,
                created_at=_FINALIZED_AT,
            )
        )
        session.flush()
        submission.lineage_id = alternate_lineage_id

    with pytest.raises(SourceScanQueryPersistenceError):
        completed_context.queries.get_scan(completed_context.run_id)


def test_findings_are_current_run_safe_summaries_with_filters(
    completed_context: _Context,
) -> None:
    page = completed_context.queries.list_findings(completed_context.run_id)
    finding = page.items[0]
    assert page.total == 1
    assert finding.authority == "gitleaks"
    assert finding.category == "SECRET_EXPOSURE"
    assert finding.priority_band == "HIGH"
    assert finding.lifecycle_state == "NEW"
    assert completed_context.queries.list_findings(
        completed_context.run_id, authority="gitleaks"
    ).total == 1
    assert completed_context.queries.list_findings(
        completed_context.run_id, category="CODE_SECURITY"
    ).total == 0
    assert completed_context.queries.list_findings(
        completed_context.run_id, priority="HIGH", lifecycle_state="NEW"
    ).total == 1
    assert completed_context.queries.list_findings(
        completed_context.run_id, limit=1, offset=1
    ).items == ()


def test_findings_have_deterministic_authority_category_identity_order(
    completed_context: _Context,
) -> None:
    with completed_context.environment.factory.begin() as session:
        membership = session.get(SourceLineageRunRow, completed_context.run_id)
        assert membership is not None
        finding_id = "0" * 64
        session.add(
            SourceFindingOccurrenceRow(
                run_id=completed_context.run_id,
                finding_id=finding_id,
                lineage_id=completed_context.lineage_id,
                authority="semgrep-ce",
                category="CODE_SECURITY",
                native_identity_schema="test-native-identity-v1",
                severity="LOW",
                subject_kind="SOURCE_CODE",
                subject_summary_json={"kind": "SOURCE_CODE", "rule_id": "test-rule"},
                primary_location_json={"kind": "REPOSITORY_PATH", "path": "app.py"},
                report_artifact_sha256=membership.report_artifact_sha256,
                finding_ordinal=1,
                indexed_at=_FINALIZED_AT,
                priority_band="LOW",
                priority_reason_codes_json=["SCANNER_NORMALIZED_SEVERITY"],
            )
        )
        session.add(
            SourceFindingLifecycleRow(
                lineage_id=completed_context.lineage_id,
                finding_id=finding_id,
                authority="semgrep-ce",
                category="CODE_SECURITY",
                native_identity_schema="test-native-identity-v1",
                current_state="NEW",
                first_seen_run_id=completed_context.run_id,
                last_seen_run_id=completed_context.run_id,
                resolved_run_id=None,
                first_seen_at=_FINALIZED_AT,
                last_seen_at=_FINALIZED_AT,
                resolved_at=None,
                transition_version=1,
            )
        )

    first = completed_context.queries.list_findings(completed_context.run_id)
    second = completed_context.queries.list_findings(completed_context.run_id)

    assert first == second
    assert [(item.authority, item.category, item.finding_id) for item in first.items] == sorted(
        (item.authority, item.category, item.finding_id) for item in first.items
    )


def test_findings_require_product_core_finalization(pending_context: _Context) -> None:
    with pytest.raises(ProductCoreNotReadyError):
        pending_context.queries.list_findings(pending_context.run_id)


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"limit": 0}, InvalidScanPaginationError),
        ({"limit": 201}, InvalidScanPaginationError),
        ({"offset": -1}, InvalidScanPaginationError),
        ({"authority": " gitleaks"}, InvalidScanFilterError),
        ({"authority": "unknown"}, InvalidScanFilterError),
        ({"category": ""}, InvalidScanFilterError),
    ],
)
def test_findings_reject_invalid_filters_and_pagination(
    completed_context: _Context, kwargs: dict[str, object], error: type[Exception]
) -> None:
    with pytest.raises(error):
        completed_context.queries.list_findings(  # type: ignore[arg-type]
            completed_context.run_id, **kwargs
        )


def test_components_and_clean_dependencies_come_from_authoritative_s4(
    completed_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = completed_context.submissions._index._rebuild_trusted_report(
        completed_context.run_id
    )
    result, execution_context, projection = syft_native(
        source_run_id=_SECOND_RUN, locations=("requirements.lock",)
    )
    syft = adapt_syft_result(
        result, context=execution_context, projection=projection
    )
    report = replace(
        original,
        scope=replace(original.scope, source_run_id=_SECOND_RUN),
        components=tuple(
            sorted(
                (*original.components, *syft.components),
                key=lambda item: item.component_ref,
            )
        ),
        evidence=tuple(
            sorted(
                (
                    *(
                        item
                        for item in original.evidence
                        if item.authority is not EvidenceAuthority.SYFT
                    ),
                    *syft.evidence,
                ),
                key=lambda item: item.evidence_id,
            )
        ),
        coverage_outcomes=tuple(
            sorted(
                (
                    *(
                        item
                        for item in original.coverage_outcomes
                        if item.authority
                        not in {EvidenceAuthority.SYFT, EvidenceAuthority.OSV}
                    ),
                    *syft.coverage_outcomes,
                ),
                key=lambda item: item.coverage_id,
            )
        ),
    )
    _clone_published_run(completed_context.environment, report, _SECOND_RUN)
    completed_context.submissions.reserve(
        run_id=_SECOND_RUN,
        lineage_id=completed_context.lineage_id,
        intake_ref=completed_context.environment.workspace.workspace_id,
    )
    monkeypatch.setattr(
        completed_context.queries._index,
        "load_verified_published_report",
        lambda *, run_id: report,
    )
    monkeypatch.setattr(
        completed_context.queries._dependency_projection,
        "_load_material",
        lambda _run_id: DependencyProjectionMaterial(
            fallback_evaluation="NOT_APPLICABLE",
            public_reason="NO_PACKAGES_OBSERVED",
        ),
    )
    components = completed_context.queries.list_components(_SECOND_RUN)
    dependencies = completed_context.queries.list_dependencies(_SECOND_RUN)
    assert components.total >= dependencies.total >= 1
    assert tuple(item.component_ref for item in components.items) == tuple(
        sorted(item.component_ref for item in components.items)
    )
    request = next(item for item in dependencies.items if item.name == "requests")
    assert request.version == "2.31.0"
    assert request.vulnerability_evaluation == "NOT_APPLICABLE"
    assert request.vulnerability_evaluation_reason == "NO_PACKAGES_OBSERVED"
    assert request.known_vulnerability_count is None
    assert request.advisory_aliases == ()


def test_dependency_projection_rejects_report_only_osv_relationships(
    completed_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = completed_context.submissions._index._rebuild_trusted_report(
        completed_context.run_id
    )
    report = _vulnerable_osv_report(original, _SECOND_RUN)
    _clone_published_run(completed_context.environment, report, _SECOND_RUN)
    completed_context.submissions.reserve(
        run_id=_SECOND_RUN,
        lineage_id=completed_context.lineage_id,
        intake_ref=completed_context.environment.workspace.workspace_id,
    )
    monkeypatch.setattr(
        completed_context.queries._index,
        "load_verified_published_report",
        lambda *, run_id: report,
    )

    with pytest.raises(SourceScanQueryPersistenceError):
        completed_context.queries.list_dependencies(_SECOND_RUN)


def test_dependency_projection_accepts_authoritative_not_applicable_without_osv_outcome(
    completed_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = completed_context.submissions._index._rebuild_trusted_report(
        completed_context.run_id
    )
    report = _vulnerable_osv_report(original, completed_context.run_id).canonical_data()
    report["coverage_outcomes"] = [
        outcome
        for outcome in report["coverage_outcomes"]
        if outcome["authority"] != "osv.dev"
    ]
    report["findings"] = [
        finding
        for finding in report["findings"]
        if finding["authority"] != "osv.dev"
    ]
    report["evidence"] = [
        item for item in report["evidence"] if item["authority"] != "osv.dev"
    ]
    monkeypatch.setattr(
        completed_context.queries,
        "_published_document",
        lambda _run_id: report,
    )
    monkeypatch.setattr(
        completed_context.queries._dependency_projection,
        "_load_material",
        lambda _run_id: DependencyProjectionMaterial(
            fallback_evaluation="NOT_APPLICABLE",
            public_reason="NO_PACKAGES_OBSERVED",
        ),
    )

    dependencies = completed_context.queries.list_dependencies(completed_context.run_id)

    assert dependencies.total >= 1
    request = next(item for item in dependencies.items if item.name == "requests")
    assert request.vulnerability_evaluation == "NOT_APPLICABLE"
    assert request.vulnerability_evaluation_reason == "NO_PACKAGES_OBSERVED"
    assert request.known_vulnerability_count is None


def test_dependency_projection_rejects_missing_osv_outcome_without_not_applicable_stage(
    completed_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = completed_context.submissions._index._rebuild_trusted_report(
        completed_context.run_id
    ).canonical_data()
    report["coverage_outcomes"] = [
        outcome
        for outcome in report["coverage_outcomes"]
        if outcome["authority"] != "osv.dev"
    ]
    report["findings"] = [
        finding
        for finding in report["findings"]
        if finding["authority"] != "osv.dev"
    ]
    stages = _with_osv_stage_state(
        completed_context,
        SourceStageProgressState.COMPLETE,
    )
    monkeypatch.setattr(
        completed_context.queries,
        "_published_document",
        lambda _run_id: report,
    )
    monkeypatch.setattr(
        completed_context.queries,
        "get_stages",
        lambda _run_id: stages,
    )

    with pytest.raises(SourceScanQueryPersistenceError):
        completed_context.queries.list_dependencies(completed_context.run_id)


def test_dependency_projection_rejects_missing_osv_outcome_with_osv_findings(
    completed_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = completed_context.submissions._index._rebuild_trusted_report(
        completed_context.run_id
    )
    report = _vulnerable_osv_report(
        original, completed_context.run_id
    ).canonical_data()
    report["coverage_outcomes"] = [
        outcome
        for outcome in report["coverage_outcomes"]
        if outcome["authority"] != "osv.dev"
    ]
    assert any(finding["authority"] == "osv.dev" for finding in report["findings"])
    stages = _with_osv_stage_state(
        completed_context,
        SourceStageProgressState.NOT_APPLICABLE,
    )
    monkeypatch.setattr(
        completed_context.queries,
        "_published_document",
        lambda _run_id: report,
    )
    monkeypatch.setattr(
        completed_context.queries,
        "get_stages",
        lambda _run_id: stages,
    )

    with pytest.raises(SourceScanQueryPersistenceError):
        completed_context.queries.list_dependencies(completed_context.run_id)


def test_dependency_projection_rejects_failed_state_with_osv_findings(
    completed_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = completed_context.submissions._index._rebuild_trusted_report(
        completed_context.run_id
    )
    report = _vulnerable_osv_report(
        original, completed_context.run_id
    ).canonical_data()
    osv = next(
        item for item in report["coverage_outcomes"] if item["authority"] == "osv.dev"
    )
    osv["state"] = "FAILED"
    osv["reason_code"] = "OSV_NETWORK_FAILURE"
    monkeypatch.setattr(
        completed_context.queries,
        "_published_document",
        lambda _run_id: report,
    )

    with pytest.raises(SourceScanQueryPersistenceError):
        completed_context.queries.list_dependencies(completed_context.run_id)


def test_coverage_gaps_and_report_are_separate_authoritative_views(
    completed_context: _Context,
) -> None:
    summary = completed_context.queries.get_scan(completed_context.run_id)
    coverage = completed_context.queries.get_coverage(completed_context.run_id)
    gaps = completed_context.queries.list_gaps(completed_context.run_id)
    report = completed_context.queries.get_report(completed_context.run_id)
    assert summary.product_status is SourceProductStatus.COMPLETED
    assert summary.coverage_complete == coverage.complete
    assert summary.gap_count == gaps.total
    assert report.report["scope"]["source_run_id"] == completed_context.run_id


def test_query_outputs_exclude_secret_streams_and_internal_execution_material(
    completed_context: _Context,
) -> None:
    rendered = repr(
        (
            completed_context.queries.get_scan(completed_context.run_id),
            completed_context.queries.list_findings(completed_context.run_id),
            completed_context.queries.list_components(completed_context.run_id),
            completed_context.queries.list_dependencies(completed_context.run_id),
            completed_context.queries.get_coverage(completed_context.run_id),
            completed_context.queries.list_gaps(completed_context.run_id),
            completed_context.queries.get_report(completed_context.run_id),
        )
    )
    assert _CONTROLLED_SECRET.decode() not in rendered
    for forbidden in (
        "stdout_bytes",
        "stderr_bytes",
        "lease_token",
        "attempt_token",
        "cleanup_receipt",
        "/not-persisted-in-native-result",
    ):
        assert forbidden not in rendered


def test_every_query_is_read_only(completed_context: _Context) -> None:
    def snapshot() -> tuple[int, int, int, int, datetime | None, str, int]:
        with completed_context.environment.factory() as session:
            submission = session.get(SourceScanSubmissionRow, completed_context.run_id)
            parent = session.get(SourceOrchestrationRow, completed_context.run_id)
            assert submission is not None and parent is not None
            return (
                int(session.scalar(select(func.count()).select_from(SourceLineageRunRow)) or 0),
                int(
                    session.scalar(select(func.count()).select_from(SourceFindingOccurrenceRow))
                    or 0
                ),
                int(
                    session.scalar(select(func.count()).select_from(SourceFindingLifecycleRow))
                    or 0
                ),
                int(
                    session.scalar(
                        select(func.count()).select_from(SourceFindingLifecycleEventRow)
                    )
                    or 0
                ),
                submission.finalized_at,
                parent.lifecycle_state,
                parent.state_version,
            )

    before = snapshot()
    completed_context.queries.get_scan(completed_context.run_id)
    completed_context.queries.list_findings(completed_context.run_id)
    completed_context.queries.list_components(completed_context.run_id)
    completed_context.queries.list_dependencies(completed_context.run_id)
    completed_context.queries.get_coverage(completed_context.run_id)
    completed_context.queries.list_gaps(completed_context.run_id)
    completed_context.queries.get_report(completed_context.run_id)
    assert snapshot() == before


def test_report_views_fail_closed_on_authoritative_artifact_tampering(
    completed_context: _Context,
) -> None:
    with completed_context.environment.factory() as session:
        parent = session.get(SourceOrchestrationRow, completed_context.run_id)
        assert parent is not None and parent.assembly_artifact_storage_path is not None
        path = completed_context.environment.store.root / parent.assembly_artifact_storage_path
    path.write_bytes(path.read_bytes() + b"tamper")

    with pytest.raises(SourceScanQueryPersistenceError) as raised:
        completed_context.queries.get_report(completed_context.run_id)
    assert str(path) not in str(raised.value)


@pytest.mark.parametrize(
    "method_name",
    [
        "get_scan",
        "list_components",
        "list_dependencies",
        "get_coverage",
        "list_gaps",
        "get_report",
    ],
)
def test_all_report_derived_reads_reject_db_json_drift_with_intact_cas(
    completed_context: _Context, method_name: str
) -> None:
    with completed_context.environment.factory() as session:
        parent = session.get(SourceOrchestrationRow, completed_context.run_id)
        assert parent is not None and parent.assembly_artifact_sha256 is not None
        original_cas = completed_context.environment.store.read_by_sha256(
            parent.assembly_artifact_sha256,
            expected_size_bytes=parent.assembly_artifact_size_bytes,
        )
    with completed_context.environment.factory.begin() as session:
        run = session.get(AnalysisRunRow, completed_context.run_id)
        assert run is not None and run.report_json is not None
        changed = dict(run.report_json)
        changed["unexpected_tamper"] = True
        run.report_json = changed

    method = getattr(completed_context.queries, method_name)
    with pytest.raises(SourceScanQueryPersistenceError) as raised:
        method(completed_context.run_id)
    assert str(raised.value) == "Source scan query is unavailable"
    with completed_context.environment.factory() as session:
        parent = session.get(SourceOrchestrationRow, completed_context.run_id)
        assert parent is not None and parent.assembly_artifact_sha256 is not None
        assert completed_context.environment.store.read_by_sha256(
            parent.assembly_artifact_sha256,
            expected_size_bytes=parent.assembly_artifact_size_bytes,
        ) == original_cas

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select, text

from securescan.api.source_scan_routes import router as scan_router
from securescan.domain.enums import TargetType
from securescan.orchestration.models import (
    OrchestrationContainmentState,
    OrchestrationNodeDisposition,
    OrchestrationNodeLifecycleState,
    SourceAuthority,
    SourcePlanningSnapshot,
    frozen_source_v1_authority_roster,
    orchestration_request_digest,
)
from securescan.orchestration.service import SourcePlanningSnapshotStore
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    TargetRow,
)
from securescan.product_core import (
    ScanNotFoundError,
    SourceProductStatus,
    SourceScanQueryPersistenceError,
    SourceScanQueryService,
    SourceScanStages,
    SourceScanSubmissionService,
    SourceStageProgressState,
    SourceStageSummary,
)
from securescan.source import (
    AnalysisCapability,
    AnalysisSurface,
    RepositoryComponent,
    SourcePlanAction,
    SourceSupportState,
)
from securescan.workspaces.models import repository_content_digest
from tests.postgres_test_guard import validated_postgres_test_url
from tests.test_source_orchestration_s6b import _Environment
from tests.test_source_product_core_pc3b import _Context, _context

_NOW = datetime(2026, 9, 24, 12, tzinfo=UTC)
_RUN_ID = "33333333-3333-4333-8333-333333333333"


def _node(
    lifecycle: OrchestrationNodeLifecycleState,
    disposition: OrchestrationNodeDisposition | None = None,
    reason: str | None = None,
):
    return SimpleNamespace(
        lifecycle_state=lifecycle.value,
        terminal_disposition=None if disposition is None else disposition.value,
        terminal_reason_code=reason,
    )


@pytest.mark.parametrize(
    ("lifecycle", "disposition", "expected"),
    [
        (OrchestrationNodeLifecycleState.PLANNED, None, SourceStageProgressState.PENDING),
        (OrchestrationNodeLifecycleState.READY, None, SourceStageProgressState.PENDING),
        (OrchestrationNodeLifecycleState.QUEUED, None, SourceStageProgressState.PENDING),
        (
            OrchestrationNodeLifecycleState.WAITING_DEPENDENCY,
            None,
            SourceStageProgressState.WAITING,
        ),
        (OrchestrationNodeLifecycleState.RUNNING, None, SourceStageProgressState.RUNNING),
        (
            OrchestrationNodeLifecycleState.RETRY_PENDING,
            None,
            SourceStageProgressState.RUNNING,
        ),
        (
            OrchestrationNodeLifecycleState.RECONCILIATION_REQUIRED,
            None,
            SourceStageProgressState.RUNNING,
        ),
        (
            OrchestrationNodeLifecycleState.NOT_APPLICABLE,
            None,
            SourceStageProgressState.NOT_APPLICABLE,
        ),
        (
            OrchestrationNodeLifecycleState.TERMINAL,
            OrchestrationNodeDisposition.COMPLETE,
            SourceStageProgressState.COMPLETE,
        ),
        (
            OrchestrationNodeLifecycleState.TERMINAL,
            OrchestrationNodeDisposition.PARTIAL,
            SourceStageProgressState.PARTIAL,
        ),
        (
            OrchestrationNodeLifecycleState.TERMINAL,
            OrchestrationNodeDisposition.NOT_APPLICABLE,
            SourceStageProgressState.NOT_APPLICABLE,
        ),
        (
            OrchestrationNodeLifecycleState.TERMINAL,
            OrchestrationNodeDisposition.FAILED,
            SourceStageProgressState.FAILED,
        ),
        (
            OrchestrationNodeLifecycleState.TERMINAL,
            OrchestrationNodeDisposition.BLOCKED_BY_DEPENDENCY,
            SourceStageProgressState.FAILED,
        ),
        (
            OrchestrationNodeLifecycleState.TERMINAL,
            OrchestrationNodeDisposition.CANCELLED,
            SourceStageProgressState.CANCELLED,
        ),
    ],
)
def test_internal_node_states_map_to_stable_product_progress(
    lifecycle: OrchestrationNodeLifecycleState,
    disposition: OrchestrationNodeDisposition | None,
    expected: SourceStageProgressState,
) -> None:
    summary = _stage((_node(lifecycle, disposition),))
    assert summary.progress_state is expected


def _stage(nodes, *, authority: str = "semgrep-ce", coverage_states=None):
    from securescan.product_core import SourceScanQueryService

    return SourceScanQueryService._stage_summary(
        authority=authority,
        capability="source_sast",
        nodes=tuple(nodes),
        coverage_states=coverage_states,
    )


def test_osv_waiting_progression_never_reports_waiting_as_failed() -> None:
    values = (
        _stage(
            (_node(OrchestrationNodeLifecycleState.WAITING_DEPENDENCY),),
            authority=SourceAuthority.OSV.value,
        ),
        _stage((_node(OrchestrationNodeLifecycleState.READY),), authority="osv.dev"),
        _stage((_node(OrchestrationNodeLifecycleState.RUNNING),), authority="osv.dev"),
        _stage(
            (
                _node(
                    OrchestrationNodeLifecycleState.TERMINAL,
                    OrchestrationNodeDisposition.COMPLETE,
                ),
            ),
            authority="osv.dev",
        ),
    )
    assert tuple(item.progress_state for item in values) == (
        SourceStageProgressState.WAITING,
        SourceStageProgressState.PENDING,
        SourceStageProgressState.RUNNING,
        SourceStageProgressState.COMPLETE,
    )
    assert values[0].reason_code == "WAITING_FOR_PACKAGE_INVENTORY"


@pytest.mark.parametrize(
    ("dispositions", "expected"),
    [
        ((OrchestrationNodeDisposition.COMPLETE,) * 2, SourceStageProgressState.COMPLETE),
        (
            (OrchestrationNodeDisposition.NOT_APPLICABLE,) * 2,
            SourceStageProgressState.NOT_APPLICABLE,
        ),
        ((OrchestrationNodeDisposition.CANCELLED,) * 2, SourceStageProgressState.CANCELLED),
        (
            (OrchestrationNodeDisposition.COMPLETE, OrchestrationNodeDisposition.PARTIAL),
            SourceStageProgressState.PARTIAL,
        ),
        (
            (OrchestrationNodeDisposition.COMPLETE, OrchestrationNodeDisposition.FAILED),
            SourceStageProgressState.PARTIAL,
        ),
        (
            (
                OrchestrationNodeDisposition.FAILED,
                OrchestrationNodeDisposition.BLOCKED_BY_DEPENDENCY,
            ),
            SourceStageProgressState.FAILED,
        ),
        (
            (OrchestrationNodeDisposition.COMPLETE, OrchestrationNodeDisposition.NOT_APPLICABLE),
            SourceStageProgressState.COMPLETE,
        ),
    ],
)
def test_multiple_nodes_collapse_to_one_conservative_stage(
    dispositions: tuple[OrchestrationNodeDisposition, ...],
    expected: SourceStageProgressState,
) -> None:
    summary = _stage(
        _node(OrchestrationNodeLifecycleState.TERMINAL, disposition) for disposition in dispositions
    )
    assert summary.progress_state is expected


def test_reason_codes_are_allowlisted_and_raw_failures_are_never_returned() -> None:
    blocked = _stage(
        (
            _node(
                OrchestrationNodeLifecycleState.TERMINAL,
                OrchestrationNodeDisposition.BLOCKED_BY_DEPENDENCY,
                "SYFT_NETWORK_FAILURE",
            ),
        )
    )
    failed = _stage(
        (
            _node(
                OrchestrationNodeLifecycleState.TERMINAL,
                OrchestrationNodeDisposition.FAILED,
                "/private/workspace secret stderr",
            ),
        )
    )
    no_packages = _stage(
        (
            _node(
                OrchestrationNodeLifecycleState.TERMINAL,
                OrchestrationNodeDisposition.NOT_APPLICABLE,
                "NO_PACKAGES_OBSERVED",
            ),
        ),
        authority="osv.dev",
    )
    assert blocked.reason_code == "DEPENDENCY_FAILED"
    assert failed.reason_code == "EXECUTION_FAILED"
    assert no_packages.reason_code == "NO_PACKAGES_OBSERVED"


@pytest.fixture
def live_context(tmp_path) -> _Context:
    context = _context(tmp_path, published=False)
    try:
        yield context
    finally:
        context.environment.close()


@pytest.fixture
def published_context(tmp_path) -> _Context:
    context = _context(tmp_path, published=True)
    try:
        yield context
    finally:
        context.environment.close()


def test_live_projection_has_complete_roster_waiting_osv_and_null_coverage(
    live_context: _Context,
) -> None:
    result = live_context.queries.get_stages(live_context.run_id)
    pairs = tuple((item.authority, item.capability) for item in result.stages)
    assert pairs == tuple(sorted(pairs))
    assert pairs == (
        ("checkov", "configuration_security"),
        ("gitleaks", "secret_detection"),
        ("osv.dev", "dependency_advisory_matching"),
        ("semgrep-ce", "source_sast"),
        ("syft", "package_inventory"),
    )
    assert len(set(pairs)) == len(pairs) == 5
    assert all(item.coverage_states is None for item in result.stages)
    osv = next(item for item in result.stages if item.authority == "osv.dev")
    assert osv.progress_state is SourceStageProgressState.WAITING
    assert osv.reason_code == "WAITING_FOR_PACKAGE_INVENTORY"
    assert all(
        item.progress_state is SourceStageProgressState.PENDING
        for item in result.stages
        if item.authority != "osv.dev"
    )


def test_published_projection_preserves_sorted_distinct_exact_coverage_states(
    published_context: _Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcomes = [
        {"authority": "checkov", "capability": "configuration_security", "state": "PARTIAL"},
        {
            "authority": "checkov",
            "capability": "configuration_security",
            "state": "COMPLETE_WITH_FINDINGS",
        },
        {"authority": "checkov", "capability": "configuration_security", "state": "PARTIAL"},
        {
            "authority": "checkov",
            "capability": "configuration_security",
            "state": "NOT_APPLICABLE",
        },
        {
            "authority": "semgrep-ce",
            "capability": "source_sast",
            "state": "COMPLETE_WITH_FINDINGS",
        },
    ]
    monkeypatch.setattr(
        published_context.queries,
        "_published_document",
        lambda _run_id: {"coverage_outcomes": outcomes},
    )

    result = published_context.queries.get_stages(published_context.run_id)
    by_authority = {item.authority: item for item in result.stages}
    assert by_authority["checkov"].coverage_states == (
        "COMPLETE_WITH_FINDINGS",
        "NOT_APPLICABLE",
        "PARTIAL",
    )
    assert by_authority["semgrep-ce"].coverage_states == ("COMPLETE_WITH_FINDINGS",)
    assert by_authority["gitleaks"].coverage_states == ()
    assert by_authority["checkov"].coverage_states != ("PARTIAL",)
    assert by_authority["semgrep-ce"].progress_state is SourceStageProgressState.COMPLETE


def test_published_detailed_coverage_is_unchanged_by_stage_projection(
    published_context: _Context,
) -> None:
    before = published_context.queries.get_coverage(published_context.run_id)
    stages = published_context.queries.get_stages(published_context.run_id)
    after = published_context.queries.get_coverage(published_context.run_id)
    report = published_context.queries.get_report(published_context.run_id).report
    expected = {
        (authority, capability): tuple(
            sorted(
                {
                    item["state"]
                    for item in report["coverage_outcomes"]
                    if item["authority"] == authority and item["capability"] == capability
                }
            )
        )
        for authority, capability in ((item.authority, item.capability) for item in stages.stages)
    }
    assert before == after
    assert {
        (item.authority, item.capability): item.coverage_states for item in stages.stages
    } == expected


def _omit_semgrep_from_planning(context: _Context) -> None:
    environment = context.environment
    profile = replace(
        environment.profile,
        surfaces=tuple(
            replace(item, support_state=SourceSupportState.DETECTED)
            if item.capability is AnalysisCapability.SOURCE_SAST
            else item
            for item in environment.profile.surfaces
        ),
    )
    plan = replace(
        environment.plan,
        profile_digest=profile.profile_digest(),
        entries=tuple(
            replace(
                item,
                support_state=SourceSupportState.DETECTED,
                action=SourcePlanAction.SKIP,
                reason_code="CAPABILITY_DETECTED_ONLY",
                analyzer_id=None,
                selected_paths=(),
                excluded_paths=(),
            )
            if item.capability is AnalysisCapability.SOURCE_SAST
            else item
            for item in environment.plan.entries
        ),
    )
    snapshot = SourcePlanningSnapshot.create(
        context.run_id, profile, plan, frozen_source_v1_authority_roster()
    )
    sha256, size_bytes, storage_path = SourcePlanningSnapshotStore(environment.store).put(snapshot)
    expected = {item.node_id: item for item in snapshot.nodes}
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, context.run_id)
        run = session.get(AnalysisRunRow, context.run_id)
        assert parent is not None and run is not None
        for node in tuple(
            session.scalars(
                select(SourceOrchestrationNodeRow).where(
                    SourceOrchestrationNodeRow.run_id == context.run_id
                )
            )
        ):
            planned = expected.get(node.node_id)
            if planned is None:
                session.delete(node)
                continue
            node.scope_digest = planned.scope_digest
            node.plan_entry_keys_json = list(planned.plan_entry_keys)
            node.selected_paths_json = list(planned.selected_paths)
        target = session.get(TargetRow, run.target_id)
        assert target is not None
        target.content_digest = profile.repository_digest
        parent.repository_digest = profile.repository_digest
        parent.profile_digest = profile.profile_digest()
        parent.plan_digest = plan.plan_digest()
        parent.planning_snapshot_sha256 = sha256
        parent.snapshot_size_bytes = size_bytes
        parent.snapshot_storage_path = storage_path
        deadline = parent.deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        parent.creation_request_digest = orchestration_request_digest(
            target_id=run.target_id,
            idempotency_key=parent.idempotency_key,
            deadline_iso=deadline.isoformat(),
            profile_digest=parent.profile_digest,
            plan_digest=parent.plan_digest,
            roster_digest=parent.roster_digest,
        )


def test_legitimate_no_node_capability_remains_visible_without_synthetic_coverage(
    live_context: _Context,
) -> None:
    _omit_semgrep_from_planning(live_context)
    result = live_context.queries.get_stages(live_context.run_id)
    semgrep = next(item for item in result.stages if item.authority == "semgrep-ce")
    assert semgrep.progress_state is SourceStageProgressState.NOT_APPLICABLE
    assert semgrep.coverage_states is None
    published_shape = _stage((), coverage_states=())
    assert published_shape.progress_state is SourceStageProgressState.NOT_APPLICABLE
    assert published_shape.coverage_states == ()
    assert published_shape.coverage_states != ("NOT_APPLICABLE",)


def test_unexpected_missing_node_and_non_source_identity_fail_safely(
    live_context: _Context, tmp_path
) -> None:
    with live_context.environment.factory.begin() as session:
        node = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == live_context.run_id,
                SourceOrchestrationNodeRow.authority == SourceAuthority.SEMGREP.value,
            )
        )
        assert node is not None
        session.delete(node)
    with pytest.raises(SourceScanQueryPersistenceError):
        live_context.queries.get_stages(live_context.run_id)

    other_root = tmp_path / "other"
    other_root.mkdir()
    other = _context(other_root, published=False)
    try:
        with other.environment.factory.begin() as session:
            run = session.get(AnalysisRunRow, other.run_id)
            assert run is not None
            target = session.get(TargetRow, run.target_id)
            assert target is not None
            target.target_type = TargetType.CONTAINER_IMAGE.value
        with pytest.raises(ScanNotFoundError):
            other.queries.get_stages(other.run_id)
    finally:
        other.environment.close()


def test_stage_query_count_is_fixed_when_planned_node_count_changes(
    live_context: _Context,
) -> None:
    def measure() -> int:
        statements = 0

        def count(*_args, **_kwargs) -> None:
            nonlocal statements
            statements += 1

        event.listen(live_context.environment.engine, "before_cursor_execute", count)
        try:
            live_context.queries.get_stages(live_context.run_id)
        finally:
            event.remove(live_context.environment.engine, "before_cursor_execute", count)
        return statements

    five_node_count = measure()
    _omit_semgrep_from_planning(live_context)
    four_node_count = measure()
    assert five_node_count == four_node_count
    assert five_node_count <= 20


def test_unknown_valid_run_is_not_found(live_context: _Context) -> None:
    with pytest.raises(ScanNotFoundError):
        live_context.queries.get_stages("99999999-9999-4999-8999-999999999999")


def _add_second_semgrep_component(context: _Context) -> None:
    environment = context.environment
    original = environment.profile
    app = next(item for item in original.files if item.relative_path == "app.py")
    secondary_path = "secondary/app.py"
    secondary = replace(
        app,
        entry=replace(app.entry, relative_path=secondary_path),
        component_id="secondary",
    )
    files = tuple(sorted((*original.files, secondary), key=lambda item: item.relative_path))
    components = tuple(
        sorted(
            (
                *original.components,
                RepositoryComponent(
                    component_id="secondary",
                    display_name="Secondary",
                    root_path="secondary",
                ),
            ),
            key=lambda item: item.component_id,
        )
    )
    surfaces = []
    for surface in original.surfaces:
        if surface.capability in {
            AnalysisCapability.REPOSITORY_PROFILING,
            AnalysisCapability.SECRET_DETECTION,
        }:
            surface = replace(
                surface,
                eligible_paths=tuple(sorted((*surface.eligible_paths, secondary_path))),
            )
        surfaces.append(surface)
    surfaces.append(
        AnalysisSurface(
            capability=AnalysisCapability.SOURCE_SAST,
            component_id="secondary",
            support_state=SourceSupportState.SCANNABLE,
            eligible_paths=(secondary_path,),
        )
    )
    languages = tuple(
        replace(
            item,
            file_count=item.file_count + 1,
            eligible_file_count=item.eligible_file_count + 1,
        )
        if item.language == "Python"
        else item
        for item in original.languages
    )
    profile = replace(
        original,
        repository_digest=repository_content_digest(tuple(item.entry for item in files)),
        files=files,
        components=components,
        languages=languages,
        surfaces=tuple(
            sorted(
                surfaces,
                key=lambda item: (item.capability.value, item.component_id or ""),
            )
        ),
    )
    surface_by_key = {(item.capability, item.component_id): item for item in profile.surfaces}
    entries = []
    for entry in environment.plan.entries:
        surface = surface_by_key[(entry.capability, entry.component_id)]
        entries.append(
            replace(
                entry,
                surface_paths=surface.eligible_paths,
                selected_paths=(
                    surface.eligible_paths if entry.action is SourcePlanAction.RUN else ()
                ),
            )
        )
    semgrep = next(
        item
        for item in environment.plan.entries
        if item.capability is AnalysisCapability.SOURCE_SAST
    )
    entries.append(
        replace(
            semgrep,
            component_id="secondary",
            surface_paths=(secondary_path,),
            selected_paths=(secondary_path,),
        )
    )
    plan = replace(
        environment.plan,
        repository_digest=profile.repository_digest,
        profile_digest=profile.profile_digest(),
        entries=tuple(
            sorted(entries, key=lambda item: (item.capability.value, item.component_id or ""))
        ),
    )
    snapshot = SourcePlanningSnapshot.create(
        context.run_id, profile, plan, frozen_source_v1_authority_roster()
    )
    sha256, size_bytes, storage_path = SourcePlanningSnapshotStore(environment.store).put(snapshot)
    expected = {item.node_id: item for item in snapshot.nodes}
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, context.run_id)
        run = session.get(AnalysisRunRow, context.run_id)
        assert parent is not None and run is not None
        durable = {
            item.node_id: item
            for item in session.scalars(
                select(SourceOrchestrationNodeRow).where(
                    SourceOrchestrationNodeRow.run_id == context.run_id
                )
            )
        }
        for node_id, planned in expected.items():
            node = durable.get(node_id)
            if node is None:
                session.add(
                    SourceOrchestrationNodeRow(
                        node_id=planned.node_id,
                        run_id=context.run_id,
                        authority=planned.authority.value,
                        capability=planned.capability.value,
                        component_id=planned.component_id,
                        component_key=planned.component_id or "",
                        analyzer_id=planned.analyzer_id,
                        contract_digest=planned.contract_digest,
                        plan_entry_keys_json=list(planned.plan_entry_keys),
                        selected_paths_json=list(planned.selected_paths),
                        scope_digest=planned.scope_digest,
                        lifecycle_state=planned.initial_state.value,
                        terminal_disposition=None,
                        terminal_reason_code=None,
                        containment_state=OrchestrationContainmentState.NOT_STARTED.value,
                        state_version=1,
                    )
                )
                continue
            node.scope_digest = planned.scope_digest
            node.plan_entry_keys_json = list(planned.plan_entry_keys)
            node.selected_paths_json = list(planned.selected_paths)
        target = session.get(TargetRow, run.target_id)
        assert target is not None
        target.content_digest = profile.repository_digest
        parent.repository_digest = profile.repository_digest
        parent.profile_digest = profile.profile_digest()
        parent.plan_digest = plan.plan_digest()
        parent.planning_snapshot_sha256 = sha256
        parent.snapshot_size_bytes = size_bytes
        parent.snapshot_storage_path = storage_path
        deadline = parent.deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        parent.creation_request_digest = orchestration_request_digest(
            target_id=run.target_id,
            idempotency_key=parent.idempotency_key,
            deadline_iso=deadline.isoformat(),
            profile_digest=parent.profile_digest,
            plan_digest=parent.plan_digest,
            roster_digest=parent.roster_digest,
        )


@pytest.mark.postgres
def test_postgres_live_waiting_terminal_no_node_and_non_source_parity(tmp_path) -> None:
    database_url = validated_postgres_test_url()
    reset_engine = create_engine(database_url, isolation_level="AUTOCOMMIT")
    try:
        with reset_engine.connect() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        reset_engine.dispose()

    environment = _Environment(tmp_path, database_url=database_url)
    try:
        with environment.factory.begin() as session:
            run = session.get(AnalysisRunRow, str(environment.snapshot.run_id))
            assert run is not None
            target = session.get(TargetRow, run.target_id)
            assert target is not None
            target.source_path = environment.workspace.workspace_id
            project_id = target.project_id
        submissions = SourceScanSubmissionService(
            environment.factory,
            environment.store,
            environment.workspace_manager,
            clock=lambda: _NOW,
        )
        lineage = submissions.create_lineage(project_id=project_id)
        submission = submissions.reserve(
            run_id=str(environment.snapshot.run_id),
            lineage_id=lineage.lineage_id,
            intake_ref=environment.workspace.workspace_id,
        )
        queries = SourceScanQueryService(environment.factory, environment.store)
        context = _Context(
            environment=environment,
            submissions=submissions,
            runner=SimpleNamespace(),
            queries=queries,
            lineage_id=lineage.lineage_id,
            run_id=submission.run_id,
        )

        live = queries.get_stages(context.run_id)
        osv = next(item for item in live.stages if item.authority == "osv.dev")
        assert osv.progress_state is SourceStageProgressState.WAITING
        assert all(item.coverage_states is None for item in live.stages)

        with environment.factory.begin() as session:
            gitleaks = session.scalar(
                select(SourceOrchestrationNodeRow).where(
                    SourceOrchestrationNodeRow.run_id == context.run_id,
                    SourceOrchestrationNodeRow.authority == SourceAuthority.GITLEAKS.value,
                )
            )
            assert gitleaks is not None
            gitleaks.lifecycle_state = OrchestrationNodeLifecycleState.TERMINAL.value
            gitleaks.terminal_disposition = OrchestrationNodeDisposition.COMPLETE.value
            gitleaks.state_version += 1
        terminal = queries.get_stages(context.run_id)
        assert (
            next(item for item in terminal.stages if item.authority == "gitleaks").progress_state
            is SourceStageProgressState.COMPLETE
        )

        _add_second_semgrep_component(context)
        with environment.factory.begin() as session:
            semgrep_nodes = tuple(
                session.scalars(
                    select(SourceOrchestrationNodeRow)
                    .where(
                        SourceOrchestrationNodeRow.run_id == context.run_id,
                        SourceOrchestrationNodeRow.authority == SourceAuthority.SEMGREP.value,
                    )
                    .order_by(SourceOrchestrationNodeRow.component_key)
                )
            )
            assert len(semgrep_nodes) == 2
            semgrep_nodes[0].lifecycle_state = OrchestrationNodeLifecycleState.TERMINAL.value
            semgrep_nodes[0].terminal_disposition = OrchestrationNodeDisposition.COMPLETE.value
            semgrep_nodes[0].state_version += 1
            semgrep_nodes[1].lifecycle_state = OrchestrationNodeLifecycleState.TERMINAL.value
            semgrep_nodes[1].terminal_disposition = OrchestrationNodeDisposition.FAILED.value
            semgrep_nodes[1].terminal_reason_code = "PRIVATE_FAILURE"
            semgrep_nodes[1].state_version += 1
        multi_node = queries.get_stages(context.run_id)
        semgrep_stage = tuple(item for item in multi_node.stages if item.authority == "semgrep-ce")
        assert len(semgrep_stage) == 1
        assert semgrep_stage[0].progress_state is SourceStageProgressState.PARTIAL

        _omit_semgrep_from_planning(context)
        no_node = queries.get_stages(context.run_id)
        assert (
            next(item for item in no_node.stages if item.authority == "semgrep-ce").progress_state
            is SourceStageProgressState.NOT_APPLICABLE
        )

        with environment.factory.begin() as session:
            run = session.get(AnalysisRunRow, context.run_id)
            assert run is not None
            target = session.get(TargetRow, run.target_id)
            assert target is not None
            target.target_type = TargetType.CONTAINER_IMAGE.value
        with pytest.raises(ScanNotFoundError):
            queries.get_stages(context.run_id)
    finally:
        environment.close()


class _StageQueries:
    error: Exception | None = None

    def get_stages(self, run_id: str) -> SourceScanStages:
        if self.error is not None:
            raise self.error
        return SourceScanStages(
            run_id=run_id,
            product_status=SourceProductStatus.RUNNING,
            published_at=None,
            finalized_at=None,
            stages=(
                SourceStageSummary(
                    authority="osv.dev",
                    capability="dependency_advisory_matching",
                    progress_state=SourceStageProgressState.WAITING,
                    coverage_states=None,
                    reason_code="WAITING_FOR_PACKAGE_INVENTORY",
                ),
            ),
        )


def _client() -> tuple[TestClient, _StageQueries]:
    application = FastAPI()
    application.include_router(scan_router)
    queries = _StageQueries()
    application.state.source_scan_query_service = queries
    return TestClient(application), queries


def test_stage_api_has_exact_confidential_key_set_and_safe_errors() -> None:
    client, queries = _client()
    response = client.get(f"/v1/scans/{_RUN_ID}/stages")
    malformed = client.get("/v1/scans/not-a-uuid/stages")
    queries.error = ScanNotFoundError()
    missing = client.get(f"/v1/scans/{_RUN_ID}/stages")
    queries.error = SourceScanQueryPersistenceError()
    unavailable = client.get(f"/v1/scans/{_RUN_ID}/stages")

    assert response.status_code == 200
    assert set(response.json()) == {
        "run_id",
        "product_status",
        "published_at",
        "finalized_at",
        "stages",
    }
    assert set(response.json()["stages"][0]) == {
        "authority",
        "capability",
        "progress_state",
        "coverage_states",
        "reason_code",
    }
    assert malformed.status_code == 422
    assert missing.status_code == 404
    assert unavailable.status_code == 503
    rendered = str((response.json(), missing.json(), unavailable.json()))
    for forbidden in (
        "node_id",
        "job_id",
        "attempt",
        "digest",
        "workspace",
        "stdout",
        "stderr",
        "database",
    ):
        assert forbidden not in rendered


def test_openapi_exposes_read_only_stage_contract() -> None:
    client, _queries = _client()
    document = client.get("/openapi.json").json()
    operation = document["paths"]["/v1/scans/{run_id}/stages"]
    assert set(operation) == {"get"}
    schema = document["components"]["schemas"]["StageSummaryResponse"]
    assert set(schema["properties"]) == {
        "authority",
        "capability",
        "progress_state",
        "coverage_states",
        "reason_code",
    }

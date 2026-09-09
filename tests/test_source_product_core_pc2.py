from __future__ import annotations

import hashlib
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from unified_evidence_fixtures import osv_native, syft_native

from securescan.domain.enums import ArtifactKind
from securescan.evidence import (
    CoverageState,
    EvidenceAuthority,
    GitleaksEvidencePayload,
    OsvAdvisoryGroupEvidencePayload,
    OsvCvssProjection,
    SecureScanEvidenceReport,
    adapt_osv_analysis,
    adapt_syft_result,
    build_evidence_id,
    build_finding_id,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceFindingLifecycleEventRow,
    SourceFindingLifecycleRow,
    SourceFindingOccurrenceRow,
    SourceLineageRunRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationAuthorityRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    TargetRow,
    ToolExecutionRow,
)
from securescan.product_core import (
    FindingLifecycleState,
    LifecycleEventKind,
    PriorityBand,
    ProductCoreLifecycleError,
    SourceFindingIndexService,
    SourceFindingLifecycleService,
)
from tests.test_source_orchestration_s6b import _RUN_ID, _Environment
from tests.test_source_product_core_pc1 import (
    _INDEXED_AT,
    _LINEAGE_IDS,
    _clone_published_run,
    _publish_environment,
)

_PC2_TIME = datetime(2026, 9, 2, tzinfo=UTC)
_RUN_IDS = (
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
)


@pytest.fixture
def pc2_environment(tmp_path: Path):
    environment = _Environment(tmp_path)
    _publish_environment(environment)
    try:
        yield environment
    finally:
        environment.close()


@pytest.fixture
def pc2_context(pc2_environment: _Environment):
    published_environment = pc2_environment
    index = SourceFindingIndexService(
        published_environment.factory,
        published_environment.store,
        clock=lambda: _INDEXED_AT,
        lineage_id_factory=lambda: _LINEAGE_IDS[0],
    )
    with published_environment.factory() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert run is not None
        target = session.get(TargetRow, run.target_id)
        assert target is not None
        project_id = target.project_id
    lineage = index.create_lineage(project_id=project_id)
    index.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    index.index_attached_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    lifecycle = SourceFindingLifecycleService(
        published_environment.factory,
        published_environment.store,
        clock=lambda: _PC2_TIME,
    )
    report = lifecycle._trusted_report(str(_RUN_ID))
    return published_environment, index, lifecycle, lineage, {str(_RUN_ID): report}


def _row_values(row, *, exclude: set[str]) -> dict:
    return {
        column.name: deepcopy(getattr(row, column.name))
        for column in row.__table__.columns
        if column.name not in exclude
    }


def _clone_gitleaks_runtime(environment: _Environment, run_id: str, ordinal: int) -> None:
    with environment.factory.begin() as session:
        authority = session.get(
            SourceOrchestrationAuthorityRow,
            (str(_RUN_ID), EvidenceAuthority.GITLEAKS.value),
        )
        node = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == str(_RUN_ID),
                SourceOrchestrationNodeRow.authority == EvidenceAuthority.GITLEAKS.value,
            )
        )
        assert authority is not None and node is not None
        mapping = session.scalar(
            select(SourceOrchestrationScannerJobRow).where(
                SourceOrchestrationScannerJobRow.node_id == node.node_id
            )
        )
        assert mapping is not None and mapping.selected_attempt_number is not None
        attempt = session.get(
            SourceOrchestrationAttemptRow,
            (mapping.job_id, mapping.selected_attempt_number),
        )
        job = session.get(JobRow, mapping.job_id)
        assert attempt is not None and job is not None and attempt.tool_execution_id is not None
        execution = session.get(ToolExecutionRow, attempt.tool_execution_id)
        assert execution is not None

        node_id = hashlib.sha256(f"pc2-node-{run_id}".encode()).hexdigest()
        job_id = f"{ordinal:08d}-1111-4111-8111-111111111111"
        execution_id = f"{ordinal:08d}-2222-4222-8222-222222222222"
        attempt_token = f"{ordinal:08d}-3333-4333-8333-333333333333"
        session.add(
            SourceOrchestrationAuthorityRow(
                run_id=run_id,
                **_row_values(authority, exclude={"run_id"}),
            )
        )
        session.flush()
        session.add(
            SourceOrchestrationNodeRow(
                run_id=run_id,
                node_id=node_id,
                **_row_values(node, exclude={"run_id", "node_id"}),
            )
        )
        session.flush()
        session.add(
            JobRow(
                id=job_id,
                run_id=run_id,
                **{
                    **_row_values(job, exclude={"id", "run_id", "idempotency_key"}),
                    "idempotency_key": hashlib.sha256(f"pc2-job-{run_id}".encode()).hexdigest(),
                },
            )
        )
        session.flush()
        session.add(
            SourceOrchestrationScannerJobRow(
                job_id=job_id,
                run_id=run_id,
                node_id=node_id,
                **_row_values(mapping, exclude={"job_id", "run_id", "node_id"}),
            )
        )
        session.add(
            ToolExecutionRow(
                id=execution_id,
                run_id=run_id,
                job_id=job_id,
                **_row_values(execution, exclude={"id", "run_id", "job_id"}),
            )
        )
        session.flush()
        session.add(
            SourceOrchestrationAttemptRow(
                job_id=job_id,
                run_id=run_id,
                node_id=node_id,
                attempt_token=attempt_token,
                tool_execution_id=execution_id,
                **_row_values(
                    attempt,
                    exclude={
                        "job_id",
                        "run_id",
                        "node_id",
                        "attempt_token",
                        "tool_execution_id",
                    },
                ),
            )
        )


def _vulnerable_osv_report(
    original: SecureScanEvidenceReport, run_id: str
) -> SecureScanEvidenceReport:
    result, context, projection = syft_native(
        source_run_id=run_id, locations=("requirements.lock",)
    )
    syft = adapt_syft_result(result, context=context, projection=projection)
    osv = adapt_osv_analysis(osv_native(result), scope=syft.scope)
    return replace(
        original,
        scope=replace(original.scope, source_run_id=run_id),
        components=tuple(
            sorted((*original.components, *syft.components), key=lambda item: item.component_ref)
        ),
        evidence=tuple(
            sorted(
                (*original.evidence, *syft.evidence, *osv.evidence),
                key=lambda item: item.evidence_id,
            )
        ),
        findings=tuple(
            sorted((*original.findings, *osv.findings), key=lambda item: item.finding_id)
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
                    *osv.coverage_outcomes,
                ),
                key=lambda item: item.coverage_id,
            )
        ),
    )


def _clone_accepted_runtime(
    environment: _Environment,
    run_id: str,
    authority: EvidenceAuthority,
    ordinal: int,
) -> None:
    with environment.factory.begin() as session:
        source_node = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == str(_RUN_ID),
                SourceOrchestrationNodeRow.authority == EvidenceAuthority.SYFT.value,
            )
        )
        target_node = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == str(_RUN_ID),
                SourceOrchestrationNodeRow.authority == authority.value,
            )
        )
        target_authority = session.get(
            SourceOrchestrationAuthorityRow, (str(_RUN_ID), authority.value)
        )
        assert source_node is not None and target_node is not None
        assert target_authority is not None
        source_mapping = session.scalar(
            select(SourceOrchestrationScannerJobRow).where(
                SourceOrchestrationScannerJobRow.node_id == source_node.node_id
            )
        )
        assert source_mapping is not None
        source_attempt = session.get(
            SourceOrchestrationAttemptRow,
            (source_mapping.job_id, source_mapping.selected_attempt_number),
        )
        source_job = session.get(JobRow, source_mapping.job_id)
        assert source_attempt is not None and source_job is not None
        assert source_attempt.tool_execution_id is not None
        source_execution = session.get(
            ToolExecutionRow, source_attempt.tool_execution_id
        )
        assert source_execution is not None

        node_id = hashlib.sha256(
            f"pc2-{authority.value}-{run_id}".encode()
        ).hexdigest()
        job_id = f"{ordinal:08d}-5111-4111-8111-111111111111"
        execution_id = f"{ordinal:08d}-5222-4222-8222-222222222222"
        attempt_token = f"{ordinal:08d}-5333-4333-8333-333333333333"
        session.add(
            SourceOrchestrationAuthorityRow(
                run_id=run_id,
                **_row_values(target_authority, exclude={"run_id"}),
            )
        )
        session.flush()
        session.add(
            SourceOrchestrationNodeRow(
                run_id=run_id,
                node_id=node_id,
                **{
                    **_row_values(target_node, exclude={"run_id", "node_id"}),
                    "lifecycle_state": "TERMINAL",
                    "terminal_disposition": "COMPLETE",
                    "terminal_reason_code": None,
                    "containment_state": "CLEAN",
                },
            )
        )
        session.flush()
        session.add(
            JobRow(
                id=job_id,
                run_id=run_id,
                **{
                    **_row_values(source_job, exclude={"id", "run_id", "idempotency_key"}),
                    "adapter_id": authority.value,
                    "idempotency_key": hashlib.sha256(job_id.encode()).hexdigest(),
                },
            )
        )
        session.flush()
        mapping_values = _row_values(
            source_mapping, exclude={"job_id", "run_id", "node_id"}
        )
        mapping_values.update(
            authority=target_node.authority,
            capability=target_node.capability,
            analyzer_id=target_node.analyzer_id,
            contract_digest=target_node.contract_digest,
        )
        session.add(
            SourceOrchestrationScannerJobRow(
                job_id=job_id,
                run_id=run_id,
                node_id=node_id,
                **mapping_values,
            )
        )
        session.add(
            ToolExecutionRow(
                id=execution_id,
                run_id=run_id,
                job_id=job_id,
                **{
                    **_row_values(
                        source_execution, exclude={"id", "run_id", "job_id"}
                    ),
                    "adapter_id": authority.value,
                },
            )
        )
        session.flush()
        session.add(
            SourceOrchestrationAttemptRow(
                job_id=job_id,
                run_id=run_id,
                node_id=node_id,
                attempt_token=attempt_token,
                tool_execution_id=execution_id,
                **_row_values(
                    source_attempt,
                    exclude={
                        "job_id",
                        "run_id",
                        "node_id",
                        "attempt_token",
                        "tool_execution_id",
                    },
                ),
            )
        )


def _without_gitleaks(
    report: SecureScanEvidenceReport, run_id: str
) -> SecureScanEvidenceReport:
    outcomes = tuple(
        replace(
            item,
            state=CoverageState.COMPLETE,
            finding_count=0,
        )
        if item.authority is EvidenceAuthority.GITLEAKS
        else item
        for item in report.coverage_outcomes
    )
    return replace(
        report,
        scope=replace(report.scope, source_run_id=run_id),
        evidence=tuple(
            item for item in report.evidence if item.authority is not EvidenceAuthority.GITLEAKS
        ),
        findings=tuple(
            item for item in report.findings if item.authority is not EvidenceAuthority.GITLEAKS
        ),
        coverage_outcomes=outcomes,
    )


def _add_run(
    context,
    monkeypatch: pytest.MonkeyPatch,
    run_id: str,
    *,
    present: bool,
    ordinal: int,
) -> SecureScanEvidenceReport:
    environment, index, lifecycle, lineage, reports = context
    original = reports[str(_RUN_ID)]
    report = (
        replace(original, scope=replace(original.scope, source_run_id=run_id))
        if present
        else _without_gitleaks(original, run_id)
    )
    reports[run_id] = _clone_published_run(environment, report, run_id)
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, run_id)
        assert parent is not None
        parent.published_at = _INDEXED_AT + timedelta(days=ordinal - 1)
    _clone_gitleaks_runtime(environment, run_id, ordinal)
    monkeypatch.setattr(index, "_rebuild_trusted_report", reports.__getitem__)
    monkeypatch.setattr(lifecycle, "_trusted_report", reports.__getitem__)
    index.attach_published_run(lineage_id=lineage.lineage_id, run_id=run_id)
    index.index_attached_run(lineage_id=lineage.lineage_id, run_id=run_id)
    return reports[run_id]


def _osv_lifecycle_context(
    environment: _Environment,
    monkeypatch: pytest.MonkeyPatch,
    *,
    current_osv_reason: str = "NO_PACKAGES_OBSERVED",
):
    index = SourceFindingIndexService(
        environment.factory,
        environment.store,
        clock=lambda: _INDEXED_AT,
        lineage_id_factory=lambda: _LINEAGE_IDS[0],
    )
    current_run_id = str(_RUN_ID)
    current_report = index._rebuild_trusted_report(current_run_id)
    if current_osv_reason != "NO_PACKAGES_OBSERVED":
        current_report = replace(
            current_report,
            coverage_outcomes=tuple(
                replace(item, reason_code=current_osv_reason)
                if item.authority is EvidenceAuthority.OSV
                else item
                for item in current_report.coverage_outcomes
            ),
        )
        artifact = environment.store.put(
            current_report.canonical_json(),
            kind=ArtifactKind.SOURCE_FINAL_RESULT,
            media_type="application/vnd.securescan.source-result+json",
            sanitized=True,
        )
        with environment.factory.begin() as session:
            run = session.get(AnalysisRunRow, current_run_id)
            parent = session.get(SourceOrchestrationRow, current_run_id)
            assert run is not None and parent is not None
            run.report_json = current_report.canonical_data()
            parent.assembly_artifact_sha256 = artifact.sha256
            parent.assembly_artifact_size_bytes = artifact.size_bytes
            parent.assembly_artifact_storage_path = artifact.storage_path
    predecessor_run_id = _RUN_IDS[0]
    predecessor_report = _vulnerable_osv_report(
        current_report, predecessor_run_id
    )
    predecessor_report = _clone_published_run(
        environment, predecessor_report, predecessor_run_id
    )
    with environment.factory.begin() as session:
        predecessor_parent = session.get(SourceOrchestrationRow, predecessor_run_id)
        current_parent = session.get(SourceOrchestrationRow, current_run_id)
        assert predecessor_parent is not None and current_parent is not None
        predecessor_parent.published_at = _INDEXED_AT
        current_parent.published_at = _INDEXED_AT + timedelta(days=1)
    _clone_accepted_runtime(
        environment, predecessor_run_id, EvidenceAuthority.SYFT, 21
    )
    _clone_accepted_runtime(
        environment, predecessor_run_id, EvidenceAuthority.OSV, 22
    )
    reports = {
        predecessor_run_id: predecessor_report,
        current_run_id: current_report,
    }
    monkeypatch.setattr(index, "_rebuild_trusted_report", reports.__getitem__)
    with environment.factory() as session:
        current_run = session.get(AnalysisRunRow, current_run_id)
        assert current_run is not None
        target = session.get(TargetRow, current_run.target_id)
        assert target is not None
        project_id = target.project_id
    lineage = index.create_lineage(project_id=project_id)
    index.attach_published_run(
        lineage_id=lineage.lineage_id, run_id=predecessor_run_id
    )
    index.index_attached_run(
        lineage_id=lineage.lineage_id, run_id=predecessor_run_id
    )
    index.attach_published_run(lineage_id=lineage.lineage_id, run_id=current_run_id)
    index.index_attached_run(lineage_id=lineage.lineage_id, run_id=current_run_id)
    lifecycle = SourceFindingLifecycleService(
        environment.factory, environment.store, clock=lambda: _PC2_TIME
    )
    monkeypatch.setattr(lifecycle, "_trusted_report", reports.__getitem__)
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=predecessor_run_id)
    osv_finding = next(
        item
        for item in predecessor_report.findings
        if item.authority is EvidenceAuthority.OSV
    )
    assert lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=osv_finding.finding_id
    ).current_state is FindingLifecycleState.NEW
    return index, lifecycle, lineage, reports, osv_finding


def test_first_run_is_new_and_duplicate_evaluation_is_idempotent(pc2_context) -> None:
    _environment, _index, lifecycle, lineage, reports = pc2_context
    finding_id = reports[str(_RUN_ID)].findings[0].finding_id
    first = lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    duplicate = lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    state = lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=finding_id
    )
    events = lifecycle.list_events(
        lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
    )
    assert first.created is True and duplicate.created is False
    assert first.evaluation_sha256 == duplicate.evaluation_sha256
    assert state.current_state is FindingLifecycleState.NEW
    assert state.first_seen_run_id == state.last_seen_run_id == str(_RUN_ID)
    assert state.resolved_run_id is None
    assert state.first_seen_at == state.last_seen_at == _INDEXED_AT
    assert state.transition_version == 1
    assert events[0].resulting_state is FindingLifecycleState.NEW
    assert events[0].created_at == _INDEXED_AT
    assert first.evaluated_at == _PC2_TIME


def test_existing_resolved_reopened_and_existing_history(
    pc2_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    _environment, _index, lifecycle, lineage, reports = pc2_context
    finding_id = reports[str(_RUN_ID)].findings[0].finding_id
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))

    _add_run(pc2_context, monkeypatch, _RUN_IDS[0], present=True, ordinal=2)
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=_RUN_IDS[0])
    assert lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=finding_id
    ).current_state is FindingLifecycleState.EXISTING

    _add_run(pc2_context, monkeypatch, _RUN_IDS[1], present=False, ordinal=3)
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=_RUN_IDS[1])
    resolved = lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=finding_id
    )
    assert resolved.current_state is FindingLifecycleState.RESOLVED
    assert resolved.resolved_run_id == _RUN_IDS[1]
    assert resolved.last_seen_run_id == _RUN_IDS[0]
    assert resolved.last_seen_at == _INDEXED_AT + timedelta(days=1)
    assert resolved.resolved_at == _INDEXED_AT + timedelta(days=2)

    _add_run(pc2_context, monkeypatch, _RUN_IDS[2], present=True, ordinal=4)
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=_RUN_IDS[2])
    reopened = lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=finding_id
    )
    assert reopened.current_state is FindingLifecycleState.REOPENED
    assert reopened.resolved_run_id is None and reopened.resolved_at is None
    assert reopened.first_seen_run_id == str(_RUN_ID)
    assert reopened.last_seen_run_id == _RUN_IDS[2]
    assert reopened.first_seen_at == _INDEXED_AT
    assert reopened.last_seen_at == _INDEXED_AT + timedelta(days=3)
    assert reopened.transition_version == 4
    resolved_event = lifecycle.list_events(
        lineage_id=lineage.lineage_id, run_id=_RUN_IDS[1]
    )[0]
    assert resolved_event.resulting_state is FindingLifecycleState.RESOLVED
    assert resolved_event.reason_codes == ("COMPARABLE_SCOPE_ABSENCE",)
    current_events = lifecycle.list_events(
        lineage_id=lineage.lineage_id, run_id=_RUN_IDS[2]
    )
    replay = lifecycle.evaluate(
        lineage_id=lineage.lineage_id, run_id=_RUN_IDS[2]
    )
    assert replay.created is False
    assert lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=finding_id
    ) == reopened
    assert lifecycle.list_events(
        lineage_id=lineage.lineage_id, run_id=_RUN_IDS[2]
    ) == current_events


def test_exact_new_native_identity_is_new_without_fuzzy_matching(
    pc2_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment, index, lifecycle, lineage, reports = pc2_context
    original = reports[str(_RUN_ID)]
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    old_finding = original.findings[0]
    old_evidence = next(
        item for item in original.evidence if item.evidence_id in old_finding.primary_evidence_refs
    )
    assert isinstance(old_evidence.payload, GitleaksEvidencePayload)
    native_identity = "d" * 64
    evidence_id = build_evidence_id(
        EvidenceAuthority.GITLEAKS,
        old_evidence.native_identity_schema,
        native_identity,
    )
    new_evidence = replace(
        old_evidence,
        evidence_id=evidence_id,
        native_identity=native_identity,
        payload=replace(old_evidence.payload, finding_instance_id=native_identity),
    )
    new_finding = replace(
        old_finding,
        finding_id=build_finding_id(
            EvidenceAuthority.GITLEAKS,
            old_finding.native_identity_schema,
            native_identity,
        ),
        native_finding_identity=native_identity,
        primary_evidence_refs=(evidence_id,),
    )
    run_id = _RUN_IDS[0]
    report = replace(
        original,
        scope=replace(original.scope, source_run_id=run_id),
        evidence=tuple(
            sorted((*original.evidence, new_evidence), key=lambda item: item.evidence_id)
        ),
        findings=tuple(
            sorted((*original.findings, new_finding), key=lambda item: item.finding_id)
        ),
        coverage_outcomes=tuple(
            replace(item, finding_count=item.finding_count + 1)
            if item.authority is EvidenceAuthority.GITLEAKS
            else item
            for item in original.coverage_outcomes
        ),
    )
    reports[run_id] = _clone_published_run(environment, report, run_id)
    _clone_gitleaks_runtime(environment, run_id, 2)
    monkeypatch.setattr(index, "_rebuild_trusted_report", reports.__getitem__)
    monkeypatch.setattr(lifecycle, "_trusted_report", reports.__getitem__)
    index.attach_published_run(lineage_id=lineage.lineage_id, run_id=run_id)
    index.index_attached_run(lineage_id=lineage.lineage_id, run_id=run_id)
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=run_id)

    assert lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=old_finding.finding_id
    ).current_state is FindingLifecycleState.EXISTING
    assert lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=new_finding.finding_id
    ).current_state is FindingLifecycleState.NEW


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        pytest.param("failed", "CURRENT_NODE_NOT_COMPLETE", id="failed"),
        pytest.param("partial", "CURRENT_NODE_NOT_COMPLETE", id="partial"),
        pytest.param("missing-result", "CURRENT_ACCEPTED_RESULT_MISSING", id="missing-result"),
        pytest.param("scope", "SELECTED_SCOPE_MISMATCH", id="changed-scope"),
        pytest.param("contract", "AUTHORITY_CONTRACT_MISMATCH", id="contract-change"),
        pytest.param("gap", "RELEVANT_GAP_PRESENT", id="relevant-gap"),
        pytest.param(
            "suppression",
            "RELEVANT_SUPPRESSION_PRESENT",
            id="relevant-suppression",
        ),
        pytest.param("deadline", "PARENT_DEADLINE_EXCEEDED", id="deadline"),
        pytest.param("blocked", "DEPENDENCY_BLOCKED", id="dependency-blocked"),
        pytest.param(
            "reconciliation",
            "CURRENT_CONTAINMENT_NOT_CLEAN",
            id="reconciliation-required",
        ),
    ],
)
def test_incomparable_relevant_authority_withholds_resolution(
    pc2_context,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_reason: str,
) -> None:
    environment, _index, lifecycle, lineage, reports = pc2_context
    finding_id = reports[str(_RUN_ID)].findings[0].finding_id
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    run_id = _RUN_IDS[0]
    _add_run(pc2_context, monkeypatch, run_id, present=False, ordinal=2)
    if mutation == "gap":
        monkeypatch.setattr(lifecycle, "_relevant_gap", lambda *_values: True)
    elif mutation == "suppression":
        monkeypatch.setattr(lifecycle, "_relevant_suppression", lambda *_values: True)
    with environment.factory.begin() as session:
        node = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == run_id,
                SourceOrchestrationNodeRow.authority == EvidenceAuthority.GITLEAKS.value,
            )
        )
        assert node is not None
        if mutation in {"failed", "partial", "blocked"}:
            node.terminal_disposition = {
                "failed": "FAILED",
                "partial": "PARTIAL",
                "blocked": "BLOCKED_BY_DEPENDENCY",
            }[mutation]
        elif mutation == "reconciliation":
            node.lifecycle_state = "RECONCILIATION_REQUIRED"
            node.terminal_disposition = None
            node.containment_state = "RECONCILIATION_REQUIRED"
        elif mutation == "scope":
            node.selected_paths_json = [*node.selected_paths_json, "other.txt"]
            node.selected_paths_json.sort()
        elif mutation == "contract":
            node.contract_digest = "f" * 64
        elif mutation == "deadline":
            parent = session.get(SourceOrchestrationRow, run_id)
            assert parent is not None
            parent.deadline_exceeded_at = _PC2_TIME
        elif mutation in {"gap", "suppression"}:
            pass
        else:
            mapping = session.scalar(
                select(SourceOrchestrationScannerJobRow).where(
                    SourceOrchestrationScannerJobRow.run_id == run_id,
                    SourceOrchestrationScannerJobRow.node_id == node.node_id,
                )
            )
            assert mapping is not None
            mapping.selected_attempt_number = None
    result = lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=run_id)
    state = lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=finding_id
    )
    event = lifecycle.list_events(lineage_id=lineage.lineage_id, run_id=run_id)[0]
    assert result.withheld_count == 1
    assert state.current_state is FindingLifecycleState.NEW
    assert event.event_kind is LifecycleEventKind.RESOLUTION_WITHHELD
    assert expected_reason in event.reason_codes


def test_unrelated_authority_failure_does_not_block_resolution(
    pc2_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment, _index, lifecycle, lineage, reports = pc2_context
    finding_id = reports[str(_RUN_ID)].findings[0].finding_id
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    run_id = _RUN_IDS[0]
    _add_run(pc2_context, monkeypatch, run_id, present=False, ordinal=2)
    with environment.factory.begin() as session:
        checkov = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == str(_RUN_ID),
                SourceOrchestrationNodeRow.authority == EvidenceAuthority.CHECKOV.value,
            )
        )
        assert checkov is not None
        checkov.terminal_disposition = "FAILED"
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=run_id)
    assert lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=finding_id
    ).current_state is FindingLifecycleState.RESOLVED


def test_missing_predecessor_pc1_index_fails_closed(
    pc2_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment, _index, lifecycle, lineage, _reports = pc2_context
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    run_id = _RUN_IDS[0]
    _add_run(pc2_context, monkeypatch, run_id, present=False, ordinal=2)
    with environment.factory.begin() as session:
        predecessor = session.get(SourceLineageRunRow, str(_RUN_ID))
        assert predecessor is not None
        predecessor.indexing_state = "ATTACHED"
        predecessor.indexed_at = None
    with pytest.raises(ProductCoreLifecycleError):
        lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=run_id)


def test_cancelled_run_fails_without_resolving_prior_finding(
    pc2_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment, _index, lifecycle, lineage, reports = pc2_context
    finding_id = reports[str(_RUN_ID)].findings[0].finding_id
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    run_id = _RUN_IDS[0]
    _add_run(pc2_context, monkeypatch, run_id, present=False, ordinal=2)
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, run_id)
        assert parent is not None
        parent.cancel_requested = True
        parent.cancel_requested_at = _PC2_TIME
    with pytest.raises(ProductCoreLifecycleError):
        lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=run_id)
    assert lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=finding_id
    ).current_state is FindingLifecycleState.NEW


def test_osv_comparability_rejects_blocked_syft_prerequisite(pc2_context) -> None:
    environment, _index, lifecycle, _lineage, _reports = pc2_context
    with environment.factory.begin() as session:
        syft = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == str(_RUN_ID),
                SourceOrchestrationNodeRow.authority == EvidenceAuthority.SYFT.value,
            )
        )
        assert syft is not None
        syft.terminal_disposition = "BLOCKED_BY_DEPENDENCY"
        reasons = lifecycle._osv_prerequisite_reasons(
            session, str(_RUN_ID), str(_RUN_ID)
        )
    assert "DEPENDENCY_BLOCKED" in reasons
    assert "CURRENT_NODE_NOT_COMPLETE" in reasons


def test_osv_finding_resolves_from_exact_complete_zero_package_proof(
    pc2_environment: _Environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    _index, lifecycle, lineage, _reports, finding = _osv_lifecycle_context(
        pc2_environment, monkeypatch
    )
    with pc2_environment.factory() as session:
        current_osv = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == str(_RUN_ID),
                SourceOrchestrationNodeRow.authority == EvidenceAuthority.OSV.value,
            )
        )
        assert current_osv is not None
        assert (
            session.scalar(
                select(SourceOrchestrationScannerJobRow).where(
                    SourceOrchestrationScannerJobRow.run_id == str(_RUN_ID),
                    SourceOrchestrationScannerJobRow.node_id == current_osv.node_id,
                )
            )
            is None
        )
    result = lifecycle.evaluate(
        lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
    )
    state = lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=finding.finding_id
    )
    event = next(
        item
        for item in lifecycle.list_events(
            lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
        )
        if item.finding_id == finding.finding_id
    )
    assert result.withheld_count == 0
    assert state.current_state is FindingLifecycleState.RESOLVED
    assert state.resolved_at == _INDEXED_AT + timedelta(days=1)
    assert event.reason_codes == ("DEPENDENCY_REMOVED_ZERO_PACKAGE_PROOF",)


def test_zero_package_resolution_rejects_non_exact_s4_reason(
    pc2_environment: _Environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    _index, lifecycle, lineage, _reports, finding = _osv_lifecycle_context(
        pc2_environment,
        monkeypatch,
        current_osv_reason="NO_PACKAGES_IN_ADVISORY_SCOPE",
    )
    result = lifecycle.evaluate(
        lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
    )
    state = lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=finding.finding_id
    )
    assert result.withheld_count >= 1
    assert state.current_state is FindingLifecycleState.NEW


@pytest.mark.parametrize(
    ("authority", "disposition", "reason"),
    [
        pytest.param(
            EvidenceAuthority.OSV,
            "NOT_APPLICABLE",
            "NO_PACKAGES_IN_ADVISORY_SCOPE",
            id="packages-outside-advisory-scope",
        ),
        pytest.param(
            EvidenceAuthority.OSV,
            "PARTIAL",
            "NO_SUPPORTED_OSV_COORDINATES",
            id="unsupported-coordinates",
        ),
        pytest.param(
            EvidenceAuthority.OSV,
            "PARTIAL",
            "MIXED_SCOPE_PACKAGE_OBSERVATION",
            id="mixed-scope",
        ),
        pytest.param(
            EvidenceAuthority.OSV,
            "PARTIAL",
            "SYFT_PREREQUISITE_PARTIAL",
            id="partial-prerequisite",
        ),
        pytest.param(
            EvidenceAuthority.SYFT,
            "FAILED",
            "SCANNER_FAILED",
            id="failed-syft",
        ),
        pytest.param(
            EvidenceAuthority.SYFT,
            "BLOCKED_BY_DEPENDENCY",
            "DEPENDENCY_BLOCKED",
            id="blocked-syft",
        ),
    ],
)
def test_non_exact_dependency_absence_proof_does_not_resolve(
    pc2_environment: _Environment,
    monkeypatch: pytest.MonkeyPatch,
    authority: EvidenceAuthority,
    disposition: str,
    reason: str,
) -> None:
    _index, lifecycle, lineage, _reports, finding = _osv_lifecycle_context(
        pc2_environment, monkeypatch
    )
    with pc2_environment.factory.begin() as session:
        node = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == str(_RUN_ID),
                SourceOrchestrationNodeRow.authority == authority.value,
            )
        )
        assert node is not None
        node.terminal_disposition = disposition
        node.terminal_reason_code = reason
    result = lifecycle.evaluate(
        lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
    )
    state = lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=finding.finding_id
    )
    assert result.withheld_count >= 1
    assert state.current_state is FindingLifecycleState.NEW
    assert state.resolved_run_id is None


@pytest.mark.parametrize(
    "mutation",
    ["changed-contract", "changed-scope", "unclean", "missing-result"],
)
def test_invalid_zero_package_syft_proof_does_not_resolve(
    pc2_environment: _Environment,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    _index, lifecycle, lineage, _reports, finding = _osv_lifecycle_context(
        pc2_environment, monkeypatch
    )
    with pc2_environment.factory.begin() as session:
        syft = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == str(_RUN_ID),
                SourceOrchestrationNodeRow.authority == EvidenceAuthority.SYFT.value,
            )
        )
        assert syft is not None
        if mutation == "changed-contract":
            syft.contract_digest = "e" * 64
        elif mutation == "changed-scope":
            syft.selected_paths_json = sorted(
                {*syft.selected_paths_json, "other.lock"}
            )
        elif mutation == "unclean":
            syft.containment_state = "RECONCILIATION_REQUIRED"
        else:
            mapping = session.scalar(
                select(SourceOrchestrationScannerJobRow).where(
                    SourceOrchestrationScannerJobRow.run_id == str(_RUN_ID),
                    SourceOrchestrationScannerJobRow.node_id == syft.node_id,
                )
            )
            assert mapping is not None
            mapping.selected_attempt_number = None
    result = lifecycle.evaluate(
        lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
    )
    state = lifecycle.load_lifecycle(
        lineage_id=lineage.lineage_id, finding_id=finding.finding_id
    )
    assert result.withheld_count >= 1
    assert state.current_state is FindingLifecycleState.NEW


def test_priority_policy_has_explicit_non_risk_reasons(pc2_context) -> None:
    _environment, _index, lifecycle, lineage, reports = pc2_context
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    with lifecycle._sessions() as session:
        occurrence = session.scalar(select(SourceFindingOccurrenceRow))
        assert occurrence is not None
        assert occurrence.priority_band == PriorityBand.HIGH.value
        assert occurrence.priority_reason_codes_json == [
            "CATEGORY_POLICY_SECRET_EXPOSURE"
        ]

    for authority, severity, expected in (
        (EvidenceAuthority.SEMGREP, "CRITICAL", PriorityBand.CRITICAL),
        (EvidenceAuthority.SEMGREP, "HIGH", PriorityBand.HIGH),
        (EvidenceAuthority.SEMGREP, "MEDIUM", PriorityBand.MEDIUM),
        (EvidenceAuthority.SEMGREP, "LOW", PriorityBand.LOW),
        (EvidenceAuthority.SEMGREP, "INFORMATIONAL", PriorityBand.INFO),
        (EvidenceAuthority.CHECKOV, "CRITICAL", PriorityBand.CRITICAL),
        (EvidenceAuthority.CHECKOV, "HIGH", PriorityBand.HIGH),
        (EvidenceAuthority.CHECKOV, "MEDIUM", PriorityBand.MEDIUM),
        (EvidenceAuthority.CHECKOV, "LOW", PriorityBand.LOW),
        (EvidenceAuthority.CHECKOV, "UNKNOWN", PriorityBand.UNRANKED),
        (EvidenceAuthority.CHECKOV, None, PriorityBand.UNRANKED),
    ):
        finding = SimpleNamespace(
            authority=authority,
            severity=None if severity is None else SimpleNamespace(value=severity),
        )
        priority = lifecycle.priority_for_finding(SimpleNamespace(), finding)
        assert priority.band is expected
        assert not {
            "EPSS",
            "KEV",
            "REACHABILITY",
            "EXPLOITABILITY",
            "RISK_SCORE",
        } & set(priority.reason_codes)
    assert not hasattr(occurrence, "risk_score")


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        pytest.param(9.0, PriorityBand.CRITICAL, id="critical"),
        pytest.param(7.0, PriorityBand.HIGH, id="high"),
        pytest.param(4.0, PriorityBand.MEDIUM, id="medium"),
        pytest.param(0.1, PriorityBand.LOW, id="low"),
        pytest.param(0.0, PriorityBand.INFO, id="zero-info"),
        pytest.param(None, PriorityBand.UNRANKED, id="missing"),
    ],
)
def test_osv_cvss_priority_thresholds(score: float | None, expected: PriorityBand) -> None:
    cvss = (
        ()
        if score is None
        else (
            OsvCvssProjection(
                cvss_type="CVSS_V3",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                source="OSV",
                base_score=score,
                scope="MATCHED_PACKAGE",
            ),
        )
    )
    payload = OsvAdvisoryGroupEvidencePayload(
        finding_id="a" * 64,
        advisory_group_key="b" * 64,
        package_observation_ids=("c" * 64,),
        canonical_advisory_id="CVE-2026-1",
        osv_record_ids=("OSV-2026-1",),
        aliases=(),
        cve_aliases=(),
        ghsa_aliases=(),
        fixed_versions=(),
        cvss=cvss,
        affected_match="MATCHED_BY_OSV_QUERY",
    )
    report = SimpleNamespace(
        evidence=(SimpleNamespace(evidence_id="e", payload=payload),)
    )
    finding = SimpleNamespace(
        authority=EvidenceAuthority.OSV,
        primary_evidence_refs=("e",),
    )
    priority = SourceFindingLifecycleService.priority_for_finding(report, finding)
    assert priority.band is expected
    assert priority.reason_codes == (
        "NO_VALIDATED_CVSS" if score is None else "VALIDATED_CVSS_BASE_SCORE",
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("native_identity_schema", "tampered", id="identity"),
        pytest.param("current_state", "EXISTING", id="state-history-conflict"),
    ],
)
def test_conflicting_lifecycle_material_fails_closed(
    pc2_context, field: str, value: str
) -> None:
    environment, _index, lifecycle, lineage, reports = pc2_context
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    finding_id = reports[str(_RUN_ID)].findings[0].finding_id
    with environment.factory.begin() as session:
        row = session.get(SourceFindingLifecycleRow, (lineage.lineage_id, finding_id))
        assert row is not None
        setattr(row, field, value)
    with pytest.raises(ProductCoreLifecycleError):
        lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))


def test_historical_resolved_event_is_not_rewritten(
    pc2_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment, _index, lifecycle, lineage, _reports = pc2_context
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    run_id = _RUN_IDS[0]
    _add_run(pc2_context, monkeypatch, run_id, present=False, ordinal=2)
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=run_id)
    with environment.factory() as session:
        event = session.scalar(
            select(SourceFindingLifecycleEventRow).where(
                SourceFindingLifecycleEventRow.run_id == run_id
            )
        )
        assert event is not None
        original = (
            event.resulting_state,
            tuple(event.reason_codes_json),
            event.created_at,
        )
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=run_id)
    with environment.factory() as session:
        event = session.scalar(
            select(SourceFindingLifecycleEventRow).where(
                SourceFindingLifecycleEventRow.run_id == run_id
            )
        )
        assert event is not None
        assert (
            event.resulting_state,
            tuple(event.reason_codes_json),
            event.created_at,
        ) == original

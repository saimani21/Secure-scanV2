from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from uuid import UUID

import pytest
from sqlalchemy import select

from securescan.domain.enums import ArtifactKind, RunStatus
from securescan.evidence import CoverageState, EvidenceAuthority
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceFindingLifecycleRow,
    SourceLineageRunRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceScanSubmissionRow,
)
from securescan.product_core import (
    AnalystDisposition,
    FindingLifecycleState,
    SecurityDeltaNotFoundError,
    SecurityDeltaPersistenceError,
    SecurityDeltaState,
    SourceFindingGovernanceService,
    SourceFindingIndexService,
    SourceFindingLifecycleService,
    SourceFindingSuppressionService,
    SourceSecurityDeltaService,
    SourceTrustedBaselineService,
    TrustedBaselineConflictError,
    TrustedBaselineIneligibleError,
    TrustedBaselineNotFoundError,
)
from tests.test_source_orchestration_s6b import _RUN_ID, _Environment
from tests.test_source_product_core_pc1 import (
    _INDEXED_AT,
    _clone_published_run,
    _publish_environment,
)
from tests.test_source_product_core_pc2 import (
    _add_run,
    _clone_gitleaks_runtime,
    _without_gitleaks,
)

pytest_plugins = ("tests.test_source_product_core_pc2",)

_BASELINE_RUN = "55555555-5555-4555-8555-555555555551"
_CANDIDATE_RUNS = (
    "55555555-5555-4555-8555-555555555552",
    "55555555-5555-4555-8555-555555555553",
    "55555555-5555-4555-8555-555555555554",
)


def _report_loader(reports):
    return lambda run_id, **_kwargs: reports[run_id]


def _mark_finalized(context, run_id: str) -> None:
    environment, _index, _lifecycle, lineage, _reports = context
    with environment.factory.begin() as session:
        membership = session.get(SourceLineageRunRow, run_id)
        assert membership is not None
        session.add(
            SourceScanSubmissionRow(
                run_id=run_id,
                lineage_id=lineage.lineage_id,
                submission_sequence_number=membership.sequence_number,
                predecessor_run_id=membership.predecessor_run_id,
                predecessor_sequence_number=membership.predecessor_sequence_number,
                intake_kind="MANAGED_WORKSPACE_V1",
                intake_ref="securescan-workspace-" + "1" * 32,
                created_at=_INDEXED_AT,
                finalized_at=_INDEXED_AT + timedelta(days=membership.sequence_number),
            )
        )


@pytest.fixture
def delta_context(pc2_context, monkeypatch):
    environment, _index, lifecycle, lineage, reports = pc2_context
    original_run = str(_RUN_ID)
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=original_run)
    _mark_finalized(pc2_context, original_run)

    _add_run(pc2_context, monkeypatch, _BASELINE_RUN, present=False, ordinal=2)
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=_BASELINE_RUN)
    _mark_finalized(pc2_context, _BASELINE_RUN)
    for ordinal, run_id in enumerate(_CANDIDATE_RUNS, start=3):
        _add_run(pc2_context, monkeypatch, run_id, present=True, ordinal=ordinal)
        lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=run_id)
        _mark_finalized(pc2_context, run_id)

    ids = iter(
        (
            UUID("66666666-6666-4666-8666-666666666661"),
            UUID("66666666-6666-4666-8666-666666666662"),
            UUID("66666666-6666-4666-8666-666666666663"),
        )
    )
    baselines = SourceTrustedBaselineService(
        environment.factory,
        environment.store,
        clock=lambda: _INDEXED_AT + timedelta(days=10),
        baseline_id_factory=lambda: next(ids),
    )
    delta = SourceSecurityDeltaService(environment.factory, environment.store)
    monkeypatch.setattr(baselines._index, "_rebuild_trusted_report", _report_loader(reports))
    monkeypatch.setattr(delta._index, "_rebuild_trusted_report", _report_loader(reports))
    return {
        "pc2": pc2_context,
        "environment": environment,
        "lineage": lineage,
        "project_id": lineage.project_id,
        "reports": reports,
        "baselines": baselines,
        "delta": delta,
    }


def _promote(context, run_id: str, revision: int = 0):
    return context["baselines"].promote(
        project_id=context["project_id"],
        lineage_id=context["lineage"].lineage_id,
        run_id=run_id,
        expected_revision=revision,
    )


def _delta(context, run_id: str):
    return context["delta"].evaluate(
        project_id=context["project_id"],
        lineage_id=context["lineage"].lineage_id,
        candidate_run_id=run_id,
    )


def _gitleaks_result(delta):
    return next(item for item in delta.findings if item.authority == "gitleaks")


def _replace_report(context, run_id: str, report) -> None:
    artifact = context["environment"].store.put(
        report.canonical_json(),
        kind=ArtifactKind.SOURCE_FINAL_RESULT,
        media_type="application/vnd.securescan.source-result+json",
        sanitized=True,
    )
    context["reports"][run_id] = report
    with context["environment"].factory.begin() as session:
        run = session.get(AnalysisRunRow, run_id)
        parent = session.get(SourceOrchestrationRow, run_id)
        assert run is not None and parent is not None
        run.report_json = report.canonical_data()
        parent.assembly_artifact_sha256 = artifact.sha256
        parent.assembly_artifact_size_bytes = artifact.size_bytes
        parent.assembly_artifact_storage_path = artifact.storage_path


def _gitleaks_node(context, run_id: str):
    with context["environment"].factory() as session:
        node = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == run_id,
                SourceOrchestrationNodeRow.authority == EvidenceAuthority.GITLEAKS.value,
            )
        )
        assert node is not None
        return node.node_id


def test_baseline_promotion_history_revision_and_monotonic_order(delta_context) -> None:
    empty = delta_context["baselines"].get_current(
        project_id=delta_context["project_id"],
        lineage_id=delta_context["lineage"].lineage_id,
    )
    assert empty.revision == 0 and empty.baseline is None

    first = _promote(delta_context, _BASELINE_RUN)
    assert first.revision == 1 and first.run_sequence_number == 2
    with pytest.raises(TrustedBaselineConflictError):
        _promote(delta_context, _CANDIDATE_RUNS[0], revision=0)
    with pytest.raises(TrustedBaselineIneligibleError):
        _promote(delta_context, str(_RUN_ID), revision=1)

    second = _promote(delta_context, _CANDIDATE_RUNS[1], revision=1)
    current = delta_context["baselines"].get_current(
        project_id=delta_context["project_id"],
        lineage_id=delta_context["lineage"].lineage_id,
    )
    history = delta_context["baselines"].list_history(
        project_id=delta_context["project_id"],
        lineage_id=delta_context["lineage"].lineage_id,
    )
    assert current.revision == 2 and current.baseline == second
    assert history.items == (first, second)
    assert history.total == 2
    assert first.baseline_id != second.baseline_id


def test_ineligible_unfinalized_run_is_rejected(delta_context) -> None:
    with delta_context["environment"].factory.begin() as session:
        row = session.get(SourceScanSubmissionRow, _BASELINE_RUN)
        assert row is not None
        row.finalized_at = None
    with pytest.raises(TrustedBaselineIneligibleError):
        _promote(delta_context, _BASELINE_RUN)


def test_finalized_partial_is_eligible_but_failed_or_cancelled_is_not(
    delta_context,
) -> None:
    with delta_context["environment"].factory.begin() as session:
        run = session.get(AnalysisRunRow, _BASELINE_RUN)
        parent = session.get(SourceOrchestrationRow, _BASELINE_RUN)
        assert run is not None and parent is not None
        run.status = RunStatus.PARTIAL.value
        parent.terminal_outcome = "PARTIAL"
    promoted = _promote(delta_context, _BASELINE_RUN)
    assert promoted.revision == 1

    for outcome, run_status in (
        ("FAILED", RunStatus.FAILED.value),
        ("CANCELLED", RunStatus.CANCELLED.value),
    ):
        with delta_context["environment"].factory.begin() as session:
            run = session.get(AnalysisRunRow, _CANDIDATE_RUNS[0])
            parent = session.get(SourceOrchestrationRow, _CANDIDATE_RUNS[0])
            assert run is not None and parent is not None
            run.status = run_status
            parent.terminal_outcome = outcome
        with pytest.raises(TrustedBaselineIneligibleError):
            _promote(delta_context, _CANDIDATE_RUNS[0], revision=1)


def test_no_baseline_has_no_implicit_latest_selection(delta_context) -> None:
    with pytest.raises(SecurityDeltaNotFoundError):
        _delta(delta_context, _CANDIDATE_RUNS[-1])
    assert (
        delta_context["baselines"]
        .get_current(
            project_id=delta_context["project_id"],
            lineage_id=delta_context["lineage"].lineage_id,
        )
        .baseline
        is None
    )


def test_unfinalized_candidate_is_not_comparison_ready(delta_context) -> None:
    _promote(delta_context, _BASELINE_RUN)
    with delta_context["environment"].factory.begin() as session:
        submission = session.get(SourceScanSubmissionRow, _CANDIDATE_RUNS[0])
        assert submission is not None
        submission.finalized_at = None
    with pytest.raises(SecurityDeltaPersistenceError):
        _delta(delta_context, _CANDIDATE_RUNS[0])


def test_non_immediate_candidates_remain_introduced_until_promotion(
    delta_context,
) -> None:
    _promote(delta_context, _BASELINE_RUN)
    for index, run_id in enumerate(_CANDIDATE_RUNS):
        result = _delta(delta_context, run_id)
        finding = _gitleaks_result(result)
        assert finding.state is SecurityDeltaState.INTRODUCED
        with delta_context["environment"].factory() as session:
            lifecycle = session.scalar(
                select(SourceFindingLifecycleRow).where(
                    SourceFindingLifecycleRow.lineage_id == delta_context["lineage"].lineage_id,
                    SourceFindingLifecycleRow.finding_id == finding.finding_id,
                )
            )
        assert lifecycle is not None
        assert lifecycle.current_state == FindingLifecycleState.EXISTING.value
        assert result.baseline_run_id == _BASELINE_RUN
        assert result.candidate_sequence_number == index + 3

    _promote(delta_context, _CANDIDATE_RUNS[1], revision=1)
    after_promotion = _delta(delta_context, _CANDIDATE_RUNS[2])
    assert _gitleaks_result(after_promotion).state is SecurityDeltaState.PRESENT
    assert after_promotion.baseline_run_id == _CANDIDATE_RUNS[1]
    assert after_promotion.baseline_revision == 2


def test_exact_self_comparison_is_all_present(delta_context) -> None:
    _promote(delta_context, _CANDIDATE_RUNS[0])
    result = _delta(delta_context, _CANDIDATE_RUNS[0])
    assert result.findings
    assert {item.state for item in result.findings} == {SecurityDeltaState.PRESENT}
    assert not any(
        item.state in {SecurityDeltaState.INTRODUCED, SecurityDeltaState.REMOVED}
        for item in result.findings
    )


def test_clean_candidate_proves_removed_for_exact_baseline_finding(delta_context) -> None:
    _promote(delta_context, str(_RUN_ID))
    result = _delta(delta_context, _BASELINE_RUN)
    finding = _gitleaks_result(result)
    assert finding.state is SecurityDeltaState.REMOVED
    assert finding.reason_codes == ("COMPARABLE_CANDIDATE_ABSENCE",)


def test_older_candidate_is_explicitly_not_comparable(delta_context) -> None:
    _promote(delta_context, _CANDIDATE_RUNS[1])
    result = _delta(delta_context, _BASELINE_RUN)
    assert result.comparison_status.value == "NOT_COMPARABLE"
    assert all(item.state is SecurityDeltaState.NOT_COMPARABLE for item in result.findings)
    assert all(item.reason_codes == ("CANDIDATE_BEFORE_BASELINE",) for item in result.findings)


def test_governance_and_suppression_do_not_change_delta_truth(delta_context) -> None:
    _promote(delta_context, _BASELINE_RUN)
    before = _delta(delta_context, _CANDIDATE_RUNS[0])
    finding = _gitleaks_result(before)
    governance = SourceFindingGovernanceService(delta_context["environment"].factory)
    suppression = SourceFindingSuppressionService(delta_context["environment"].factory)
    governance.mutate(
        project_id=delta_context["project_id"],
        lineage_id=delta_context["lineage"].lineage_id,
        finding_id=finding.finding_id,
        disposition=AnalystDisposition.FALSE_POSITIVE,
        reason="does not rewrite evidence truth",
        expires_at=None,
        expected_revision=0,
    )
    suppression.suppress(
        project_id=delta_context["project_id"],
        lineage_id=delta_context["lineage"].lineage_id,
        finding_id=finding.finding_id,
        reason="also independent",
        expires_at=_INDEXED_AT + timedelta(days=90),
        expected_revision=0,
    )
    after = _delta(delta_context, _CANDIDATE_RUNS[0])
    assert _gitleaks_result(after).state is SecurityDeltaState.INTRODUCED
    assert before == after


@pytest.mark.parametrize(
    ("side", "baseline_run", "candidate_run", "expected_reason"),
    [
        ("baseline", _BASELINE_RUN, _CANDIDATE_RUNS[0], "BASELINE_COVERAGE_NOT_COMPLETE"),
        ("candidate", str(_RUN_ID), _BASELINE_RUN, "CANDIDATE_COVERAGE_NOT_COMPLETE"),
    ],
)
def test_incomplete_coverage_never_proves_absence(
    delta_context, side, baseline_run, candidate_run, expected_reason
) -> None:
    _promote(delta_context, baseline_run)
    run_id = baseline_run if side == "baseline" else candidate_run
    report = delta_context["reports"][run_id]
    limited = replace(
        report,
        coverage_outcomes=tuple(
            replace(
                item,
                state=CoverageState.PARTIAL,
                reason_code="COVERAGE_LIMITED",
            )
            if item.authority is EvidenceAuthority.GITLEAKS
            else item
            for item in report.coverage_outcomes
        ),
    )
    _replace_report(delta_context, run_id, limited)

    finding = _gitleaks_result(_delta(delta_context, candidate_run))
    assert finding.state is SecurityDeltaState.NOT_COMPARABLE
    assert expected_reason in finding.reason_codes


@pytest.mark.parametrize(
    ("baseline_run", "candidate_run", "mutated_run", "expected_reason"),
    [
        (_BASELINE_RUN, _CANDIDATE_RUNS[0], _BASELINE_RUN, "BASELINE_NODE_NOT_COMPLETE"),
        (str(_RUN_ID), _BASELINE_RUN, _BASELINE_RUN, "CANDIDATE_NODE_NOT_COMPLETE"),
    ],
)
def test_scanner_failure_never_produces_introduced_or_removed(
    delta_context, baseline_run, candidate_run, mutated_run, expected_reason
) -> None:
    _promote(delta_context, baseline_run)
    node_id = _gitleaks_node(delta_context, mutated_run)
    with delta_context["environment"].factory.begin() as session:
        node = session.get(SourceOrchestrationNodeRow, node_id)
        assert node is not None
        node.terminal_disposition = "FAILED"

    finding = _gitleaks_result(_delta(delta_context, candidate_run))
    assert finding.state is SecurityDeltaState.NOT_COMPARABLE
    assert expected_reason in finding.reason_codes


def test_scope_and_contract_mismatch_are_not_comparable(delta_context) -> None:
    _promote(delta_context, _BASELINE_RUN)
    node_id = _gitleaks_node(delta_context, _CANDIDATE_RUNS[0])
    with delta_context["environment"].factory.begin() as session:
        node = session.get(SourceOrchestrationNodeRow, node_id)
        assert node is not None
        node.selected_paths_json = sorted({*node.selected_paths_json, "other/path.txt"})
        node.analyzer_id = "different-analyzer-contract"

    finding = _gitleaks_result(_delta(delta_context, _CANDIDATE_RUNS[0]))
    assert finding.state is SecurityDeltaState.NOT_COMPARABLE
    assert "SELECTED_SCOPE_MISMATCH" in finding.reason_codes
    assert "AUTHORITY_CONTRACT_MISMATCH" in finding.reason_codes


def test_exact_positive_presence_survives_broader_authority_incompatibility(
    delta_context,
) -> None:
    _promote(delta_context, _CANDIDATE_RUNS[0])
    node_id = _gitleaks_node(delta_context, _CANDIDATE_RUNS[1])
    with delta_context["environment"].factory.begin() as session:
        node = session.get(SourceOrchestrationNodeRow, node_id)
        assert node is not None
        node.analyzer_id = "different-analyzer-contract"
    result = _delta(delta_context, _CANDIDATE_RUNS[1])
    assert _gitleaks_result(result).state is SecurityDeltaState.PRESENT
    gitleaks = next(item for item in result.authority_summaries if item.authority == "gitleaks")
    assert gitleaks.comparison_status.value == "PARTIAL"
    assert "AUTHORITY_CONTRACT_MISMATCH" in gitleaks.reason_codes


def test_failed_candidate_cannot_change_current_baseline(delta_context) -> None:
    promoted = _promote(delta_context, _BASELINE_RUN)
    with delta_context["environment"].factory.begin() as session:
        run = session.get(AnalysisRunRow, _CANDIDATE_RUNS[0])
        parent = session.get(SourceOrchestrationRow, _CANDIDATE_RUNS[0])
        assert run is not None and parent is not None
        run.status = RunStatus.FAILED.value
        parent.terminal_outcome = "FAILED"
    with pytest.raises(SecurityDeltaPersistenceError):
        _delta(delta_context, _CANDIDATE_RUNS[0])
    current = delta_context["baselines"].get_current(
        project_id=delta_context["project_id"],
        lineage_id=delta_context["lineage"].lineage_id,
    )
    assert current.baseline == promoted and current.revision == 1


def test_unrelated_authority_failure_does_not_poison_gitleaks(delta_context) -> None:
    _promote(delta_context, _BASELINE_RUN)
    result = _delta(delta_context, _CANDIDATE_RUNS[0])
    assert _gitleaks_result(result).state is SecurityDeltaState.INTRODUCED
    gitleaks = next(item for item in result.authority_summaries if item.authority == "gitleaks")
    semgrep = next(item for item in result.authority_summaries if item.authority == "semgrep-ce")
    assert gitleaks.comparison_status.value == "COMPLETE"
    assert semgrep.comparison_status.value == "NOT_COMPARABLE"
    assert result.comparison_status.value == "PARTIAL"


def test_delta_read_is_side_effect_free_and_history_survives_service_restart(
    delta_context,
) -> None:
    promoted = _promote(delta_context, _BASELINE_RUN)
    before = delta_context["baselines"].list_history(
        project_id=delta_context["project_id"],
        lineage_id=delta_context["lineage"].lineage_id,
    )
    _delta(delta_context, _CANDIDATE_RUNS[0])
    restarted = SourceTrustedBaselineService(
        delta_context["environment"].factory,
        delta_context["environment"].store,
    )
    after = restarted.list_history(
        project_id=delta_context["project_id"],
        lineage_id=delta_context["lineage"].lineage_id,
    )
    assert before == after
    assert after.items == (promoted,)


def test_cross_project_and_cross_lineage_promotion_are_rejected(delta_context) -> None:
    with pytest.raises(TrustedBaselineNotFoundError):
        delta_context["baselines"].promote(
            project_id="99999999-9999-4999-8999-999999999999",
            lineage_id=delta_context["lineage"].lineage_id,
            run_id=_BASELINE_RUN,
            expected_revision=0,
        )
    with pytest.raises(TrustedBaselineNotFoundError):
        delta_context["baselines"].promote(
            project_id=delta_context["project_id"],
            lineage_id="99999999-9999-4999-8999-999999999998",
            run_id=_BASELINE_RUN,
            expected_revision=0,
        )


def test_clean_first_baseline_keeps_new_then_existing_candidates_introduced(
    tmp_path, monkeypatch
) -> None:
    environment = _Environment(tmp_path)
    _publish_environment(environment)
    original_run = str(_RUN_ID)
    candidate_runs = (
        "88888888-8888-4888-8888-888888888881",
        "88888888-8888-4888-8888-888888888882",
        "88888888-8888-4888-8888-888888888883",
    )
    try:
        index = SourceFindingIndexService(environment.factory, environment.store)
        finding_report = index._rebuild_trusted_report(original_run)
        clean_report = _without_gitleaks(finding_report, original_run)
        artifact = environment.store.put(
            clean_report.canonical_json(),
            kind=ArtifactKind.SOURCE_FINAL_RESULT,
            media_type="application/vnd.securescan.source-result+json",
            sanitized=True,
        )
        with environment.factory.begin() as session:
            run = session.get(AnalysisRunRow, original_run)
            parent = session.get(SourceOrchestrationRow, original_run)
            assert run is not None and parent is not None
            run.report_json = clean_report.canonical_data()
            parent.assembly_artifact_sha256 = artifact.sha256
            parent.assembly_artifact_size_bytes = artifact.size_bytes
            parent.assembly_artifact_storage_path = artifact.storage_path
            target = run.target
            project_id = target.project_id
        lineage = index.create_lineage(project_id=project_id)
        reports = {original_run: clean_report}
        lifecycle = SourceFindingLifecycleService(environment.factory, environment.store)
        monkeypatch.setattr(index, "_rebuild_trusted_report", _report_loader(reports))
        monkeypatch.setattr(lifecycle, "_trusted_report", reports.__getitem__)
        index.attach_published_run(lineage_id=lineage.lineage_id, run_id=original_run)
        index.index_attached_run(lineage_id=lineage.lineage_id, run_id=original_run)
        lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=original_run)
        context = (environment, index, lifecycle, lineage, reports)
        _mark_finalized(context, original_run)

        lifecycle_states = []
        for ordinal, run_id in enumerate(candidate_runs, start=2):
            report = replace(
                finding_report,
                scope=replace(finding_report.scope, source_run_id=run_id),
            )
            reports[run_id] = _clone_published_run(environment, report, run_id)
            _clone_gitleaks_runtime(environment, run_id, ordinal)
            monkeypatch.setattr(index, "_rebuild_trusted_report", _report_loader(reports))
            monkeypatch.setattr(lifecycle, "_trusted_report", reports.__getitem__)
            index.attach_published_run(lineage_id=lineage.lineage_id, run_id=run_id)
            index.index_attached_run(lineage_id=lineage.lineage_id, run_id=run_id)
            lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=run_id)
            _mark_finalized(context, run_id)
            lifecycle_states.append(
                lifecycle.list_events(lineage_id=lineage.lineage_id, run_id=run_id)[
                    0
                ].resulting_state
            )

        baselines = SourceTrustedBaselineService(environment.factory, environment.store)
        delta = SourceSecurityDeltaService(environment.factory, environment.store)
        monkeypatch.setattr(
            baselines._index, "_rebuild_trusted_report", _report_loader(reports)
        )
        monkeypatch.setattr(delta._index, "_rebuild_trusted_report", _report_loader(reports))
        baselines.promote(
            project_id=project_id,
            lineage_id=lineage.lineage_id,
            run_id=original_run,
            expected_revision=0,
        )
        states = tuple(
            _gitleaks_result(
                delta.evaluate(
                    project_id=project_id,
                    lineage_id=lineage.lineage_id,
                    candidate_run_id=run_id,
                )
            ).state
            for run_id in candidate_runs
        )
        assert lifecycle_states == [
            FindingLifecycleState.NEW,
            FindingLifecycleState.EXISTING,
            FindingLifecycleState.EXISTING,
        ]
        assert states == (SecurityDeltaState.INTRODUCED,) * 3
    finally:
        environment.close()

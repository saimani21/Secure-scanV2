from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest
from unified_evidence_fixtures import (
    PLAN_DIGEST,
    PROFILE_DIGEST,
    REPOSITORY_DIGEST,
    osv_native,
    syft_native,
)

from securescan.advisories.osv.evaluation import (
    OsvCandidateMatch,
    OsvDependencyAnalysis,
)
from securescan.advisories.osv.models import (
    OsvAdvisoryObservation,
    OsvAdvisoryReference,
    OsvGapReason,
    group_advisories,
)
from securescan.evidence import (
    OSV_FINDING_IDENTITY_SCHEMA,
    EvidenceAuthority,
    adapt_osv_analysis,
    adapt_syft_result,
    build_finding_id,
)
from securescan.orchestration.dependency_evaluation import (
    DependencyEvaluationDecision,
    DependencyGapEvidence,
    DependencyScopeEvidence,
    PackageScopeClassification,
    PackageScopeEvidence,
    SourceDependencyEvaluation,
    SyftPrerequisiteEvidence,
)
from securescan.orchestration.osv_execution import (
    SafeSourceOsvResult,
    SourceOsvExecutionInput,
)
from securescan.product_core.dependencies import (
    DependencyProjectionError,
    DependencyProjectionMaterial,
    SourceDependencyProjectionService,
    resolve_dependency_summaries,
)
from securescan.product_core.query import SourceScanQueryService

_RUN_ID = "11111111-1111-4111-8111-111111111111"
_JOB_ID = "22222222-2222-4222-8222-222222222222"
_NODE_ID = "a" * 64
_SYFT_NODE_ID = "b" * 64
_EVALUATION_SHA = "c" * 64
_SYFT_SHA = "d" * 64


def _analysis(*, vulnerable: bool):
    syft_result, context, projection = syft_native(
        source_run_id=_RUN_ID, locations=("requirements.lock",)
    )
    if vulnerable:
        analysis = osv_native(syft_result)
    else:
        candidate = osv_native(syft_result).candidates[0]
        match = OsvCandidateMatch(candidate, (), ())
        analysis = OsvDependencyAnalysis(
            candidates=(candidate,),
            gaps=(),
            candidate_matches=(match,),
            findings=(),
            completed_candidate_ids=(candidate.candidate_id,),
            zero_advisory_candidate_ids=(candidate.candidate_id,),
        )
    syft = adapt_syft_result(syft_result, context=context, projection=projection)
    osv = adapt_osv_analysis(analysis, scope=syft.scope)
    report = {
        "scope": syft.scope.canonical_data(),
        "components": [item.canonical_data() for item in syft.components],
        "evidence": [
            item.canonical_data() for item in (*syft.evidence, *osv.evidence)
        ],
        "findings": [item.canonical_data() for item in osv.findings],
        "coverage_outcomes": [
            item.canonical_data()
            for item in (*syft.coverage_outcomes, *osv.coverage_outcomes)
        ],
    }
    priorities = {item.finding_id: "UNRANKED" for item in osv.findings}
    return syft_result, analysis, report, priorities


def _evaluation(
    syft_result,
    analysis,
    *,
    prerequisite_complete: bool = True,
) -> SourceDependencyEvaluation:
    observation = syft_result.observations[0]
    return SourceDependencyEvaluation(
        run_id=_RUN_ID,
        osv_node_id=_NODE_ID,
        scope=DependencyScopeEvidence(
            selected_paths=observation.locations,
            scope_digest="e" * 64,
        ),
        syft_prerequisite=SyftPrerequisiteEvidence(
            node_id=_SYFT_NODE_ID,
            job_id=_JOB_ID,
            selected_attempt_number=1,
            native_result_sha256=_SYFT_SHA,
            prerequisite_complete=prerequisite_complete,
        ),
        observations=(
            PackageScopeEvidence(
                package_observation_id=observation.package_observation_id,
                package_key=observation.package_key,
                locations=observation.locations,
                classification=PackageScopeClassification.IN_SCOPE,
            ),
        ),
        mixed_scope_gaps=(),
        eligible_package_observation_ids=(observation.package_observation_id,),
        candidate_ids=tuple(item.candidate_id for item in analysis.candidates),
        coordinate_gaps=(),
        decision=DependencyEvaluationDecision.OSV_RUN_REQUIRED,
        coverage_limited=not prerequisite_complete,
    )


def _material(
    syft_result,
    analysis,
    *,
    prerequisite_complete: bool = True,
    accepted: bool = True,
    failure_reason: str | None = None,
) -> DependencyProjectionMaterial:
    evaluation = _evaluation(
        syft_result,
        analysis,
        prerequisite_complete=prerequisite_complete,
    )
    execution_input = SourceOsvExecutionInput(
        run_id=_RUN_ID,
        node_id=_NODE_ID,
        job_id=_JOB_ID,
        repository_digest=REPOSITORY_DIGEST,
        profile_digest=PROFILE_DIGEST,
        plan_digest=PLAN_DIGEST,
        scope_digest=evaluation.scope.scope_digest,
        dependency_evaluation_sha256=_EVALUATION_SHA,
        dependency_evaluation_size_bytes=1,
        dependency_evaluation_schema_version=evaluation.schema_version,
        syft_node_id=evaluation.syft_prerequisite.node_id,
        syft_job_id=evaluation.syft_prerequisite.job_id,
        syft_selected_attempt_number=1,
        syft_native_result_sha256=_SYFT_SHA,
        candidates=analysis.candidates,
        coverage_limited=evaluation.coverage_limited,
    )
    result = (
        SafeSourceOsvResult.from_analysis(
            execution_input,
            attempt_number=1,
            analysis=analysis,
        )
        if accepted
        else None
    )
    return DependencyProjectionMaterial(
        evaluation=evaluation,
        evaluation_sha256=_EVALUATION_SHA,
        execution_input=execution_input,
        accepted_result=result,
        public_reason=failure_reason,
        report_reason=failure_reason,
    )


def _case(
    *,
    vulnerable: bool,
    prerequisite_complete: bool = True,
):
    syft_result, analysis, report, priorities = _analysis(vulnerable=vulnerable)
    if not prerequisite_complete:
        outcome = next(
            item for item in report["coverage_outcomes"] if item["authority"] == "osv.dev"
        )
        outcome["state"] = "PARTIAL"
        outcome["reason_code"] = "DEPENDENCY_COVERAGE_LIMITED"
    return (
        report,
        priorities,
        _material(
            syft_result,
            analysis,
            prerequisite_complete=prerequisite_complete,
        ),
    )


def _resolve(report, priorities, material):
    return resolve_dependency_summaries(report, priorities, material)[0]


def test_complete_clean_has_exact_zero_count() -> None:
    report, priorities, material = _case(vulnerable=False)
    dependency = _resolve(report, priorities, material)
    assert dependency.vulnerability_evaluation == "COMPLETE"
    assert dependency.known_vulnerability_count == 0
    assert dependency.advisories == ()


def test_complete_vulnerable_projects_exact_nested_advisory() -> None:
    report, priorities, material = _case(vulnerable=True)
    dependency = _resolve(report, priorities, material)
    assert dependency.vulnerability_evaluation == "COMPLETE"
    assert dependency.known_vulnerability_count == 1
    assert len(dependency.advisories) == 1
    advisory = dependency.advisories[0]
    assert advisory.canonical_advisory_id == "CVE-2025-12345"
    assert advisory.osv_record_ids == ("GHSA-9wx4-h78v-vm56",)
    assert advisory.aliases == ("CVE-2025-12345",)
    assert advisory.cve_aliases == ("CVE-2025-12345",)
    assert advisory.ghsa_aliases == ("GHSA-9wx4-h78v-vm56",)
    assert advisory.fixed_versions == ("2.32.0",)
    assert advisory.priority_band == "UNRANKED"
    assert dependency.advisory_aliases == (
        "CVE-2025-12345",
        "GHSA-9wx4-h78v-vm56",
    )
    assert dependency.fixed_versions == ("2.32.0",)
    assert dependency.priority_bands == ("UNRANKED",)


def test_aliases_do_not_inflate_canonical_count() -> None:
    report, priorities, material = _case(vulnerable=True)
    dependency = _resolve(report, priorities, material)
    advisory = dependency.advisories[0]
    assert len(
        {
            *advisory.osv_record_ids,
            *advisory.aliases,
            *advisory.cve_aliases,
            *advisory.ghsa_aliases,
        }
    ) == 2
    assert dependency.known_vulnerability_count == 1


def test_partial_prerequisite_retains_advisory_but_count_is_unknown() -> None:
    report, priorities, material = _case(
        vulnerable=True, prerequisite_complete=False
    )
    dependency = _resolve(report, priorities, material)
    assert dependency.vulnerability_evaluation == "PARTIAL"
    assert dependency.vulnerability_evaluation_reason == "SYFT_PREREQUISITE_PARTIAL"
    assert dependency.vulnerability_evaluation_reason != "DEPENDENCY_COVERAGE_LIMITED"
    assert dependency.known_vulnerability_count is None
    assert len(dependency.advisories) == 1


def test_package_gaps_present_remains_a_compatible_published_reason() -> None:
    report, priorities, material = _case(
        vulnerable=True, prerequisite_complete=False
    )
    outcome = next(
        item for item in report["coverage_outcomes"] if item["authority"] == "osv.dev"
    )
    outcome["reason_code"] = "PACKAGE_GAPS_PRESENT"

    dependency = _resolve(report, priorities, material)

    assert dependency.vulnerability_evaluation == "PARTIAL"
    assert dependency.vulnerability_evaluation_reason == "SYFT_PREREQUISITE_PARTIAL"
    assert dependency.known_vulnerability_count is None
    assert len(dependency.advisories) == 1


def test_generic_partial_requires_an_accepted_result() -> None:
    report, priorities, material = _case(
        vulnerable=True, prerequisite_complete=False
    )

    with pytest.raises(DependencyProjectionError):
        _resolve(report, priorities, replace(material, accepted_result=None))


def test_generic_partial_rejects_complete_artifact_correlation() -> None:
    report, priorities, material = _case(vulnerable=False)
    outcome = next(
        item for item in report["coverage_outcomes"] if item["authority"] == "osv.dev"
    )
    outcome["state"] = "PARTIAL"
    outcome["reason_code"] = "DEPENDENCY_COVERAGE_LIMITED"

    with pytest.raises(DependencyProjectionError):
        _resolve(report, priorities, material)


def test_required_candidate_failure_has_no_count_or_advisories() -> None:
    syft_result, analysis, report, priorities = _analysis(vulnerable=False)
    outcome = next(
        item for item in report["coverage_outcomes"] if item["authority"] == "osv.dev"
    )
    outcome["state"] = "FAILED"
    outcome["reason_code"] = "NETWORK_FAILURE"
    material = _material(
        syft_result,
        analysis,
        accepted=False,
        failure_reason="NETWORK_FAILURE",
    )
    dependency = _resolve(report, priorities, material)
    assert dependency.vulnerability_evaluation == "FAILED"
    assert dependency.vulnerability_evaluation_reason == "NETWORK_FAILURE"
    assert dependency.known_vulnerability_count is None
    assert dependency.advisories == ()


def test_planning_omission_requires_zero_osv_outcomes_and_findings() -> None:
    _syft_result, _analysis_value, report, _priorities = _analysis(vulnerable=False)
    report["coverage_outcomes"] = [
        item for item in report["coverage_outcomes"] if item["authority"] != "osv.dev"
    ]
    dependency = _resolve(
        report,
        {},
        DependencyProjectionMaterial(fallback_evaluation="NOT_APPLICABLE"),
    )
    assert dependency.vulnerability_evaluation == "NOT_APPLICABLE"
    assert dependency.known_vulnerability_count is None
    assert dependency.advisories == ()


def test_pre_artifact_failure_is_capability_level_and_safe() -> None:
    _syft_result, _analysis_value, report, _priorities = _analysis(vulnerable=False)
    outcome = next(
        item for item in report["coverage_outcomes"] if item["authority"] == "osv.dev"
    )
    outcome["state"] = "FAILED"
    outcome["reason_code"] = "DEPENDENCY_EVALUATION_FAILED"
    dependency = _resolve(
        report,
        {},
        DependencyProjectionMaterial(
            fallback_evaluation="FAILED",
            public_reason="DEPENDENCY_FAILED",
            report_reason="DEPENDENCY_EVALUATION_FAILED",
        ),
    )
    assert dependency.vulnerability_evaluation == "FAILED"
    assert dependency.vulnerability_evaluation_reason == "DEPENDENCY_FAILED"
    assert dependency.known_vulnerability_count is None


def test_unknown_public_reason_fails_closed() -> None:
    _syft_result, _analysis_value, report, _priorities = _analysis(vulnerable=False)
    report["coverage_outcomes"] = [
        item for item in report["coverage_outcomes"] if item["authority"] != "osv.dev"
    ]
    with pytest.raises(DependencyProjectionError):
        resolve_dependency_summaries(
            report,
            {},
            DependencyProjectionMaterial(
                fallback_evaluation="NOT_APPLICABLE",
                public_reason="ARBITRARY_INTERNAL_TEXT",
            ),
        )


def test_zero_outcome_with_osv_finding_fails_closed() -> None:
    _syft_result, _analysis_value, report, priorities = _analysis(vulnerable=True)
    report["coverage_outcomes"] = [
        item for item in report["coverage_outcomes"] if item["authority"] != "osv.dev"
    ]
    with pytest.raises(DependencyProjectionError):
        resolve_dependency_summaries(
            report,
            priorities,
            DependencyProjectionMaterial(fallback_evaluation="NOT_APPLICABLE"),
        )


def test_execution_input_scope_mismatch_fails_closed() -> None:
    report, priorities, material = _case(vulnerable=False)
    tampered = deepcopy(report)
    tampered["scope"]["plan_digest"] = "f" * 64
    with pytest.raises(DependencyProjectionError):
        resolve_dependency_summaries(tampered, priorities, material)


@pytest.mark.parametrize(
    "mutation",
    ["binding", "missing-evidence", "wrong-kind", "missing-priority", "duplicate"],
)
def test_advisory_relationship_contradictions_fail_closed(mutation: str) -> None:
    report, priorities, material = _case(vulnerable=True)
    tampered = deepcopy(report)
    finding = next(
        item for item in tampered["findings"] if item["authority"] == "osv.dev"
    )
    group_ref = next(
        ref
        for ref in finding["primary_evidence_refs"]
        if next(
            item for item in tampered["evidence"] if item["evidence_id"] == ref
        )["evidence_kind"]
        == "OSV_ADVISORY_GROUP"
    )
    if mutation == "binding":
        component = next(
            item for item in tampered["components"] if item["component_kind"] == "PACKAGE"
        )
        component["native_component_identity"] = "f" * 64
    elif mutation == "missing-evidence":
        tampered["evidence"] = [
            item for item in tampered["evidence"] if item["evidence_id"] != group_ref
        ]
    elif mutation == "wrong-kind":
        group = next(
            item for item in tampered["evidence"] if item["evidence_id"] == group_ref
        )
        group["evidence_kind"] = "OSV_ADVISORY_REVISION"
    elif mutation == "missing-priority":
        priorities = {}
    else:
        tampered["findings"].append(deepcopy(finding))
    with pytest.raises(DependencyProjectionError):
        resolve_dependency_summaries(tampered, priorities, material)


def test_alias_connected_duplicate_advisory_relationship_fails_closed() -> None:
    report, priorities, material = _case(vulnerable=True)
    tampered = deepcopy(report)
    finding = next(
        item for item in tampered["findings"] if item["authority"] == "osv.dev"
    )
    group_ref = next(
        ref
        for ref in finding["primary_evidence_refs"]
        if next(
            item for item in tampered["evidence"] if item["evidence_id"] == ref
        )["evidence_kind"]
        == "OSV_ADVISORY_GROUP"
    )
    group = deepcopy(
        next(item for item in tampered["evidence"] if item["evidence_id"] == group_ref)
    )
    group["evidence_id"] = "7" * 64
    group["native_identity"] = "8" * 64
    group["payload"]["advisory_group_key"] = "8" * 64
    group["payload"]["finding_id"] = "9" * 64
    duplicate = deepcopy(finding)
    duplicate["native_finding_identity"] = "9" * 64
    duplicate["finding_id"] = build_finding_id(
        EvidenceAuthority.OSV,
        OSV_FINDING_IDENTITY_SCHEMA,
        duplicate["native_finding_identity"],
    )
    duplicate["primary_evidence_refs"] = sorted(
        group["evidence_id"] if ref == group_ref else ref
        for ref in duplicate["primary_evidence_refs"]
    )
    tampered["evidence"].append(group)
    tampered["findings"].append(duplicate)
    priorities[duplicate["finding_id"]] = "UNRANKED"
    with pytest.raises(DependencyProjectionError):
        resolve_dependency_summaries(tampered, priorities, material)


def test_locations_are_unique_and_deterministically_sorted() -> None:
    report, priorities, material = _case(vulnerable=False)
    dependency = _resolve(report, priorities, material)
    assert dependency.locations == (
        {"kind": "REPOSITORY_PATH", "path": "requirements.lock"},
    )


def test_projection_contains_no_execution_material() -> None:
    report, priorities, material = _case(vulnerable=True)
    rendered = repr(_resolve(report, priorities, material))
    for forbidden in (
        "repository_digest",
        "profile_digest",
        "plan_digest",
        "native_result_sha256",
        "storage_path",
        "stderr",
        "stdout",
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    ("classification", "gap_reason", "outcome_state", "outcome_reason", "state", "reason"),
    [
        (
            PackageScopeClassification.OUTSIDE_SCOPE,
            None,
            "NOT_APPLICABLE",
            "NO_PACKAGES_IN_ADVISORY_SCOPE",
            "NOT_APPLICABLE",
            "OUTSIDE_SCOPE",
        ),
        (
            PackageScopeClassification.MIXED_SCOPE,
            "MIXED_SCOPE_PACKAGE_OBSERVATION",
            "PARTIAL",
            "MIXED_SCOPE_PACKAGE_OBSERVATION",
            "PARTIAL",
            "MIXED_SCOPE_PACKAGE_OBSERVATION",
        ),
        (
            PackageScopeClassification.IN_SCOPE,
            OsvGapReason.PACKAGE_VERSION_UNRESOLVED.value,
            "PARTIAL",
            "NO_SUPPORTED_OSV_COORDINATES",
            "PARTIAL",
            OsvGapReason.PACKAGE_VERSION_UNRESOLVED.value,
        ),
    ],
)
def test_package_scope_and_coordinate_limitations(
    classification,
    gap_reason,
    outcome_state,
    outcome_reason,
    state,
    reason,
) -> None:
    syft_result, context, projection = syft_native(
        source_run_id=_RUN_ID,
        version=None if gap_reason == OsvGapReason.PACKAGE_VERSION_UNRESOLVED.value else "2.31.0",
        locations=("requirements.lock",),
    )
    syft = adapt_syft_result(syft_result, context=context, projection=projection)
    observation = syft_result.observations[0]
    gap = (
        ()
        if gap_reason is None
        else (
            DependencyGapEvidence(
                reason_code=gap_reason,
                package_key=observation.package_key,
                package_observation_ids=(observation.package_observation_id,),
                locations=observation.locations,
            ),
        )
    )
    mixed = (
        gap
        if classification is PackageScopeClassification.MIXED_SCOPE
        else ()
    )
    coordinates = (
        gap
        if classification is PackageScopeClassification.IN_SCOPE and gap
        else ()
    )
    in_scope = classification is PackageScopeClassification.IN_SCOPE
    decision = (
        DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES_IN_SCOPE
        if classification is PackageScopeClassification.OUTSIDE_SCOPE
        else DependencyEvaluationDecision.PARTIAL_NO_SUPPORTED_COORDINATES
    )
    evaluation = SourceDependencyEvaluation(
        run_id=_RUN_ID,
        osv_node_id=_NODE_ID,
        scope=DependencyScopeEvidence(observation.locations, "e" * 64),
        syft_prerequisite=SyftPrerequisiteEvidence(
            _SYFT_NODE_ID, _JOB_ID, 1, _SYFT_SHA, True
        ),
        observations=(
            PackageScopeEvidence(
                observation.package_observation_id,
                observation.package_key,
                observation.locations,
                classification,
            ),
        ),
        mixed_scope_gaps=mixed,
        eligible_package_observation_ids=(
            (observation.package_observation_id,) if in_scope else ()
        ),
        candidate_ids=(),
        coordinate_gaps=coordinates,
        decision=decision,
        coverage_limited=bool(gap),
    )
    report = {
        "scope": syft.scope.canonical_data(),
        "components": [item.canonical_data() for item in syft.components],
        "evidence": [item.canonical_data() for item in syft.evidence],
        "findings": [],
        "coverage_outcomes": [
            {
                "authority": "osv.dev",
                "state": outcome_state,
                "reason_code": outcome_reason,
            }
        ],
    }
    dependency = _resolve(
        report,
        {},
        DependencyProjectionMaterial(
            evaluation=evaluation,
            evaluation_sha256=evaluation.sha256(),
        ),
    )
    assert dependency.vulnerability_evaluation == state
    assert dependency.vulnerability_evaluation_reason == reason
    assert dependency.known_vulnerability_count is None
    assert dependency.advisories == ()


def test_multiple_advisories_are_distinct_and_sorted_by_public_finding_id() -> None:
    syft_result, context, projection = syft_native(
        source_run_id=_RUN_ID, locations=("requirements.lock",)
    )
    base = osv_native(syft_result)
    candidate = base.candidates[0]
    first = base.candidate_matches[0].advisories[0]
    second = OsvAdvisoryObservation(
        osv_record_id="OSV-2026-2",
        modified="2026-02-03T04:05:06Z",
        published="2026-02-01T00:00:00Z",
        aliases=("CVE-2026-2222",),
        cve_aliases=("CVE-2026-2222",),
        ghsa_aliases=(),
        summary="Second independent advisory",
        applicable_package_key=candidate.package_key,
        fixed_versions=("2.33.0",),
        cvss=(),
    )
    advisories = tuple(sorted((first, second), key=lambda item: item.osv_record_id))
    references = tuple(
        OsvAdvisoryReference(item.osv_record_id, item.modified) for item in advisories
    )
    findings = group_advisories(candidate, advisories)
    analysis = OsvDependencyAnalysis(
        candidates=(candidate,),
        gaps=(),
        candidate_matches=(OsvCandidateMatch(candidate, references, advisories),),
        findings=findings,
        completed_candidate_ids=(candidate.candidate_id,),
        zero_advisory_candidate_ids=(),
    )
    syft = adapt_syft_result(syft_result, context=context, projection=projection)
    osv = adapt_osv_analysis(analysis, scope=syft.scope)
    report = {
        "scope": syft.scope.canonical_data(),
        "components": [item.canonical_data() for item in syft.components],
        "evidence": [
            item.canonical_data() for item in (*syft.evidence, *osv.evidence)
        ],
        "findings": [item.canonical_data() for item in osv.findings],
        "coverage_outcomes": [
            item.canonical_data()
            for item in (*syft.coverage_outcomes, *osv.coverage_outcomes)
        ],
    }
    priorities = {item.finding_id: "HIGH" for item in osv.findings}
    dependency = _resolve(
        report,
        priorities,
        _material(syft_result, analysis),
    )
    assert dependency.known_vulnerability_count == 2
    assert tuple(item.finding_id for item in dependency.advisories) == tuple(
        sorted(item.finding_id for item in dependency.advisories)
    )
    assert dependency.priority_bands == ("HIGH",)


def test_run_level_partial_does_not_demote_complete_package() -> None:
    first_result, analysis, report, priorities = _analysis(vulnerable=False)
    second_result, second_context, second_projection = syft_native(
        source_run_id=_RUN_ID,
        version=None,
        locations=("unknown.lock",),
    )
    second = adapt_syft_result(
        second_result, context=second_context, projection=second_projection
    )
    report["components"].extend(item.canonical_data() for item in second.components)
    report["evidence"].extend(item.canonical_data() for item in second.evidence)
    osv_outcome = next(
        item for item in report["coverage_outcomes"] if item["authority"] == "osv.dev"
    )
    osv_outcome["state"] = "PARTIAL"
    osv_outcome["reason_code"] = "DEPENDENCY_COVERAGE_LIMITED"
    first_observation = first_result.observations[0]
    second_observation = second_result.observations[0]
    coordinate_gap = DependencyGapEvidence(
        OsvGapReason.PACKAGE_VERSION_UNRESOLVED.value,
        second_observation.package_key,
        (second_observation.package_observation_id,),
        second_observation.locations,
    )
    evaluation = SourceDependencyEvaluation(
        run_id=_RUN_ID,
        osv_node_id=_NODE_ID,
        scope=DependencyScopeEvidence(
            tuple(sorted((*first_observation.locations, *second_observation.locations))),
            "e" * 64,
        ),
        syft_prerequisite=SyftPrerequisiteEvidence(
            _SYFT_NODE_ID, _JOB_ID, 1, _SYFT_SHA, True
        ),
        observations=tuple(
            sorted(
                (
                    PackageScopeEvidence(
                        item.package_observation_id,
                        item.package_key,
                        item.locations,
                        PackageScopeClassification.IN_SCOPE,
                    )
                    for item in (first_observation, second_observation)
                ),
                key=lambda item: item.package_observation_id,
            )
        ),
        mixed_scope_gaps=(),
        eligible_package_observation_ids=tuple(
            sorted(
                (
                    first_observation.package_observation_id,
                    second_observation.package_observation_id,
                )
            )
        ),
        candidate_ids=(analysis.candidates[0].candidate_id,),
        coordinate_gaps=(coordinate_gap,),
        decision=DependencyEvaluationDecision.OSV_RUN_REQUIRED,
        coverage_limited=True,
    )
    execution_input = SourceOsvExecutionInput(
        run_id=_RUN_ID,
        node_id=_NODE_ID,
        job_id=_JOB_ID,
        repository_digest=REPOSITORY_DIGEST,
        profile_digest=PROFILE_DIGEST,
        plan_digest=PLAN_DIGEST,
        scope_digest=evaluation.scope.scope_digest,
        dependency_evaluation_sha256=_EVALUATION_SHA,
        dependency_evaluation_size_bytes=1,
        dependency_evaluation_schema_version=evaluation.schema_version,
        syft_node_id=_SYFT_NODE_ID,
        syft_job_id=_JOB_ID,
        syft_selected_attempt_number=1,
        syft_native_result_sha256=_SYFT_SHA,
        candidates=analysis.candidates,
        coverage_limited=True,
    )
    material = DependencyProjectionMaterial(
        evaluation=evaluation,
        evaluation_sha256=_EVALUATION_SHA,
        execution_input=execution_input,
        accepted_result=SafeSourceOsvResult.from_analysis(
            execution_input, attempt_number=1, analysis=analysis
        ),
    )
    dependencies = resolve_dependency_summaries(report, priorities, material)
    by_name_version = {(item.name, item.version): item for item in dependencies}
    assert by_name_version[("requests", "2.31.0")].vulnerability_evaluation == "COMPLETE"
    assert by_name_version[("requests", "2.31.0")].known_vulnerability_count == 0
    limited = by_name_version[("requests", None)]
    assert limited.vulnerability_evaluation == "PARTIAL"
    assert limited.vulnerability_evaluation_reason == (
        OsvGapReason.PACKAGE_VERSION_UNRESOLVED.value
    )
    assert limited.vulnerability_evaluation_reason != "DEPENDENCY_COVERAGE_LIMITED"
    assert limited.known_vulnerability_count is None


def test_location_index_is_built_once_for_multiple_components(monkeypatch) -> None:
    first_result, first_context, first_projection = syft_native(
        source_run_id=_RUN_ID,
        locations=("a.lock",),
    )
    second_result, second_context, second_projection = syft_native(
        source_run_id=_RUN_ID,
        version="2.30.0",
        locations=("b.lock",),
    )
    first = adapt_syft_result(
        first_result, context=first_context, projection=first_projection
    )
    second = adapt_syft_result(
        second_result, context=second_context, projection=second_projection
    )
    report = {
        "scope": first.scope.canonical_data(),
        "components": [
            item.canonical_data() for item in (*first.components, *second.components)
        ],
        "evidence": [
            item.canonical_data() for item in (*first.evidence, *second.evidence)
        ],
        "findings": [],
        "coverage_outcomes": [],
    }
    from securescan.product_core import dependencies as module

    original = module._repository_paths
    calls = 0

    def counted(item):
        nonlocal calls
        calls += 1
        return original(item)

    monkeypatch.setattr(module, "_repository_paths", counted)
    projected = resolve_dependency_summaries(
        report,
        {},
        DependencyProjectionMaterial(fallback_evaluation="NOT_APPLICABLE"),
    )
    assert len(projected) == 2
    assert calls == len(report["evidence"]) == 2


def test_verified_artifact_loaders_are_called_at_most_once() -> None:
    syft_result, analysis, _report, _priorities = _analysis(vulnerable=False)
    material = _material(syft_result, analysis)
    node = SimpleNamespace(
        node_id=_NODE_ID,
        authority="osv.dev",
        capability="dependency_advisory_matching",
        lifecycle_state="TERMINAL",
        terminal_disposition="COMPLETE",
        terminal_reason_code=None,
    )
    evaluation_row = SimpleNamespace(osv_node_id=_NODE_ID)
    mapping = SimpleNamespace(
        node_id=_NODE_ID,
        job_id=_JOB_ID,
        selected_attempt_number=1,
    )

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def scalars(self, statement):
            entity = statement.column_descriptions[0]["entity"]
            name = entity.__name__
            return {
                "SourceOrchestrationNodeRow": (node,),
                "SourceOrchestrationDependencyEvaluationRow": (evaluation_row,),
                "SourceOrchestrationScannerJobRow": (mapping,),
            }[name]

    counts = {"evaluation": 0, "input": 0, "result": 0}

    def load_evaluation(**_kwargs):
        counts["evaluation"] += 1
        return SimpleNamespace(
            evaluation=material.evaluation,
            artifact_sha256=_EVALUATION_SHA,
        )

    def load_input(**_kwargs):
        counts["input"] += 1
        return material.execution_input

    def load_result(**_kwargs):
        counts["result"] += 1
        return material.accepted_result

    service = object.__new__(SourceDependencyProjectionService)
    service._sessions = lambda: _Session()
    service._evaluations = SimpleNamespace(load=load_evaluation)
    service._osv_jobs = SimpleNamespace(load_input=load_input)
    service._osv_attempts = SimpleNamespace(load_accepted_result=load_result)
    service._orchestrations = SimpleNamespace()
    loaded = service._load_material(_RUN_ID)
    assert loaded.accepted_result == material.accepted_result
    assert counts == {"evaluation": 1, "input": 1, "result": 1}


def test_query_invokes_report_priority_and_projection_once() -> None:
    counts = {"report": 0, "priority": 0, "projection": 0}

    def report(_run_id):
        counts["report"] += 1
        return {}

    def priorities(_run_id):
        counts["priority"] += 1
        return {}

    def project(**_kwargs):
        counts["projection"] += 1
        return ()

    service = object.__new__(SourceScanQueryService)
    service._published_document = report
    service._priorities = priorities
    service._dependency_projection = SimpleNamespace(project=project)
    page = service.list_dependencies(_RUN_ID)
    assert page.items == ()
    assert counts == {"report": 1, "priority": 1, "projection": 1}


def test_resolver_is_read_only_over_report_and_priority_inputs() -> None:
    report, priorities, material = _case(vulnerable=True)
    expected_report = deepcopy(report)
    expected_priorities = dict(priorities)
    first = resolve_dependency_summaries(report, priorities, material)
    second = resolve_dependency_summaries(report, priorities, material)
    assert first == second
    assert report == expected_report
    assert priorities == expected_priorities

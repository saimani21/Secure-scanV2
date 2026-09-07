from __future__ import annotations

from dataclasses import replace
from uuid import UUID

import pytest
from unified_evidence_fixtures import (
    SECOND_RUN_ID,
    SEMGREP_ARTIFACT_BYTES,
    checkov_native,
    gitleaks_native,
    osv_native,
    semgrep_native,
    semgrep_tool_execution,
    syft_native,
)

from securescan.advisories.osv import (
    OsvAdvisoryObservation,
    OsvAdvisoryReference,
    OsvCandidateMatch,
    build_osv_query_candidates,
    group_advisories,
)
from securescan.advisories.osv.evaluation import OsvDependencyAnalysis
from securescan.domain.enums import ArtifactKind, JobStatus
from securescan.evidence import (
    ComponentKind,
    EvidenceAuthority,
    EvidenceKind,
    FindingCategory,
    GapScopeKind,
    PackageSubject,
    SemgrepSanitizedArtifactReference,
    SeverityScheme,
    UnifiedEvidenceError,
    adapt_checkov_result,
    adapt_gitleaks_result,
    adapt_osv_analysis,
    adapt_repository_components,
    adapt_semgrep_assessment,
    adapt_syft_result,
    build_finding_id,
    build_report,
)
from securescan.scanners.gitleaks import build_gitleaks_finding_identity
from securescan.scanners.syft import PackageObservation
from securescan.source import (
    CoverageStatus,
    RepositoryComponent,
    SourceAnalysisGap,
    SourceExecutionStatus,
)


def _semgrep_fragment(**kwargs):
    assessment, context, projection, binding = semgrep_native(**kwargs)
    return adapt_semgrep_assessment(
        assessment,
        context=context,
        projection=projection,
        binding=binding,
        tool_execution=semgrep_tool_execution(assessment),
        sanitized_artifact_bytes=SEMGREP_ARTIFACT_BYTES,
    )


def _gitleaks_fragment(**kwargs):
    result, context, projection = gitleaks_native(**kwargs)
    return adapt_gitleaks_result(result, context=context, projection=projection)


def _syft_fragment(**kwargs):
    result, context, projection = syft_native(**kwargs)
    return result, adapt_syft_result(result, context=context, projection=projection)


def _checkov_fragment(**kwargs):
    result, context, projection = checkov_native(**kwargs)
    return adapt_checkov_result(result, context=context, projection=projection)


def test_semgrep_adapter_preserves_native_identity_evidence_and_severity() -> None:
    assessment, context, projection, binding = semgrep_native()
    fragment = adapt_semgrep_assessment(
        assessment,
        context=context,
        projection=projection,
        binding=binding,
        tool_execution=semgrep_tool_execution(assessment),
        sanitized_artifact_bytes=SEMGREP_ARTIFACT_BYTES,
    )
    finding = fragment.findings[0]
    evidence = fragment.evidence[0]
    assert finding.category is FindingCategory.CODE_SECURITY
    assert finding.native_finding_identity == assessment.observations[0].fingerprint
    assert finding.primary_evidence_refs == (evidence.evidence_id,)
    assert finding.severity is not None
    assert finding.severity.scheme is SeverityScheme.SEMGREP_NORMALIZED
    assert evidence.payload.cwe_ids == ("CWE-95",)  # type: ignore[union-attr]
    assert evidence.provenance.ruleset_digest == binding.ruleset_sha256  # type: ignore[union-attr]


def test_gitleaks_adapter_uses_safe_structural_identity_only() -> None:
    result, context, projection = gitleaks_native()
    fragment = adapt_gitleaks_result(result, context=context, projection=projection)
    identity = build_gitleaks_finding_identity(result.findings[0])
    finding = fragment.findings[0]
    evidence = fragment.evidence[0]
    assert finding.category is FindingCategory.SECRET_EXPOSURE
    assert finding.native_finding_identity == identity.finding_instance_id
    assert evidence.evidence_kind is EvidenceKind.GITLEAKS_SECRET_OBSERVATION
    assert evidence.payload.detection_kind == "CONTENT"  # type: ignore[union-attr]
    assert identity.identity_material()["scanner_version"] == result.scanner_version


def test_gitleaks_duplicate_native_identity_preserves_multiplicity() -> None:
    result, context, projection = gitleaks_native()
    duplicate = replace(
        result,
        findings=(result.findings[0], result.findings[0]),
        finding_count=2,
    )
    fragment = adapt_gitleaks_result(duplicate, context=context, projection=projection)
    single = adapt_gitleaks_result(result, context=context, projection=projection)
    assert len(fragment.findings) == len(fragment.evidence) == 1
    assert fragment.findings[0].finding_id == single.findings[0].finding_id
    assert fragment.evidence[0].payload.native_occurrence_count == 2  # type: ignore[union-attr]
    assert fragment.coverage_outcomes[0].finding_count == 2
    assert b"raw_secret" not in repr(fragment.evidence[0].canonical_data()).lower().encode()
    report = build_report(fragment.scope, fragment)  # type: ignore[arg-type]
    assert report.coverage_outcomes[0].finding_count == 2


def test_gitleaks_duplicate_projection_is_input_order_independent() -> None:
    result, context, projection = gitleaks_native()
    other = replace(
        result.findings[0],
        start_line=9,
        end_line=9,
    )
    first = replace(
        result,
        findings=(result.findings[0], other, result.findings[0]),
        finding_count=3,
    )
    second = replace(first, findings=tuple(reversed(first.findings)))
    assert adapt_gitleaks_result(
        first, context=context, projection=projection
    ) == adapt_gitleaks_result(second, context=context, projection=projection)


def test_syft_adapter_creates_component_and_evidence_but_no_finding() -> None:
    result, fragment = _syft_fragment()
    component = fragment.components[0]
    evidence = fragment.evidence[0]
    assert component.component_kind is ComponentKind.PACKAGE
    assert component.native_component_identity == result.observations[0].package_key
    assert evidence.component_refs == (component.component_ref,)
    assert evidence.authority is EvidenceAuthority.SYFT
    assert fragment.findings == ()


def test_osv_finding_uses_osv_primary_and_syft_supporting_evidence() -> None:
    syft_result, syft_fragment = _syft_fragment()
    analysis = osv_native(syft_result)
    osv_fragment = adapt_osv_analysis(analysis, scope=syft_fragment.scope)
    finding = osv_fragment.findings[0]
    assert finding.category is FindingCategory.DEPENDENCY_VULNERABILITY
    assert isinstance(finding.subject, PackageSubject)
    assert finding.subject.component_ref == syft_fragment.components[0].component_ref
    assert all(
        reference in {item.evidence_id for item in osv_fragment.evidence}
        for reference in finding.primary_evidence_refs
    )
    assert finding.supporting_evidence_refs == (syft_fragment.evidence[0].evidence_id,)
    group = next(
        item
        for item in osv_fragment.evidence
        if item.evidence_kind is EvidenceKind.OSV_ADVISORY_GROUP
    )
    assert group.payload.package_observation_ids == (  # type: ignore[union-attr]
        syft_result.observations[0].package_observation_id,
    )
    assert finding.severity is None


def test_one_syft_observation_supports_multiple_legitimate_osv_findings() -> None:
    syft_result, syft_fragment = _syft_fragment()
    original = osv_native(syft_result)
    candidate = original.candidates[0]
    first = original.candidate_matches[0].advisories[0]
    second = replace(
        first,
        osv_record_id="GHSA-2222-3333-4444",
        modified="2026-02-03T04:05:06Z",
        published="2025-02-03T04:05:06Z",
        aliases=("CVE-2025-22222",),
        cve_aliases=("CVE-2025-22222",),
        ghsa_aliases=("GHSA-2222-3333-4444",),
    )
    references = tuple(
        sorted(
            (OsvAdvisoryReference(item.osv_record_id, item.modified) for item in (first, second)),
            key=lambda item: (item.osv_record_id, item.modified),
        )
    )
    analysis = OsvDependencyAnalysis(
        candidates=(candidate,),
        gaps=(),
        candidate_matches=(OsvCandidateMatch(candidate, references, (first, second)),),
        findings=group_advisories(candidate, (first, second)),
        completed_candidate_ids=(candidate.candidate_id,),
        zero_advisory_candidate_ids=(),
    )
    osv = adapt_osv_analysis(analysis, scope=syft_fragment.scope)
    report = build_report(syft_fragment.scope, syft_fragment, osv)  # type: ignore[arg-type]
    assert len(report.findings) == 2
    assert {item.supporting_evidence_refs for item in report.findings} == {
        (syft_fragment.evidence[0].evidence_id,)
    }


def test_advisory_revision_can_support_multiple_bound_package_findings() -> None:
    syft_result, context, projection = syft_native()
    second_package = PackageObservation.create(
        package_name="flask",
        package_version="3.0.0",
        package_type="python",
        language="python",
        purl="pkg:pypi/flask@3.0.0",
        found_by="python-package-cataloger",
        locations=("requirements.txt",),
        projection_id=syft_result.projection_id,
        snapshot_digest=syft_result.snapshot_digest,
        binding_digest=syft_result.binding_digest,
    )
    combined_result = replace(
        syft_result,
        observations=tuple(
            sorted(
                (*syft_result.observations, second_package),
                key=lambda item: (
                    item.package_observation_id,
                    item.package_key,
                    item.package_name,
                ),
            )
        ),
        package_count=2,
    )
    syft_fragment = adapt_syft_result(combined_result, context=context, projection=projection)
    candidates, gaps = build_osv_query_candidates(combined_result.observations)
    assert not gaps
    matches = []
    findings = []
    for candidate in candidates:
        advisory = OsvAdvisoryObservation(
            osv_record_id="GHSA-9wx4-h78v-vm56",
            modified="2026-01-02T03:04:05Z",
            published="2025-01-02T03:04:05Z",
            aliases=("CVE-2025-12345",),
            cve_aliases=("CVE-2025-12345",),
            ghsa_aliases=("GHSA-9wx4-h78v-vm56",),
            summary="Shared controlled advisory revision",
            applicable_package_key=candidate.package_key,
            fixed_versions=(),
            cvss=(),
        )
        reference = OsvAdvisoryReference(advisory.osv_record_id, advisory.modified)
        matches.append(OsvCandidateMatch(candidate, (reference,), (advisory,)))
        findings.extend(group_advisories(candidate, (advisory,)))
    analysis = OsvDependencyAnalysis(
        candidates=candidates,
        gaps=(),
        candidate_matches=tuple(matches),
        findings=tuple(sorted(findings, key=lambda item: item.finding_id)),
        completed_candidate_ids=tuple(sorted(item.candidate_id for item in candidates)),
        zero_advisory_candidate_ids=(),
    )
    osv = adapt_osv_analysis(analysis, scope=syft_fragment.scope)
    report = build_report(syft_fragment.scope, syft_fragment, osv)  # type: ignore[arg-type]
    revisions = [
        item for item in report.evidence if item.evidence_kind is EvidenceKind.OSV_ADVISORY_REVISION
    ]
    assert len(revisions) == 1
    assert set(revisions[0].component_refs) == {
        item.component_ref for item in syft_fragment.components
    }


def test_osv_support_rejects_same_package_nonoriginating_syft_observation() -> None:
    original_result, context, projection = syft_native()
    original = original_result.observations[0]
    substitute = PackageObservation.create(
        package_name=original.package_name,
        package_version=original.package_version,
        package_type=original.package_type,
        language=original.language,
        purl=original.purl,
        found_by="second-python-package-cataloger",
        locations=original.locations,
        projection_id=original.projection_id,
        snapshot_digest=original.snapshot_digest,
        binding_digest=original.binding_digest,
    )
    assert substitute.package_key == original.package_key
    assert substitute.package_observation_id != original.package_observation_id
    combined_result = replace(
        original_result,
        used_catalogers=tuple(sorted((*original_result.used_catalogers, substitute.found_by))),
        observations=tuple(
            sorted(
                (original, substitute),
                key=lambda item: (
                    item.package_observation_id,
                    item.package_key,
                    item.package_name,
                ),
            )
        ),
        package_count=2,
    )
    syft = adapt_syft_result(combined_result, context=context, projection=projection)

    originating_osv = adapt_osv_analysis(osv_native(original_result), scope=syft.scope)
    build_report(syft.scope, syft, originating_osv)  # type: ignore[arg-type]
    finding = originating_osv.findings[0]
    evidence_by_native_id = {item.native_identity: item.evidence_id for item in syft.evidence}
    original_ref = evidence_by_native_id[original.package_observation_id]
    substitute_ref = evidence_by_native_id[substitute.package_observation_id]
    assert finding.supporting_evidence_refs == (original_ref,)

    for changed_refs in (
        (substitute_ref,),
        tuple(sorted((original_ref, substitute_ref))),
    ):
        changed = replace(finding, supporting_evidence_refs=changed_refs)
        changed_fragment = replace(originating_osv, findings=(changed,))
        with pytest.raises(UnifiedEvidenceError):
            build_report(syft.scope, syft, changed_fragment)  # type: ignore[arg-type]

    exact_both = adapt_osv_analysis(osv_native(combined_result), scope=syft.scope)
    exact_report = build_report(syft.scope, syft, exact_both)  # type: ignore[arg-type]
    assert exact_report.findings[0].supporting_evidence_refs == tuple(
        sorted((original_ref, substitute_ref))
    )


def test_checkov_adapter_separates_findings_suppressions_gaps_and_coverage() -> None:
    fragment = _checkov_fragment()
    assert len(fragment.findings) == 1
    assert len(fragment.suppressions) == 1
    assert len(fragment.gaps) == 1
    assert len(fragment.coverage_outcomes) == 5
    assert fragment.findings[0].category is FindingCategory.CONFIGURATION_SECURITY
    assert fragment.gaps[0].scope.kind is GapScopeKind.PATH
    assert fragment.gaps[0].scope.value == "malformed.tf"
    assert fragment.gaps[0].scope.framework == "terraform"
    assert sum(item.finding_count for item in fragment.coverage_outcomes) == 1
    assert sum(item.suppression_count for item in fragment.coverage_outcomes) == 1
    assert sum(item.gap_count for item in fragment.coverage_outcomes) == 1


def test_same_native_finding_in_two_runs_has_same_id_but_separate_occurrence() -> None:
    first = _semgrep_fragment()
    second = _semgrep_fragment(source_run_id=SECOND_RUN_ID)
    assert first.findings[0].finding_id == second.findings[0].finding_id
    assert first.scope is not None and second.scope is not None
    assert first.scope.source_run_id != second.scope.source_run_id
    assert (first.scope.source_run_id, first.findings[0].finding_id) != (
        second.scope.source_run_id,
        second.findings[0].finding_id,
    )


def test_authorities_domain_separate_identical_native_identity_text() -> None:
    native = "1" * 64
    assert build_finding_id(EvidenceAuthority.SEMGREP, "native-v1", native) != (
        build_finding_id(EvidenceAuthority.CHECKOV, "native-v1", native)
    )


def test_semgrep_line_movement_follows_native_identity() -> None:
    assert _semgrep_fragment(line=7).findings[0].finding_id != (
        _semgrep_fragment(line=8).findings[0].finding_id
    )


def test_semgrep_display_message_and_severity_do_not_change_identity() -> None:
    original = _semgrep_fragment()
    changed = _semgrep_fragment(message="Another fixed display message", severity="low")
    assert original.findings[0].finding_id == changed.findings[0].finding_id


def test_checkov_line_name_and_severity_changes_do_not_change_identity() -> None:
    original = _checkov_fragment()
    changed = _checkov_fragment(
        line_start=20,
        check_name="Changed display name",
        severity="LOW",
    )
    assert original.findings[0].finding_id == changed.findings[0].finding_id


def test_projection_change_does_not_change_semgrep_finding_identity() -> None:
    assessment, context, projection, binding = semgrep_native()
    original = adapt_semgrep_assessment(
        assessment,
        context=context,
        projection=projection,
        binding=binding,
        tool_execution=semgrep_tool_execution(assessment),
        sanitized_artifact_bytes=SEMGREP_ARTIFACT_BYTES,
    )
    changed = adapt_semgrep_assessment(
        assessment,
        context=context,
        projection=replace(
            projection,
            projection_id="securescan-source-projection-" + "5" * 32,
            projection_digest="6" * 64,
        ),
        binding=binding,
        tool_execution=semgrep_tool_execution(assessment),
        sanitized_artifact_bytes=SEMGREP_ARTIFACT_BYTES,
    )
    assert original.findings[0].finding_id == changed.findings[0].finding_id
    assert original.evidence[0].provenance != changed.evidence[0].provenance


def test_semgrep_sanitized_artifact_provenance_is_validated_and_safe() -> None:
    assessment, context, projection, binding = semgrep_native()
    execution = semgrep_tool_execution(assessment)
    fragment = adapt_semgrep_assessment(
        assessment,
        context=context,
        projection=projection,
        binding=binding,
        tool_execution=execution,
        sanitized_artifact_bytes=SEMGREP_ARTIFACT_BYTES,
    )
    provenance = fragment.evidence[0].provenance
    assert isinstance(provenance.sanitized_artifact, SemgrepSanitizedArtifactReference)  # type: ignore[union-attr]
    artifact = provenance.sanitized_artifact  # type: ignore[union-attr]
    assert artifact.artifact_id == str(execution.artifacts[0].artifact_id)
    assert artifact.tool_execution_id == assessment.final_tool_execution_id
    assert artifact.sha256 == execution.artifacts[0].sha256
    serialized = fragment.evidence[0].canonical_data()
    assert "storage_path" not in repr(serialized)
    assert SEMGREP_ARTIFACT_BYTES not in repr(serialized).encode()


def test_semgrep_sanitized_artifact_integrity_mismatches_fail_closed() -> None:
    assessment, context, projection, binding = semgrep_native()
    execution = semgrep_tool_execution(assessment)
    mutations = (
        execution.model_copy(update={"run_id": UUID("00000000-0000-4000-8000-00000000a499")}),
        execution.model_copy(update={"execution_id": UUID("00000000-0000-4000-8000-00000000a498")}),
        execution.model_copy(
            update={"artifacts": [execution.artifacts[0].model_copy(update={"sha256": "0" * 64})]}
        ),
        execution.model_copy(
            update={
                "artifacts": [
                    execution.artifacts[0].model_copy(update={"kind": ArtifactKind.STDOUT})
                ]
            }
        ),
        execution.model_copy(
            update={"artifacts": [execution.artifacts[0].model_copy(update={"sanitized": False})]}
        ),
    )
    for changed in mutations:
        with pytest.raises(UnifiedEvidenceError):
            adapt_semgrep_assessment(
                assessment,
                context=context,
                projection=projection,
                binding=binding,
                tool_execution=changed,
                sanitized_artifact_bytes=SEMGREP_ARTIFACT_BYTES,
            )
    with pytest.raises(UnifiedEvidenceError):
        adapt_semgrep_assessment(
            assessment,
            context=context,
            projection=projection,
            binding=binding,
            tool_execution=execution,
            sanitized_artifact_bytes=SEMGREP_ARTIFACT_BYTES + b"changed",
        )


def test_multi_component_coverage_is_scope_sensitive_and_count_isolated() -> None:
    first = _semgrep_fragment(path="backend/app.py", component_id="backend")
    second = _semgrep_fragment(path="worker/app.py", component_id="worker")
    components = adapt_repository_components(
        (
            RepositoryComponent(
                component_id="backend",
                display_name="Backend",
                root_path="backend",
            ),
            RepositoryComponent(
                component_id="worker",
                display_name="Worker",
                root_path="worker",
            ),
        )
    )
    assert first.coverage_outcomes[0].coverage_id != second.coverage_outcomes[0].coverage_id
    report = build_report(first.scope, components, first, second)  # type: ignore[arg-type]
    assert [item.finding_count for item in report.coverage_outcomes] == [1, 1]
    assert report == build_report(first.scope, components, second, first)  # type: ignore[arg-type]
    with pytest.raises(UnifiedEvidenceError):
        replace(
            report,
            coverage_outcomes=(
                report.coverage_outcomes[0],
                report.coverage_outcomes[0],
            ),
        )

    changed_outcome = replace(first.coverage_outcomes[0], finding_count=2)
    changed = replace(first, coverage_outcomes=(changed_outcome,))
    with pytest.raises(UnifiedEvidenceError):
        build_report(first.scope, components, changed, second)  # type: ignore[arg-type]


def test_package_location_changes_evidence_not_component_identity() -> None:
    _, original = _syft_fragment(locations=("requirements.txt",))
    _, changed = _syft_fragment(locations=("service/requirements.txt",))
    assert original.components[0].component_ref == changed.components[0].component_ref
    assert original.evidence[0].evidence_id != changed.evidence[0].evidence_id


def test_dependency_version_changes_component_and_osv_finding_identity() -> None:
    old_result, old_syft = _syft_fragment(version="2.31.0")
    new_result, new_syft = _syft_fragment(version="2.30.0")
    old_osv = adapt_osv_analysis(osv_native(old_result), scope=old_syft.scope)
    new_osv = adapt_osv_analysis(osv_native(new_result), scope=new_syft.scope)
    assert old_syft.components[0].component_ref != new_syft.components[0].component_ref
    assert old_osv.findings[0].finding_id != new_osv.findings[0].finding_id


def test_osv_alias_group_change_follows_native_identity() -> None:
    syft_result, syft_fragment = _syft_fragment()
    original = adapt_osv_analysis(osv_native(syft_result), scope=syft_fragment.scope)
    changed = adapt_osv_analysis(
        osv_native(syft_result, alias="CVE-2025-54321"),
        scope=syft_fragment.scope,
    )
    assert original.findings[0].finding_id != changed.findings[0].finding_id


def test_gitleaks_binding_and_run_provenance_do_not_change_native_identity() -> None:
    result, context, projection = gitleaks_native()
    original = adapt_gitleaks_result(result, context=context, projection=projection)
    changed_context = replace(
        context,
        source_run_id=SECOND_RUN_ID,
        binding_digest="8" * 64,
    )
    changed_finding = replace(result.findings[0], context_digest=changed_context.context_digest())
    changed_result = replace(
        result,
        binding_digest="8" * 64,
        context_digest=changed_context.context_digest(),
        findings=(changed_finding,),
    )
    changed_projection = replace(projection, context_digest=changed_context.context_digest())
    changed = adapt_gitleaks_result(
        changed_result,
        context=changed_context,
        projection=changed_projection,
    )
    assert original.findings[0].finding_id == changed.findings[0].finding_id


def test_semgrep_source_gap_remains_a_gap_and_forces_partial_coverage() -> None:
    assessment, context, projection, binding = semgrep_native()
    native_gap = SourceAnalysisGap(
        code="SEMGREP_PARSE_ERROR",
        capability=context.capability,
        component_id=None,
        stage="semgrep_parse",
        relative_path="src/app.py",
        message="Semgrep could not parse part of the repository",
    )
    assessment = replace(
        assessment,
        execution_status=SourceExecutionStatus.PARTIAL,
        coverage_status=CoverageStatus.PARTIAL,
        terminal_job_status=JobStatus.PARTIAL,
        gaps=(native_gap,),
    )
    fragment = adapt_semgrep_assessment(
        assessment,
        context=context,
        projection=projection,
        binding=binding,
        tool_execution=semgrep_tool_execution(assessment),
        sanitized_artifact_bytes=SEMGREP_ARTIFACT_BYTES,
    )
    assert len(fragment.gaps) == 1
    assert fragment.coverage_outcomes[0].state.value == "PARTIAL"
    assert fragment.coverage_outcomes[0].gap_count == 1


def test_osv_unresolved_package_remains_a_package_gap_not_a_finding() -> None:
    syft_result, syft_fragment = _syft_fragment(version=None)
    candidates, gaps = build_osv_query_candidates(syft_result.observations)
    assert candidates == () and len(gaps) == 1
    analysis = OsvDependencyAnalysis((), gaps, (), (), (), ())
    osv_fragment = adapt_osv_analysis(analysis, scope=syft_fragment.scope)
    assert osv_fragment.findings == ()
    assert len(osv_fragment.gaps) == 1
    assert osv_fragment.coverage_outcomes[0].state.value == "PARTIAL"
    assert syft_fragment.scope is not None
    report = build_report(syft_fragment.scope, syft_fragment, osv_fragment)
    assert len(report.gaps) == 1

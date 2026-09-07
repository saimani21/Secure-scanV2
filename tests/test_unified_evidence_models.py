from __future__ import annotations

import hashlib
from dataclasses import fields, replace

import pytest
from unified_evidence_fixtures import (
    REPOSITORY_DIGEST,
    RUN_ID,
    SEMGREP_ARTIFACT_BYTES,
    checkov_native,
    gitleaks_native,
    osv_native,
    semgrep_native,
    semgrep_tool_execution,
    syft_native,
)

from securescan.evidence import (
    SECURESCAN_EVIDENCE_SCHEMA_VERSION,
    ComponentKind,
    EvidenceAuthority,
    FindingCategory,
    PackageSubject,
    RepositoryPathLocation,
    RepositoryScopeLocation,
    SecureScanEvidenceFragment,
    SecureScanEvidenceReport,
    SecureScanFinding,
    SecureScanReportScope,
    SourceSpanLocation,
    UnifiedEvidenceError,
    adapt_checkov_result,
    adapt_gitleaks_result,
    adapt_osv_analysis,
    adapt_semgrep_assessment,
    adapt_syft_result,
    build_report,
)


def _report() -> SecureScanEvidenceReport:
    assessment, semgrep_context, semgrep_projection, binding = semgrep_native()
    semgrep = adapt_semgrep_assessment(
        assessment,
        context=semgrep_context,
        projection=semgrep_projection,
        binding=binding,
        tool_execution=semgrep_tool_execution(assessment),
        sanitized_artifact_bytes=SEMGREP_ARTIFACT_BYTES,
    )
    gitleaks_result, gitleaks_context, gitleaks_projection = gitleaks_native()
    gitleaks = adapt_gitleaks_result(
        gitleaks_result,
        context=gitleaks_context,
        projection=gitleaks_projection,
    )
    syft_result, syft_context, syft_projection = syft_native()
    syft = adapt_syft_result(
        syft_result,
        context=syft_context,
        projection=syft_projection,
    )
    osv = adapt_osv_analysis(osv_native(syft_result), scope=syft.scope)
    checkov_result, checkov_context, checkov_projection = checkov_native()
    checkov = adapt_checkov_result(
        checkov_result,
        context=checkov_context,
        projection=checkov_projection,
    )
    assert syft.scope is not None
    return build_report(syft.scope, semgrep, gitleaks, syft, osv, checkov)


def test_schema_and_finding_taxonomy_are_exactly_frozen() -> None:
    assert SECURESCAN_EVIDENCE_SCHEMA_VERSION == "securescan-unified-evidence-s4-v1"
    assert {item.value for item in FindingCategory} == {
        "CODE_SECURITY",
        "SECRET_EXPOSURE",
        "DEPENDENCY_VULNERABILITY",
        "CONFIGURATION_SECURITY",
    }
    assert "PACKAGE_INVENTORY" not in {item.value for item in FindingCategory}


def test_report_scope_is_run_provenance_not_finding_identity() -> None:
    report = _report()
    assert report.scope == SecureScanReportScope(
        RUN_ID,
        REPOSITORY_DIGEST,
        "b" * 64,
        "c" * 64,
    )
    assert "source_run_id" not in fields(SecureScanFinding)


def test_location_union_is_typed_and_rejects_host_paths() -> None:
    assert SourceSpanLocation("src/app.py", 1, 3, 20, 2).end_column == 2
    assert RepositoryPathLocation("requirements.txt").path == "requirements.txt"
    assert RepositoryScopeLocation().canonical_data()["kind"] == "REPOSITORY_SCOPE"
    with pytest.raises(UnifiedEvidenceError):
        RepositoryPathLocation("/home/user/repository/secret.py")
    with pytest.raises(UnifiedEvidenceError):
        SourceSpanLocation("../escape.py", 1, 1)
    with pytest.raises(UnifiedEvidenceError):
        SourceSpanLocation("app.py", 2, 1)


def test_report_has_only_repository_and_package_components() -> None:
    report = _report()
    assert {item.component_kind for item in report.components} <= {
        ComponentKind.REPOSITORY,
        ComponentKind.PACKAGE,
    }
    assert all("FILE" not in item.component_kind.value for item in report.components)


def test_controlled_graph_contains_all_required_sibling_collections() -> None:
    report = _report()
    assert len(report.findings) == 4
    assert len(report.components) == 1
    assert len(report.evidence) == 6
    assert len(report.suppressions) == 1
    assert len(report.gaps) == 1
    assert len(report.coverage_outcomes) == 9
    package_finding = next(
        item for item in report.findings if isinstance(item.subject, PackageSubject)
    )
    assert len(package_finding.primary_evidence_refs) == 2
    assert len(package_finding.supporting_evidence_refs) == 1


def test_canonical_json_is_sorted_byte_deterministic_and_strict_json() -> None:
    first = _report().canonical_json()
    second = _report().canonical_json()
    assert first == second
    assert hashlib.sha256(first).hexdigest() == hashlib.sha256(second).hexdigest()
    assert first.endswith(b"\n")
    assert b"NaN" not in first


def test_duplicate_and_unsorted_collections_fail_closed() -> None:
    report = _report()
    with pytest.raises(UnifiedEvidenceError):
        replace(report, evidence=(report.evidence[0], report.evidence[0]))
    with pytest.raises(UnifiedEvidenceError):
        replace(report, evidence=tuple(reversed(report.evidence)))


def test_dangling_primary_supporting_and_component_refs_fail_closed() -> None:
    report = _report()
    semgrep_index = next(
        index
        for index, item in enumerate(report.findings)
        if item.authority is EvidenceAuthority.SEMGREP
    )
    dangling = replace(report.findings[semgrep_index], primary_evidence_refs=("0" * 64,))
    findings = list(report.findings)
    findings[semgrep_index] = dangling
    with pytest.raises(UnifiedEvidenceError):
        replace(report, findings=tuple(sorted(findings, key=lambda item: item.finding_id)))

    osv_index = next(
        index
        for index, item in enumerate(report.findings)
        if item.authority is EvidenceAuthority.OSV
    )
    dangling = replace(report.findings[osv_index], supporting_evidence_refs=("0" * 64,))
    findings = list(report.findings)
    findings[osv_index] = dangling
    with pytest.raises(UnifiedEvidenceError):
        replace(report, findings=tuple(sorted(findings, key=lambda item: item.finding_id)))

    syft_index = next(
        index
        for index, item in enumerate(report.evidence)
        if item.authority is EvidenceAuthority.SYFT
    )
    evidence = list(report.evidence)
    evidence[syft_index] = replace(evidence[syft_index], component_refs=("0" * 64,))
    with pytest.raises(UnifiedEvidenceError):
        replace(report, evidence=tuple(sorted(evidence, key=lambda item: item.evidence_id)))


def test_wrong_category_subject_and_payload_relationships_fail_closed() -> None:
    report = _report()
    semgrep = next(item for item in report.findings if item.authority is EvidenceAuthority.SEMGREP)
    with pytest.raises(UnifiedEvidenceError):
        replace(semgrep, category=FindingCategory.SECRET_EXPOSURE)
    with pytest.raises(UnifiedEvidenceError):
        replace(semgrep, subject=PackageSubject("0" * 64))

    evidence = next(item for item in report.evidence if item.authority is EvidenceAuthority.SEMGREP)
    changed_payload = replace(evidence.payload, rule_id="securescan.python.other")
    changed_evidence = replace(evidence, payload=changed_payload)
    evidence_values = tuple(
        sorted(
            (
                changed_evidence if item.evidence_id == evidence.evidence_id else item
                for item in report.evidence
            ),
            key=lambda item: item.evidence_id,
        )
    )
    with pytest.raises(UnifiedEvidenceError):
        replace(report, evidence=evidence_values)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_run_id", "00000000-0000-4000-8000-00000000a499"),
        ("repository_digest", "1" * 64),
        ("profile_digest", "2" * 64),
        ("plan_digest", "3" * 64),
    ),
)
def test_fragment_scope_mismatch_fails_report_assembly(field: str, value: str) -> None:
    report = _report()
    changed_scope = replace(report.scope, **{field: value})
    fragment = SecureScanEvidenceFragment(scope=changed_scope)
    with pytest.raises(UnifiedEvidenceError):
        build_report(report.scope, fragment)


def test_no_confidence_or_raw_private_fields_exist_in_schema() -> None:
    report = _report()
    canonical = report.canonical_json()
    forbidden = (
        b"confidence",
        b"raw_secret",
        b"must-not-persist",
        b"code_block",
        b"evaluations",
        b"connected_node",
        b"stdout",
        b"stderr",
        b"raw_json",
        b"/home/",
        b"/tmp/",
    )
    assert all(value not in canonical.lower() for value in forbidden)


def test_osv_cvss_is_not_flattened_to_generic_severity() -> None:
    report = _report()
    osv = next(item for item in report.findings if item.authority is EvidenceAuthority.OSV)
    assert osv.severity is None


def _replace_evidence(report, changed):
    return replace(
        report,
        evidence=tuple(
            sorted(
                (
                    changed if item.evidence_id == changed.evidence_id else item
                    for item in report.evidence
                ),
                key=lambda item: item.evidence_id,
            )
        ),
    )


def test_osv_syft_wrong_package_relationship_fails_closed() -> None:
    report = _report()
    _, second_context, second_projection = syft_native(version="2.30.0")
    second_result, _, _ = syft_native(version="2.30.0")
    second = adapt_syft_result(
        second_result,
        context=second_context,
        projection=second_projection,
    )
    osv = next(item for item in report.findings if item.authority is EvidenceAuthority.OSV)
    changed_finding = replace(osv, supporting_evidence_refs=(second.evidence[0].evidence_id,))
    with pytest.raises(UnifiedEvidenceError):
        replace(
            report,
            components=tuple(
                sorted(
                    (*report.components, *second.components),
                    key=lambda item: item.component_ref,
                )
            ),
            evidence=tuple(
                sorted(
                    (*report.evidence, *second.evidence),
                    key=lambda item: item.evidence_id,
                )
            ),
            findings=tuple(
                sorted(
                    (
                        changed_finding if item.finding_id == osv.finding_id else item
                        for item in report.findings
                    ),
                    key=lambda item: item.finding_id,
                )
            ),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("binding_digest", "1" * 64),
        ("projection_digest", "2" * 64),
        ("projection_id", "securescan-source-projection-" + "3" * 32),
    ),
)
def test_osv_syft_provenance_mismatch_fails_closed(field: str, value: str) -> None:
    report = _report()
    syft = next(item for item in report.evidence if item.authority is EvidenceAuthority.SYFT)
    changed = replace(syft, provenance=replace(syft.provenance, **{field: value}))
    with pytest.raises(UnifiedEvidenceError):
        _replace_evidence(report, changed)


def test_osv_primary_package_and_group_binding_fail_closed() -> None:
    report = _report()
    group = next(
        item for item in report.evidence if item.evidence_kind.value == "OSV_ADVISORY_GROUP"
    )
    with pytest.raises(UnifiedEvidenceError):
        _replace_evidence(report, replace(group, component_refs=()))
    unrelated = replace(
        group,
        payload=replace(group.payload, finding_id="7" * 64),
    )
    with pytest.raises(UnifiedEvidenceError):
        _replace_evidence(report, unrelated)


@pytest.mark.parametrize(
    "package_observation_ids",
    (
        (),
        ("1" * 64, "0" * 64),
        ("1" * 64, "1" * 64),
        ("not-a-syft-observation-id",),
    ),
)
def test_osv_group_requires_canonical_package_observation_ids(
    package_observation_ids: tuple[str, ...],
) -> None:
    report = _report()
    group = next(
        item for item in report.evidence if item.evidence_kind.value == "OSV_ADVISORY_GROUP"
    )
    with pytest.raises(UnifiedEvidenceError):
        replace(group.payload, package_observation_ids=package_observation_ids)


def test_suppression_gap_and_coverage_are_not_findings() -> None:
    report = _report()
    assert not {item.suppression_id for item in report.suppressions} & {
        item.finding_id for item in report.findings
    }
    assert not {item.gap_id for item in report.gaps} & {item.finding_id for item in report.findings}
    assert all(item.primary_evidence_refs for item in report.findings)


def test_report_rejects_noncanonical_source_run_id() -> None:
    with pytest.raises(UnifiedEvidenceError):
        SecureScanReportScope(RUN_ID.upper(), REPOSITORY_DIGEST, "b" * 64, "c" * 64)


def test_native_payload_identity_cannot_be_repaired_by_rehashing_wrapper() -> None:
    report = _report()
    evidence = next(item for item in report.evidence if item.authority is EvidenceAuthority.CHECKOV)
    changed_payload = replace(evidence.payload, observation_id="0" * 64)
    with pytest.raises(UnifiedEvidenceError):
        replace(evidence, payload=changed_payload)


def test_model_is_immutable() -> None:
    report = _report()
    with pytest.raises(AttributeError):
        report.scope = replace(report.scope, source_run_id=RUN_ID)  # type: ignore[misc]


def test_canonical_serialization_revalidates_hostile_nested_mutation() -> None:
    report = _report()
    evidence = next(item for item in report.evidence if item.authority is EvidenceAuthority.SEMGREP)
    object.__setattr__(evidence.payload, "rule_id", "hostile.changed-rule")
    with pytest.raises(UnifiedEvidenceError):
        report.canonical_json()


def test_canonical_revalidation_covers_new_nested_s4_contracts() -> None:
    report = _report()
    semgrep = next(item for item in report.evidence if item.authority is EvidenceAuthority.SEMGREP)
    object.__setattr__(
        semgrep.provenance.sanitized_artifact,  # type: ignore[union-attr]
        "sanitized",
        False,
    )
    with pytest.raises(UnifiedEvidenceError):
        report.canonical_json()

    report = _report()
    gitleaks = next(
        item for item in report.evidence if item.authority is EvidenceAuthority.GITLEAKS
    )
    object.__setattr__(gitleaks.payload, "native_occurrence_count", 0)
    with pytest.raises(UnifiedEvidenceError):
        report.canonical_json()

    report = _report()
    object.__setattr__(report.coverage_outcomes[0], "component_ref", "0" * 64)
    with pytest.raises(UnifiedEvidenceError):
        report.canonical_json()

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import HTTPException
from sqlalchemy import text
from test_source_orchestration_s6b import _RUN_ID
from test_source_product_core_pc1 import indexed_context, published_environment  # noqa: F401
from test_unified_evidence_models import _report

from securescan.api.guidance_routes import get_finding_guidance, router
from securescan.api.guidance_schemas import FindingGuidanceResponse
from securescan.evidence.models import EvidenceAuthority
from securescan.persistence.database import Base
from securescan.product_core.guidance import (
    CheckovGuidanceRenderer,
    EvidenceOnlyGuidanceRenderer,
    FindingGuidanceNotFoundError,
    FindingGuidanceService,
    FindingGuidanceUnavailableError,
    GitleaksGuidanceRenderer,
    GuidanceBasis,
    OsvGuidanceRenderer,
    SemgrepGuidanceRenderer,
)


def _finding_and_evidence(authority: EvidenceAuthority):
    report = _report()
    finding = next(item for item in report.findings if item.authority is authority)
    evidence = {item.evidence_id: item for item in report.evidence}
    return report, finding, evidence


def _serialized(guidance) -> str:
    response = FindingGuidanceResponse.model_validate(guidance)
    return json.dumps(response.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def test_semgrep_classification_and_family_are_not_exact_fixes() -> None:
    report, finding, evidence = _finding_and_evidence(EvidenceAuthority.SEMGREP)
    renderer = SemgrepGuidanceRenderer()
    classified = renderer.render(report.scope.source_run_id, finding, evidence)
    assert classified.basis_level is GuidanceBasis.CLASSIFICATION
    assert classified.cwe_ids == ("CWE-95",)
    assert classified.rule_id == finding.subject.rule_id
    assert "exact patch" in _serialized(classified)
    assert "exploitability" in _serialized(classified)
    evidence_id = finding.primary_evidence_refs[0]
    evidence[evidence_id] = replace(
        evidence[evidence_id], payload=replace(evidence[evidence_id].payload, cwe_ids=())
    )
    family = renderer.render(report.scope.source_run_id, finding, evidence)
    assert family.basis_level is GuidanceBasis.FAMILY
    assert family.cwe_ids == ()
    assert _serialized(classified) == _serialized(
        renderer.render(
            report.scope.source_run_id,
            finding,
            {item.evidence_id: item for item in report.evidence},
        )
    )


def test_gitleaks_family_never_reconstructs_secret_or_claims_revocation() -> None:
    report, finding, evidence = _finding_and_evidence(EvidenceAuthority.GITLEAKS)
    guidance = GitleaksGuidanceRenderer().render(report.scope.source_run_id, finding, evidence)
    body = _serialized(guidance)
    assert guidance.basis_level is GuidanceBasis.FAMILY
    assert guidance.detection_kind == "CONTENT"
    assert "Rotate or revoke" in body
    assert "does not prove external credential revocation" in body
    assert "SECRET_SENTINEL_4d8b38f1" not in body
    assert "REDACTED" not in body
    assert "credential is active" in body  # limitation, never an affirmative claim


def test_osv_uses_accepted_advisory_package_alias_and_fixed_event_only() -> None:
    report, finding, evidence = _finding_and_evidence(EvidenceAuthority.OSV)
    renderer = OsvGuidanceRenderer()
    guidance = renderer.render(report.scope.source_run_id, finding, evidence, report)
    assert guidance.basis_level is GuidanceBasis.EXACT_EVIDENCE
    assert guidance.package_name == "requests"
    assert guidance.observed_version == "2.31.0"
    assert guidance.advisory_id
    assert "CVE-2025-12345" in guidance.advisory_aliases
    assert guidance.reported_fixed_event_versions == ("2.32.0",)
    assert "not guaranteed upgrade targets" in _serialized(guidance)
    assert "reachability" in _serialized(guidance)
    group_id = next(
        ref
        for ref in finding.primary_evidence_refs
        if hasattr(evidence[ref].payload, "fixed_versions")
    )
    evidence[group_id] = replace(
        evidence[group_id], payload=replace(evidence[group_id].payload, fixed_versions=())
    )
    no_fixed = renderer.render(report.scope.source_run_id, finding, evidence, report)
    assert no_fixed.reported_fixed_event_versions == ()
    assert "No exact fixed version is available" in _serialized(no_fixed)


def test_checkov_exact_check_is_iac_only_and_treats_hostile_name_as_data() -> None:
    report, finding, evidence = _finding_and_evidence(EvidenceAuthority.CHECKOV)
    renderer = CheckovGuidanceRenderer()
    guidance = renderer.render(report.scope.source_run_id, finding, evidence)
    assert guidance.basis_level is GuidanceBasis.EXACT_EVIDENCE
    assert guidance.check_id
    assert guidance.check_name
    assert guidance.resource
    assert guidance.framework
    assert guidance.locations
    assert "live cloud state" in _serialized(guidance)
    evidence_id = finding.primary_evidence_refs[0]
    hostile = "<script>alert(1)</script>"
    evidence[evidence_id] = replace(
        evidence[evidence_id], payload=replace(evidence[evidence_id].payload, check_name=hostile)
    )
    structured = renderer.render(report.scope.source_run_id, finding, evidence)
    assert structured.check_name == hostile
    assert hostile not in structured.title + structured.summary
    assert hostile not in " ".join(structured.remediation_steps)


def test_missing_optional_or_wrong_authority_evidence_downgrades_safely() -> None:
    report, finding, evidence = _finding_and_evidence(EvidenceAuthority.SEMGREP)
    fallback = SemgrepGuidanceRenderer().render(report.scope.source_run_id, finding, {})
    assert fallback.basis_level is GuidanceBasis.EVIDENCE_ONLY
    assert fallback.evidence_refs == finding.primary_evidence_refs
    assert "new valid scan" in _serialized(fallback)
    assert _serialized(fallback) == _serialized(
        EvidenceOnlyGuidanceRenderer().render(report.scope.source_run_id, finding)
    )
    other = next(item for item in report.evidence if item.authority is EvidenceAuthority.CHECKOV)
    evidence[finding.primary_evidence_refs[0]] = other
    assert (
        SemgrepGuidanceRenderer().render(report.scope.source_run_id, finding, evidence).basis_level
        is GuidanceBasis.EVIDENCE_ONLY
    )


def _database_snapshot(environment) -> tuple[tuple[str, tuple[str, ...]], ...]:
    with environment.factory() as session:
        return tuple(
            (
                table.name,
                tuple(
                    sorted(
                        repr(tuple(row))
                        for row in session.execute(text(f'SELECT * FROM "{table.name}"'))
                    )
                ),
            )
            for table in Base.metadata.sorted_tables
        )


def test_service_is_exact_run_scoped_verified_and_read_only(indexed_context) -> None:  # noqa: F811
    environment, index, lineage = indexed_context
    index.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    index.index_attached_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    report = index.load_verified_published_report(run_id=str(_RUN_ID))
    finding = report.findings[0]
    service = FindingGuidanceService(environment.factory, environment.store)
    before = _database_snapshot(environment)
    first = service.get_for_run(
        project_id=lineage.project_id,
        lineage_id=lineage.lineage_id,
        run_id=str(_RUN_ID),
        finding_id=finding.finding_id,
    )
    second = FindingGuidanceService(environment.factory, environment.store).get_for_run(
        project_id=lineage.project_id,
        lineage_id=lineage.lineage_id,
        run_id=str(_RUN_ID),
        finding_id=finding.finding_id,
    )
    assert first.run_id == str(_RUN_ID)
    assert first.basis_level is GuidanceBasis.FAMILY
    assert _serialized(first) == _serialized(second)
    assert _database_snapshot(environment) == before
    for scope in (
        {"project_id": "99999999-9999-4999-8999-999999999999"},
        {"lineage_id": "99999999-9999-4999-8999-999999999999"},
        {"run_id": "99999999-9999-4999-8999-999999999999"},
        {"finding_id": "9" * 64},
    ):
        target = dict(
            project_id=lineage.project_id,
            lineage_id=lineage.lineage_id,
            run_id=str(_RUN_ID),
            finding_id=finding.finding_id,
        )
        target.update(scope)
        with pytest.raises(FindingGuidanceNotFoundError):
            service.get_for_run(**target)
    assert _database_snapshot(environment) == before


def test_service_rejects_unverified_published_report(indexed_context) -> None:  # noqa: F811
    environment, index, lineage = indexed_context
    index.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    index.index_attached_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    finding = index.load_verified_published_report(run_id=str(_RUN_ID)).findings[0]
    service = FindingGuidanceService(environment.factory, environment.store)
    from securescan.persistence.database import AnalysisRunRow

    with environment.factory.begin() as session:
        row = session.get(AnalysisRunRow, str(_RUN_ID))
        assert row is not None
        row.report_json = {"tampered": True}
    with pytest.raises(FindingGuidanceUnavailableError):
        service.get_for_run(
            project_id=lineage.project_id,
            lineage_id=lineage.lineage_id,
            run_id=str(_RUN_ID),
            finding_id=finding.finding_id,
        )


def test_read_only_api_route_and_scoped_error() -> None:
    report, finding, evidence = _finding_and_evidence(EvidenceAuthority.GITLEAKS)
    guidance = GitleaksGuidanceRenderer().render(report.scope.source_run_id, finding, evidence)
    service = SimpleNamespace(get_for_run=lambda **_kwargs: guidance)
    project = UUID("77777777-7777-4777-8777-777777777771")
    lineage = UUID("77777777-7777-4777-8777-777777777772")
    run = UUID(report.scope.source_run_id)
    response = get_finding_guidance(project, lineage, run, finding.finding_id, service)
    assert response.run_id == report.scope.source_run_id
    assert response.finding_id == finding.finding_id
    assert response.basis_level is GuidanceBasis.FAMILY
    paths = {route.path: route.methods for route in router.routes}
    route = (
        "/v1/projects/{project_id}/lineages/{lineage_id}/runs/{run_id}"
        "/findings/{finding_id}/guidance"
    )
    assert paths[route] == {"GET"}
    failing = SimpleNamespace(
        get_for_run=lambda **_kwargs: (_ for _ in ()).throw(FindingGuidanceNotFoundError())
    )
    with pytest.raises(HTTPException) as error:
        get_finding_guidance(project, lineage, run, finding.finding_id, failing)
    assert error.value.status_code == 404
    assert error.value.detail["code"] == "GUIDANCE_NOT_FOUND"

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from sqlalchemy.orm import sessionmaker
from test_unified_evidence_models import _report

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.evidence.models import EvidenceAuthority, OsvAdvisoryGroupEvidencePayload
from securescan.persistence.database import (
    SourceFindingOccurrenceRow,
    SourceLineageRunRow,
    SourceTargetLineageRow,
)
from securescan.product_core.guidance import (
    FindingGuidanceService,
    GuidanceBasis,
    OsvGuidanceRenderer,
)


def test_same_finding_id_uses_requested_run_evidence(tmp_path, monkeypatch) -> None:
    report = _report()
    finding = next(item for item in report.findings if item.authority is EvidenceAuthority.SEMGREP)
    second_run = "00000000-0000-4000-8000-00000000a499"
    later = replace(
        report,
        scope=replace(report.scope, source_run_id=second_run),
        evidence=tuple(
            replace(item, payload=replace(item.payload, cwe_ids=()))
            if item.authority is EvidenceAuthority.SEMGREP
            else item
            for item in report.evidence
        ),
    )
    reports = {report.scope.source_run_id: report, second_run: later}
    project_id = "77777777-7777-4777-8777-777777777771"
    lineage_id = "77777777-7777-4777-8777-777777777772"

    class ScopeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, row_type, key):
            if row_type is SourceTargetLineageRow:
                return SimpleNamespace(project_id=project_id)
            if row_type is SourceLineageRunRow:
                assert key in reports
                return SimpleNamespace(
                    lineage_id=lineage_id,
                    indexing_state="INDEXED",
                    indexed_at=object(),
                    report_artifact_sha256="a" * 64,
                )
            if row_type is SourceFindingOccurrenceRow:
                assert key[0] in reports and key[1] == finding.finding_id
                return SimpleNamespace(
                    lineage_id=lineage_id,
                    report_artifact_sha256="a" * 64,
                    authority=EvidenceAuthority.SEMGREP.value,
                )
            raise AssertionError(row_type)

    service = FindingGuidanceService(sessionmaker(), ContentAddressedArtifactStore(tmp_path))
    monkeypatch.setattr(service, "_sessions", ScopeSession)
    monkeypatch.setattr(
        service._index, "load_verified_published_report", lambda *, run_id: reports[run_id]
    )

    def get(run_id: str):
        return service.get_for_run(
            project_id=project_id,
            lineage_id=lineage_id,
            run_id=run_id,
            finding_id=finding.finding_id,
        )

    first = get(report.scope.source_run_id)
    second = get(second_run)
    assert first.finding_id == second.finding_id
    assert first.basis_level is GuidanceBasis.CLASSIFICATION
    assert second.basis_level is GuidanceBasis.FAMILY
    assert first.run_id != second.run_id


def test_osv_multiple_accepted_aliases_are_not_collapsed() -> None:
    report = _report()
    finding = next(item for item in report.findings if item.authority is EvidenceAuthority.OSV)
    evidence = {item.evidence_id: item for item in report.evidence}
    group_ref = next(
        ref
        for ref in finding.primary_evidence_refs
        if isinstance(evidence[ref].payload, OsvAdvisoryGroupEvidencePayload)
    )
    original = evidence[group_ref]
    aliases = tuple(sorted((*original.payload.aliases, "CVE-2024-9999")))
    evidence[group_ref] = replace(original, payload=replace(original.payload, aliases=aliases))
    guidance = OsvGuidanceRenderer().render(report.scope.source_run_id, finding, evidence, report)
    assert guidance.advisory_aliases == aliases
    assert guidance.advisory_id == original.payload.canonical_advisory_id

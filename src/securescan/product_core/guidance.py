"""Deterministic, run-scoped advice derived only from verified S4 evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.evidence.models import (
    CheckovEvidencePayload,
    ComponentKind,
    EvidenceAuthority,
    GitleaksEvidencePayload,
    OsvAdvisoryGroupEvidencePayload,
    PackageComponentPayload,
    SecureScanEvidence,
    SecureScanEvidenceReport,
    SecureScanFinding,
    SemgrepEvidencePayload,
)
from securescan.persistence.database import (
    SourceFindingOccurrenceRow,
    SourceLineageRunRow,
    SourceTargetLineageRow,
)

from .finding_index import ProductCoreIndexError, SourceFindingIndexService

_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class GuidanceBasis(StrEnum):
    EXACT_EVIDENCE = "EXACT_EVIDENCE"
    CLASSIFICATION = "CLASSIFICATION"
    FAMILY = "FAMILY"
    EVIDENCE_ONLY = "EVIDENCE_ONLY"


class FindingGuidanceError(RuntimeError):
    pass


class FindingGuidanceNotFoundError(FindingGuidanceError):
    pass


class FindingGuidanceValidationError(FindingGuidanceError):
    pass


class FindingGuidanceUnavailableError(FindingGuidanceError):
    pass


@dataclass(frozen=True, slots=True)
class FindingGuidance:
    run_id: str
    finding_id: str
    authority: str
    basis_level: GuidanceBasis
    title: str
    summary: str
    remediation_steps: tuple[str, ...]
    verification_steps: tuple[str, ...]
    limitations: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    locations: tuple[dict[str, Any], ...]
    rule_id: str | None = None
    cwe_ids: tuple[str, ...] = ()
    detection_kind: str | None = None
    advisory_id: str | None = None
    advisory_aliases: tuple[str, ...] = ()
    package_name: str | None = None
    observed_version: str | None = None
    reported_fixed_event_versions: tuple[str, ...] = ()
    check_id: str | None = None
    check_name: str | None = None
    framework: str | None = None
    resource: str | None = None


def _guidance(
    run_id: str,
    finding: SecureScanFinding,
    basis_level: GuidanceBasis,
    title: str,
    summary: str,
    remediation_steps: tuple[str, ...],
    verification_steps: tuple[str, ...],
    limitations: tuple[str, ...],
    **structured: Any,
) -> FindingGuidance:
    authority = finding.authority
    return FindingGuidance(
        run_id=run_id,
        finding_id=finding.finding_id,
        authority=authority.value if isinstance(authority, EvidenceAuthority) else str(authority),
        basis_level=basis_level,
        title=title,
        summary=summary,
        remediation_steps=remediation_steps,
        verification_steps=verification_steps,
        limitations=limitations,
        evidence_refs=tuple(
            sorted((*finding.primary_evidence_refs, *finding.supporting_evidence_refs))
        ),
        locations=tuple(location.canonical_data() for location in finding.locations),
        **structured,
    )


def _single_primary(
    finding: SecureScanFinding,
    evidence: dict[str, SecureScanEvidence],
    authority: EvidenceAuthority,
    payload_type: type,
) -> Any | None:
    if len(finding.primary_evidence_refs) != 1:
        return None
    item = evidence.get(finding.primary_evidence_refs[0])
    if (
        item is None
        or item.authority is not authority
        or not isinstance(item.payload, payload_type)
    ):
        return None
    return item.payload


class EvidenceOnlyGuidanceRenderer:
    def render(self, run_id: str, finding: SecureScanFinding) -> FindingGuidance:
        return _guidance(
            run_id,
            finding,
            GuidanceBasis.EVIDENCE_ONLY,
            "Review accepted finding evidence",
            "Accepted evidence is insufficient for a specific remediation claim.",
            ("Review the referenced evidence and remediate the underlying condition.",),
            ("Run a new valid scan with the same authority and comparable coverage.",),
            ("No exact fix or remediation success is established by this guidance.",),
        )


class SemgrepGuidanceRenderer:
    def render(
        self, run_id: str, finding: SecureScanFinding, evidence: dict[str, SecureScanEvidence]
    ) -> FindingGuidance:
        payload = _single_primary(
            finding, evidence, EvidenceAuthority.SEMGREP, SemgrepEvidencePayload
        )
        if payload is None:
            return EvidenceOnlyGuidanceRenderer().render(run_id, finding)
        return _guidance(
            run_id,
            finding,
            GuidanceBasis.CLASSIFICATION if payload.cwe_ids else GuidanceBasis.FAMILY,
            "Semgrep source-code finding",
            "The accepted Semgrep evidence records a rule match at this source location.",
            (
                "Review the matched operation and its input or trust boundary.",
                "Choose an appropriate safe implementation after reviewing the rule and code.",
            ),
            ("Rerun the same Semgrep rule with comparable source coverage after the change.",),
            (
                "A rule match does not prove exploitability, reachability, or business impact.",
                "Accepted evidence does not provide an exact patch.",
            ),
            rule_id=payload.rule_id,
            cwe_ids=payload.cwe_ids,
        )


class GitleaksGuidanceRenderer:
    def render(
        self, run_id: str, finding: SecureScanFinding, evidence: dict[str, SecureScanEvidence]
    ) -> FindingGuidance:
        payload = _single_primary(
            finding, evidence, EvidenceAuthority.GITLEAKS, GitleaksEvidencePayload
        )
        if payload is None:
            return EvidenceOnlyGuidanceRenderer().render(run_id, finding)
        return _guidance(
            run_id,
            finding,
            GuidanceBasis.FAMILY,
            "Possible secret exposure in source",
            "The accepted Gitleaks evidence records a secret-detection rule observation.",
            (
                "Review and remove exposed material from source and history where applicable.",
                "Rotate or revoke a potentially exposed credential through its owning system.",
                "Use an approved secret-management mechanism instead of source storage.",
            ),
            ("Rerun Gitleaks on the changed source with comparable coverage.",),
            (
                "The evidence does not establish that a credential is active or was revoked.",
                "Absence in a new source scan does not prove external credential revocation.",
            ),
            rule_id=payload.rule_id,
            detection_kind=payload.detection_kind,
        )


class OsvGuidanceRenderer:
    def render(
        self,
        run_id: str,
        finding: SecureScanFinding,
        evidence: dict[str, SecureScanEvidence],
        report: SecureScanEvidenceReport,
    ) -> FindingGuidance:
        groups = [
            evidence.get(ref)
            for ref in finding.primary_evidence_refs
            if evidence.get(ref) is not None
            and isinstance(evidence[ref].payload, OsvAdvisoryGroupEvidencePayload)
        ]
        if len(groups) != 1 or groups[0].authority is not EvidenceAuthority.OSV:
            return EvidenceOnlyGuidanceRenderer().render(run_id, finding)
        group = groups[0].payload
        components = {item.component_ref: item for item in report.components}
        component = components.get(finding.subject.component_ref)
        if (
            component is None
            or component.component_kind is not ComponentKind.PACKAGE
            or not isinstance(component.payload, PackageComponentPayload)
            or component.component_ref not in groups[0].component_refs
            or component.payload.package_version is None
        ):
            return EvidenceOnlyGuidanceRenderer().render(run_id, finding)
        return _guidance(
            run_id,
            finding,
            GuidanceBasis.EXACT_EVIDENCE,
            "Accepted dependency advisory match",
            "The accepted run evidence matches an observed package version "
            "to an OSV advisory group.",
            (
                "Review the accepted advisory and select a nonaffected version "
                "supported by the application.",
                "Regenerate dependency or lockfile state and validate application compatibility.",
            ),
            (
                "Rerun dependency inventory and advisory matching on the changed build.",
                "Confirm the resulting component version against accepted advisory evidence.",
            ),
            (
                "Reported fixed-event versions are advisory evidence, "
                "not guaranteed upgrade targets.",
                "Full affected ranges, reachability, and application "
                "compatibility are not established here.",
            )
            if group.fixed_versions
            else (
                "No exact fixed version is available from the accepted evidence.",
                "Full affected ranges, reachability, and application "
                "compatibility are not established here.",
            ),
            advisory_id=group.canonical_advisory_id,
            advisory_aliases=group.aliases,
            package_name=component.payload.package_name,
            observed_version=component.payload.package_version,
            reported_fixed_event_versions=group.fixed_versions,
        )


class CheckovGuidanceRenderer:
    def render(
        self, run_id: str, finding: SecureScanFinding, evidence: dict[str, SecureScanEvidence]
    ) -> FindingGuidance:
        payload = _single_primary(
            finding, evidence, EvidenceAuthority.CHECKOV, CheckovEvidencePayload
        )
        if payload is None:
            return EvidenceOnlyGuidanceRenderer().render(run_id, finding)
        return _guidance(
            run_id,
            finding,
            GuidanceBasis.EXACT_EVIDENCE,
            "Failed source configuration check",
            "The accepted Checkov evidence records a failed IaC/configuration check.",
            (
                "Review the exact check requirement and update the source configuration control.",
                "Apply the change through the normal infrastructure workflow.",
            ),
            (
                "Rerun Checkov on the changed source with comparable coverage.",
                "Separately validate the deployed environment if operationally required.",
            ),
            ("Source-level evidence does not establish live cloud state or deployed remediation.",),
            check_id=payload.check_id,
            check_name=payload.check_name,
            framework=payload.framework,
            resource=payload.resource,
        )


class FindingGuidanceService:
    """Read-only exact-run guidance; Product Core rows establish scope, not advice."""

    def __init__(
        self, session_factory: sessionmaker[Session], artifact_store: ContentAddressedArtifactStore
    ) -> None:
        self._sessions = session_factory
        self._index = SourceFindingIndexService(session_factory, artifact_store)
        self._renderers = {
            EvidenceAuthority.SEMGREP: SemgrepGuidanceRenderer(),
            EvidenceAuthority.GITLEAKS: GitleaksGuidanceRenderer(),
            EvidenceAuthority.OSV: OsvGuidanceRenderer(),
            EvidenceAuthority.CHECKOV: CheckovGuidanceRenderer(),
        }

    def get_for_run(
        self, *, project_id: str, lineage_id: str, run_id: str, finding_id: str
    ) -> FindingGuidance:
        for value in (project_id, lineage_id, run_id):
            try:
                if str(UUID(value)) != value:
                    raise ValueError
            except (TypeError, ValueError, AttributeError):
                raise FindingGuidanceValidationError from None
        if not isinstance(finding_id, str) or _SHA256.fullmatch(finding_id) is None:
            raise FindingGuidanceValidationError
        try:
            with self._sessions() as session:
                lineage = session.get(SourceTargetLineageRow, lineage_id)
                membership = session.get(SourceLineageRunRow, run_id)
                occurrence = session.get(SourceFindingOccurrenceRow, (run_id, finding_id))
                if (
                    lineage is None
                    or lineage.project_id != project_id
                    or membership is None
                    or membership.lineage_id != lineage_id
                    or membership.indexing_state != "INDEXED"
                    or membership.indexed_at is None
                    or occurrence is None
                    or occurrence.lineage_id != lineage_id
                    or occurrence.report_artifact_sha256 != membership.report_artifact_sha256
                ):
                    raise FindingGuidanceNotFoundError
                expected_authority = occurrence.authority
            report = self._index.load_verified_published_report(run_id=run_id)
        except FindingGuidanceNotFoundError:
            raise
        except (ProductCoreIndexError, SQLAlchemyError, OSError, TypeError, ValueError):
            raise FindingGuidanceUnavailableError from None
        finding = next((item for item in report.findings if item.finding_id == finding_id), None)
        if finding is None or finding.authority.value != expected_authority:
            raise FindingGuidanceUnavailableError
        evidence = {item.evidence_id: item for item in report.evidence}
        renderer = self._renderers.get(finding.authority)
        if renderer is None:
            return EvidenceOnlyGuidanceRenderer().render(run_id, finding)
        if isinstance(renderer, OsvGuidanceRenderer):
            return renderer.render(run_id, finding, evidence, report)
        return renderer.render(run_id, finding, evidence)

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from securescan.advisories.osv.client import OsvCandidateMatch, TrustedOsvClient
from securescan.advisories.osv.models import (
    DependencyVulnerabilityFinding,
    OsvPackageGap,
    OsvQueryCandidate,
    build_osv_query_candidates,
    canonical_json,
    group_advisories,
)
from securescan.scanners.syft import SyftParseResult
from securescan.source.enums import AnalysisCapability, SourceSupportState
from securescan.source.planning import TrustedSourceAnalyzer
from securescan.source.support import CapabilitySupportRule, SourceSupportPolicy

OSV_SOURCE_ANALYZER_ID = "osv-dependency-advisory-v1"
OSV_SCANNABLE_REASON = "OSV_VERSION_SPECIFIC_ADVISORY_SCANNABLE"


@dataclass(frozen=True, slots=True)
class OsvDependencyAnalysis:
    candidates: tuple[OsvQueryCandidate, ...]
    gaps: tuple[OsvPackageGap, ...]
    candidate_matches: tuple[OsvCandidateMatch, ...]
    findings: tuple[DependencyVulnerabilityFinding, ...]
    completed_candidate_ids: tuple[str, ...]
    zero_advisory_candidate_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        candidate_ids = tuple(item.candidate_id for item in self.candidates)
        matched_ids = tuple(item.candidate.candidate_id for item in self.candidate_matches)
        if (
            candidate_ids != tuple(sorted(candidate_ids))
            or matched_ids != candidate_ids
            or self.completed_candidate_ids != candidate_ids
            or self.zero_advisory_candidate_ids
            != tuple(
                item.candidate.candidate_id
                for item in self.candidate_matches
                if not item.references
            )
            or self.findings != tuple(sorted(self.findings, key=lambda item: item.finding_id))
        ):
            raise ValueError("OSV dependency analysis is invalid")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "candidate_count": len(self.candidates),
            "completed_candidate_ids": list(self.completed_candidate_ids),
            "finding_count": len(self.findings),
            "findings": [
                {
                    "affected_match": item.affected_match,
                    "advisory_group_key": item.advisory_group_key,
                    "aliases": list(item.aliases),
                    "api_version": item.api_version,
                    "canonical_advisory_id": item.canonical_advisory_id,
                    "cve_aliases": list(item.cve_aliases),
                    "cvss": [
                        {
                            "base_score": score.base_score,
                            "source": score.source,
                            "scope": score.scope.value,
                            "type": score.cvss_type,
                            "vector": score.vector,
                        }
                        for score in item.cvss
                    ],
                    "finding_id": item.finding_id,
                    "fixed_versions": list(item.fixed_versions),
                    "ghsa_aliases": list(item.ghsa_aliases),
                    "locations": list(item.locations),
                    "modified": [list(value) for value in item.modified],
                    "osv_record_ids": list(item.osv_record_ids),
                    "package_key": item.package_key,
                    "package_name": item.package_name,
                    "package_observation_ids": list(item.package_observation_ids),
                    "package_type": item.package_type,
                    "package_version": item.package_version,
                    "projection_id": item.projection_id,
                    "purl": item.purl,
                    "snapshot_digest": item.snapshot_digest,
                    "source_service": item.source_service,
                    "syft_binding_digest": item.syft_binding_digest,
                }
                for item in self.findings
            ],
            "gap_count": len(self.gaps),
            "gaps": [
                {
                    "locations": list(item.locations),
                    "package_key": item.package_key,
                    "package_observation_ids": list(item.package_observation_ids),
                    "reason_code": item.reason_code.value,
                }
                for item in self.gaps
            ],
            "schema_version": "securescan-osv-dependency-analysis-s2",
            "zero_advisory_candidate_ids": list(self.zero_advisory_candidate_ids),
        }

    def canonical_json(self) -> bytes:
        return canonical_json(self.canonical_data())


def evaluate_syft_packages(
    parse_result: SyftParseResult, client: TrustedOsvClient
) -> OsvDependencyAnalysis:
    if not isinstance(parse_result, SyftParseResult):
        raise TypeError("OSV dependency analysis input is invalid")
    candidates, gaps = build_osv_query_candidates(parse_result.observations)
    candidates = tuple(sorted(candidates, key=lambda item: item.candidate_id))
    matches = client.query(candidates)
    findings = tuple(
        sorted(
            (
                finding
                for match in matches
                for finding in group_advisories(match.candidate, match.advisories)
            ),
            key=lambda item: item.finding_id,
        )
    )
    candidate_ids = tuple(item.candidate_id for item in candidates)
    return OsvDependencyAnalysis(
        candidates=candidates,
        gaps=gaps,
        candidate_matches=matches,
        findings=findings,
        completed_candidate_ids=candidate_ids,
        zero_advisory_candidate_ids=tuple(
            item.candidate.candidate_id for item in matches if not item.references
        ),
    )


def with_osv_source_support(policy: SourceSupportPolicy) -> SourceSupportPolicy:
    expected = CapabilitySupportRule(
        AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
        SourceSupportState.SCANNABLE,
        OSV_SCANNABLE_REASON,
    )
    existing = next(
        (
            item
            for item in policy.capability_rules
            if item.capability is AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING
        ),
        None,
    )
    if existing is not None:
        if existing != expected:
            raise ValueError("OSV Source support policy is invalid")
        return policy
    return replace(
        policy,
        capability_rules=tuple(
            sorted((*policy.capability_rules, expected), key=lambda item: item.capability.value)
        ),
    )


def build_osv_source_analyzer_snapshot(*, available: bool) -> TrustedSourceAnalyzer:
    return TrustedSourceAnalyzer(
        analyzer_id=OSV_SOURCE_ANALYZER_ID,
        capabilities=(AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,),
        available=available,
        unavailable_reason_code=None if available else "OSV_SERVICE_UNAVAILABLE",
    )

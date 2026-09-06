from __future__ import annotations

from dataclasses import replace

import pytest

from securescan.advisories.osv import (
    OsvCandidateMatch,
    build_osv_source_analyzer_snapshot,
    evaluate_syft_packages,
    with_osv_source_support,
)
from securescan.benchmarks.osv_s2 import build_controlled_candidates
from securescan.scanners.syft import (
    SYFT_JSON_SCHEMA_VERSION,
    SYFT_VERSION,
    PackageObservation,
    SyftParseResult,
)
from securescan.source.enums import AnalysisCapability, SourceSupportState
from securescan.source.support import SourceSupportPolicy


class _NoFindingClient:
    def query(self, candidates):
        return tuple(OsvCandidateMatch(candidate, (), ()) for candidate in candidates)


def _parse_result() -> SyftParseResult:
    observations = tuple(
        # Controlled candidates are derived from these exact frozen observations.
        # Reusing their fields avoids inventing a second package identity path.
        PackageObservation(
            scanner_id="syft",
            scanner_version=SYFT_VERSION,
            package_name=candidate.package_name,
            package_version=candidate.package_version,
            package_type=candidate.package_type,
            language=None,
            purl=candidate.purl,
            found_by="securescan-s2-controlled-plan",
            locations=candidate.locations,
            projection_id=candidate.projection_id,
            snapshot_digest=candidate.snapshot_digest,
            binding_digest=candidate.syft_binding_digest,
            package_key=candidate.package_key,
            package_observation_id=candidate.package_observation_ids[0],
        )
        for candidate in build_controlled_candidates()
    )
    observations = tuple(sorted(observations, key=lambda item: item.package_observation_id))
    return SyftParseResult(
        scanner_id="syft",
        scanner_version=SYFT_VERSION,
        binding_digest=observations[0].binding_digest,
        projection_id=observations[0].projection_id,
        snapshot_digest=observations[0].snapshot_digest,
        syft_schema_version=SYFT_JSON_SCHEMA_VERSION,
        requested_cataloger_strategy=("directory", "file"),
        used_catalogers=("securescan-s2-controlled-plan",),
        observations=observations,
        package_count=len(observations),
    )


def test_successful_zero_advisory_analysis_is_explicit_not_failure() -> None:
    analysis = evaluate_syft_packages(_parse_result(), _NoFindingClient())
    assert len(analysis.completed_candidate_ids) == 6
    assert analysis.zero_advisory_candidate_ids == analysis.completed_candidate_ids
    assert analysis.findings == ()
    assert analysis.gaps == ()


def test_osv_analysis_requires_frozen_syft_parse_result() -> None:
    with pytest.raises(TypeError):
        evaluate_syft_packages((), _NoFindingClient())


def test_source_support_and_availability_are_explicit() -> None:
    policy = with_osv_source_support(SourceSupportPolicy())
    rule = next(
        item
        for item in policy.capability_rules
        if item.capability is AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING
    )
    assert rule.support_state is SourceSupportState.SCANNABLE
    assert rule.reason_code == "OSV_VERSION_SPECIFIC_ADVISORY_SCANNABLE"
    assert build_osv_source_analyzer_snapshot(available=True).available is True
    assert build_osv_source_analyzer_snapshot(available=False).available is False


def test_existing_conflicting_support_cannot_be_weakened() -> None:
    policy = with_osv_source_support(SourceSupportPolicy())
    bad = replace(
        policy,
        capability_rules=(
            replace(
                policy.capability_rules[0], support_state=SourceSupportState.DETECTED
            ),
        ),
    )
    with pytest.raises(ValueError):
        with_osv_source_support(bad)

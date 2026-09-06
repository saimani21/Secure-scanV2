from __future__ import annotations

from dataclasses import replace

from securescan.advisories.osv import (
    OsvAdvisoryObservation,
    OsvCvssEvidence,
    OsvCvssScope,
    OsvGapReason,
    build_osv_query_candidates,
    group_advisories,
)
from securescan.scanners.syft import PackageObservation

PROJECTION = "securescan-source-projection-" + "12" * 16
SNAPSHOT = "12" * 32
BINDING = "34" * 32


def _observation(
    *,
    name: str = "requests",
    package_version: str | None = "2.19.1",
    package_type: str = "python",
    purl: str | None = "pkg:pypi/requests@2.19.1",
    location: str = "requirements.txt",
    cataloger: str = "python-package-cataloger",
) -> PackageObservation:
    return PackageObservation.create(
        package_name=name,
        package_version=package_version,
        package_type=package_type,
        language="python",
        purl=purl,
        found_by=cataloger,
        locations=(location,),
        projection_id=PROJECTION,
        snapshot_digest=SNAPSHOT,
        binding_digest=BINDING,
    )


def test_query_candidates_group_same_package_key_and_retain_provenance() -> None:
    first = _observation(location="a/requirements.txt")
    second = _observation(location="b/requirements.txt")
    candidates, gaps = build_osv_query_candidates((second, first))
    assert not gaps
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.package_observation_ids == tuple(
        sorted((first.package_observation_id, second.package_observation_id))
    )
    assert candidate.locations == ("a/requirements.txt", "b/requirements.txt")
    assert candidate.query_data() == {"package": {"purl": "pkg:pypi/requests@2.19.1"}}
    assert "version" not in candidate.query_data()


def test_supported_mapping_requires_syft_package_type_and_purl_type_pair() -> None:
    observation = _observation(package_type="npm", purl="pkg:pypi/requests@2.19.1")
    candidates, gaps = build_osv_query_candidates((observation,))
    assert candidates == ()
    assert gaps[0].reason_code is OsvGapReason.UNSUPPORTED_PURL_TYPE


def test_unqueryable_package_reasons_are_distinct() -> None:
    cases = (
        (
            _observation(package_version=None, purl="pkg:pypi/requests"),
            OsvGapReason.PACKAGE_VERSION_UNRESOLVED,
        ),
        (_observation(purl=None), OsvGapReason.PACKAGE_PURL_UNRESOLVED),
        (
            _observation(package_type="rust", purl="pkg:cargo/requests@2.19.1"),
            OsvGapReason.UNSUPPORTED_PURL_TYPE,
        ),
        (
            _observation(purl="pkg:pypi/requests@2.20.0"),
            OsvGapReason.PURL_VERSION_MISMATCH,
        ),
        (
            _observation(purl="pkg:pypi/flask@2.19.1"),
            OsvGapReason.PURL_PACKAGE_MISMATCH,
        ),
    )
    for observation, expected in cases:
        candidates, gaps = build_osv_query_candidates((observation,))
        assert not candidates
        assert gaps[0].reason_code is expected
        assert gaps[0].package_key == observation.package_key


def test_pypi_package_name_normalization_is_narrow_and_canonical() -> None:
    candidates, gaps = build_osv_query_candidates(
        (
            _observation(
                name="Requests_Package",
                purl="pkg:pypi/requests-package@2.19.1",
            ),
        )
    )
    assert len(candidates) == 1
    assert gaps == ()


def _advisory(
    record_id: str, aliases: tuple[str, ...], package_key: str
) -> OsvAdvisoryObservation:
    identities = (record_id, *aliases)
    return OsvAdvisoryObservation(
        osv_record_id=record_id,
        modified="2026-08-06T00:00:00Z",
        published=None,
        aliases=aliases,
        cve_aliases=tuple(value for value in identities if value.startswith("CVE-")),
        ghsa_aliases=tuple(value for value in identities if value.startswith("GHSA-")),
        summary=None,
        applicable_package_key=package_key,
        fixed_versions=(),
        cvss=(),
    )


def test_alias_grouping_is_transitive_and_input_order_independent() -> None:
    (candidate,), _ = build_osv_query_candidates((_observation(),))
    values = (
        _advisory("GHSA-2345-6789-cfgh", ("CVE-2024-10001",), candidate.package_key),
        _advisory("PYSEC-2024-1", ("GHSA-2345-6789-cfgh",), candidate.package_key),
        _advisory("GO-2024-1000", (), candidate.package_key),
    )
    first = group_advisories(candidate, values)
    second = group_advisories(candidate, tuple(reversed(values)))
    assert first == second
    assert len(first) == 2
    grouped = next(item for item in first if "PYSEC-2024-1" in item.osv_record_ids)
    assert grouped.canonical_advisory_id == "CVE-2024-10001"
    assert grouped.cve_aliases == ("CVE-2024-10001",)
    assert grouped.finding_id == grouped.finding_id


def test_evidence_location_does_not_change_finding_identity() -> None:
    first_observation = _observation(location="requirements.txt")
    second_observation = _observation(location="nested/requirements.txt")
    (first_candidate,), _ = build_osv_query_candidates((first_observation,))
    (second_candidate,), _ = build_osv_query_candidates((second_observation,))
    first = _advisory("PYSEC-2024-1", (), first_candidate.package_key)
    second = _advisory("PYSEC-2024-1", (), second_candidate.package_key)
    assert group_advisories(first_candidate, (first,))[0].finding_id == group_advisories(
        second_candidate, (second,)
    )[0].finding_id


def test_structural_finding_identity_ignores_summary_score_and_modified() -> None:
    (candidate,), _ = build_osv_query_candidates((_observation(),))
    first = _advisory(
        "GHSA-2345-6789-cfgh", ("CVE-2024-10001",), candidate.package_key
    )
    second = replace(first, modified="2026-09-01T00:00:00Z", summary="changed")
    third = replace(
        first,
        cvss=(
            OsvCvssEvidence(
                cvss_type="CVSS_V3",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                source=None,
                base_score=9.8,
                scope=OsvCvssScope.MATCHED_PACKAGE,
            ),
        ),
    )
    finding_ids = {
        group_advisories(candidate, (value,))[0].finding_id
        for value in (first, second, third)
    }
    assert len(finding_ids) == 1

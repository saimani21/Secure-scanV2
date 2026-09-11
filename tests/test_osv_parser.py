from __future__ import annotations

import copy
import json

import pytest

import securescan.advisories.osv.parser as parser_module
from securescan.advisories.osv import (
    OsvAdvisoryReference,
    OsvCvssScope,
    OsvFailureCode,
    OsvIntegrationError,
    build_osv_query_candidates,
    parse_advisory_response,
    parse_query_response,
)
from securescan.advisories.osv.models import osv_advisory_revision_matches
from securescan.benchmarks.osv_s2 import build_controlled_candidates
from securescan.scanners.syft import PackageObservation


def _candidate():
    return next(
        item for item in build_controlled_candidates() if item.purl == "pkg:pypi/pyyaml@5.3.1"
    )


def _document() -> dict:
    return {
        "schema_version": "1.9.0",
        "id": "GHSA-2345-6789-cfgh",
        "modified": "2026-08-06T00:00:00Z",
        "published": "2024-01-01T00:00:00Z",
        "aliases": ["CVE-2024-10001"],
        "upstream": ["GO-2024-9999"],
        "related": ["PYSEC-2024-999"],
        "summary": "bounded summary",
        "severity": [
            {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "source": "NVD",
            },
            {
                "type": "CVSS_V4",
                "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
        ],
        "affected": [
            {
                "package": {
                    "ecosystem": "PyPI",
                    "name": "PyYAML",
                    "purl": "pkg:pypi/pyyaml",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.20.0"},
                            {"limit": "3"},
                        ],
                    }
                ],
            },
            {
                "package": {
                    "ecosystem": "npm",
                    "name": "requests",
                    "purl": "pkg:npm/requests",
                },
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "99.0.0"}],
                    }
                ],
            },
        ],
    }


def _payload(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def test_query_response_preserves_order_zero_and_deduplicates_ids() -> None:
    value = {
        "results": [
            {},
            {
                "vulns": [
                    {"id": "GHSA-2345-6789-cfgh", "modified": "2026-08-06T00:00:00Z"},
                    {"id": "GHSA-2345-6789-cfgh", "modified": "2026-08-06T00:00:00Z"},
                ],
                "next_page_token": "next",
            },
        ]
    }
    parsed = parse_query_response(_payload(value), 2)
    assert parsed[0] == ((), None)
    assert len(parsed[1][0]) == 1
    assert parsed[1][1] == "next"


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        b"{",
        b'{"results":[],"results":[]}',
        b'{"results":[],"x":NaN}',
        b'{"results":{}}',
        b'{"results":[]}',
    ],
)
def test_invalid_query_shapes_fail_closed(payload: bytes) -> None:
    with pytest.raises(OsvIntegrationError) as caught:
        parse_query_response(payload, 1)
    assert caught.value.code in {
        OsvFailureCode.QUERY_RESPONSE_INVALID,
        OsvFailureCode.RESPONSE_LIMIT,
    }


def test_advisory_schema_alias_fix_and_cvss_normalization() -> None:
    expected = OsvAdvisoryReference("GHSA-2345-6789-cfgh", "2026-08-06T00:00:00Z")
    result = parse_advisory_response(
        _payload(_document()), expected=expected, candidate=_candidate()
    )
    assert result.cve_aliases == ("CVE-2024-10001",)
    assert result.fixed_versions == ("2.20.0",)
    assert tuple(value.cvss_type for value in result.cvss) == (
        "CVSS_V2",
        "CVSS_V3",
        "CVSS_V4",
    )
    assert tuple(value.base_score for value in result.cvss) == (7.5, 9.8, 9.3)
    assert {value.scope for value in result.cvss} == {OsvCvssScope.ADVISORY}
    assert "GO-2024-9999" not in result.aliases
    assert "PYSEC-2024-999" not in result.aliases
    assert "3" not in result.fixed_versions
    assert "99.0.0" not in result.fixed_versions


@pytest.mark.parametrize(
    ("reference_modified", "observed_modified"),
    [
        ("2026-09-10T03:50:25.139398Z", "2026-09-10T03:50:25.139398Z"),
        ("2026-09-10T03:50:25.139398Z", "2026-09-10T03:50:25.139398550Z"),
    ],
)
def test_advisory_revision_accepts_directional_precision_extension(
    reference_modified: str, observed_modified: str
) -> None:
    document = _document()
    document["modified"] = observed_modified
    expected = OsvAdvisoryReference(document["id"], reference_modified)
    result = parse_advisory_response(
        _payload(document), expected=expected, candidate=_candidate()
    )
    assert result.modified == observed_modified


@pytest.mark.parametrize(
    ("reference_modified", "observed_modified"),
    [
        ("2026-09-10T03:50:25.139398Z", "2026-09-10T03:50:25.139399000Z"),
        ("2026-09-10T03:50:25.139398550Z", "2026-09-10T03:50:25.139398Z"),
    ],
)
def test_advisory_revision_rejects_change_or_precision_loss(
    reference_modified: str, observed_modified: str
) -> None:
    document = _document()
    document["modified"] = observed_modified
    expected = OsvAdvisoryReference(document["id"], reference_modified)
    with pytest.raises(OsvIntegrationError) as caught:
        parse_advisory_response(
            _payload(document), expected=expected, candidate=_candidate()
        )
    assert caught.value.code is OsvFailureCode.DATA_CHANGED_DURING_QUERY


def test_advisory_revision_matcher_rejects_malformed_values() -> None:
    valid = "2026-09-10T03:50:25.139398Z"
    assert not osv_advisory_revision_matches("not-a-timestamp", valid)
    assert not osv_advisory_revision_matches(valid, None)


@pytest.mark.parametrize("field", ["id", "modified"])
def test_advisory_identity_or_modified_mismatch_is_data_change(field: str) -> None:
    document = _document()
    document[field] = "PYSEC-2024-1" if field == "id" else "2026-08-07T00:00:00Z"
    expected = OsvAdvisoryReference("GHSA-2345-6789-cfgh", "2026-08-06T00:00:00Z")
    with pytest.raises(OsvIntegrationError) as caught:
        parse_advisory_response(_payload(document), expected=expected, candidate=_candidate())
    assert caught.value.code is OsvFailureCode.DATA_CHANGED_DURING_QUERY


def test_withdrawn_after_query_is_data_change() -> None:
    document = _document()
    document["withdrawn"] = "2026-08-07T00:00:00Z"
    expected = OsvAdvisoryReference("GHSA-2345-6789-cfgh", "2026-08-06T00:00:00Z")
    with pytest.raises(OsvIntegrationError) as caught:
        parse_advisory_response(_payload(document), expected=expected, candidate=_candidate())
    assert caught.value.code is OsvFailureCode.DATA_CHANGED_DURING_QUERY


def test_malformed_schema_and_invalid_cvss_fail_closed() -> None:
    expected = OsvAdvisoryReference("GHSA-2345-6789-cfgh", "2026-08-06T00:00:00Z")
    for mutation in ("missing", "cvss"):
        document = copy.deepcopy(_document())
        if mutation == "missing":
            document.pop("id")
        else:
            document["severity"][1]["score"] = "CVSS:3.1/not-valid"
        with pytest.raises(OsvIntegrationError) as caught:
            parse_advisory_response(_payload(document), expected=expected, candidate=_candidate())
        assert caught.value.code is OsvFailureCode.ADVISORY_SCHEMA_INVALID


def test_arbitrary_metadata_and_details_are_not_persisted() -> None:
    document = _document()
    document["details"] = "large markdown"
    document["database_specific"] = {"secret": "ignored"}
    document["affected"][0]["ecosystem_specific"] = {"functions": ["ignored"]}
    expected = OsvAdvisoryReference("GHSA-2345-6789-cfgh", "2026-08-06T00:00:00Z")
    result = parse_advisory_response(_payload(document), expected=expected, candidate=_candidate())
    assert not hasattr(result, "details")
    assert not hasattr(result, "database_specific")
    assert not hasattr(result, "raw_response")


def test_missing_and_unknown_severity_do_not_manufacture_cvss() -> None:
    expected = OsvAdvisoryReference("GHSA-2345-6789-cfgh", "2026-08-06T00:00:00Z")
    for severity in (None, [{"type": "Ubuntu", "score": "medium"}]):
        document = _document()
        if severity is None:
            document.pop("severity")
        else:
            document["severity"] = severity
        result = parse_advisory_response(
            _payload(document), expected=expected, candidate=_candidate()
        )
        assert result.cvss == ()


def test_oversized_query_response_fails_with_response_limit() -> None:
    payload = b'{"results":[]}' + b" " * (8 * 1024 * 1024)
    with pytest.raises(OsvIntegrationError) as caught:
        parse_query_response(payload, 0)
    assert caught.value.code is OsvFailureCode.RESPONSE_LIMIT


def test_affected_package_without_purl_uses_exact_ecosystem_name_fallback() -> None:
    document = _document()
    document.pop("severity")
    package = document["affected"][0]["package"]
    package.pop("purl")
    package["name"] = "pYYaml"
    document["affected"][0]["severity"] = [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    ]
    expected = OsvAdvisoryReference("GHSA-2345-6789-cfgh", "2026-08-06T00:00:00Z")
    result = parse_advisory_response(
        _payload(document), expected=expected, candidate=_candidate()
    )
    assert result.fixed_versions == ("2.20.0",)
    assert {value.scope for value in result.cvss} == {OsvCvssScope.MATCHED_PACKAGE}


def test_unrelated_no_purl_affected_entry_cannot_supply_fix_or_cvss() -> None:
    document = _document()
    document.pop("severity")
    package = document["affected"][0]["package"]
    package.pop("purl")
    package["name"] = "not-pyyaml"
    document["affected"][0]["severity"] = [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    ]
    expected = OsvAdvisoryReference("GHSA-2345-6789-cfgh", "2026-08-06T00:00:00Z")
    result = parse_advisory_response(
        _payload(document), expected=expected, candidate=_candidate()
    )
    assert result.fixed_versions == ()
    assert result.cvss == ()


def _candidate_for(*, name: str, version: str, package_type: str, purl: str):
    observation = PackageObservation.create(
        package_name=name,
        package_version=version,
        package_type=package_type,
        language=None,
        purl=purl,
        found_by="hostile-test",
        locations=("package.lock",),
        projection_id="securescan-source-projection-" + "12" * 16,
        snapshot_digest="12" * 32,
        binding_digest="34" * 32,
    )
    (candidate,), gaps = build_osv_query_candidates((observation,))
    assert gaps == ()
    return candidate


@pytest.mark.parametrize(
    ("candidate", "package", "expected"),
    [
        (
            _candidate_for(
                name="@scope/name",
                version="1.0.0",
                package_type="npm",
                purl="pkg:npm/%40scope/name@1.0.0",
            ),
            {"ecosystem": "npm", "name": "@scope/name"},
            True,
        ),
        (
            _candidate_for(
                name="example.com/mod",
                version="v1.0.0",
                package_type="go-module",
                purl="pkg:golang/example.com/mod@v1.0.0",
            ),
            {"ecosystem": "Go", "name": "example.com/mod"},
            True,
        ),
        (
            _candidate_for(
                name="example.com/mod",
                version="v1.0.0",
                package_type="go-module",
                purl="pkg:golang/example.com/mod@v1.0.0",
            ),
            {"ecosystem": "go", "name": "example.com/mod"},
            False,
        ),
    ],
)
def test_no_purl_fallback_is_ecosystem_specific(candidate, package, expected) -> None:
    assert parser_module._affected_package_matches(package, candidate) is expected


def test_malformed_affected_purl_fails_closed() -> None:
    document = _document()
    document["affected"][0]["package"]["purl"] = "not-a-purl"
    expected = OsvAdvisoryReference("GHSA-2345-6789-cfgh", "2026-08-06T00:00:00Z")
    with pytest.raises(OsvIntegrationError) as caught:
        parse_advisory_response(
            _payload(document), expected=expected, candidate=_candidate()
        )
    assert caught.value.code is OsvFailureCode.ADVISORY_SCHEMA_INVALID


def test_git_fixed_commit_never_becomes_fixed_version() -> None:
    document = _document()
    document["affected"][0]["ranges"].extend(
        [
            {
                "type": "GIT",
                "repo": "https://example.invalid/repository",
                "events": [
                    {"introduced": "0" * 40},
                    {"fixed": "8f96da9f5d5eff988554c1aae1784627c4bf6754"},
                ],
            },
            {
                "type": "SEMVER",
                "events": [{"introduced": "0"}, {"fixed": "2.21.0"}],
            },
        ]
    )
    expected = OsvAdvisoryReference("GHSA-2345-6789-cfgh", "2026-08-06T00:00:00Z")
    result = parse_advisory_response(
        _payload(document), expected=expected, candidate=_candidate()
    )
    assert result.fixed_versions == ("2.20.0", "2.21.0")
    assert "8f96da9f5d5eff988554c1aae1784627c4bf6754" not in result.fixed_versions


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-08-06 00:00:00Z",
        "2026-08-06T00:00Z",
        "2026-08-06T00:00:00+00:00",
        "2026-08-06T00:00:00.Z",
        "2026-13-06T00:00:00Z",
    ],
)
def test_query_modified_requires_strict_rfc3339_utc(timestamp: str) -> None:
    payload = _payload(
        {"results": [{"vulns": [{"id": "PYSEC-2024-1", "modified": timestamp}]}]}
    )
    with pytest.raises(OsvIntegrationError) as caught:
        parse_query_response(payload, 1)
    assert caught.value.code is OsvFailureCode.QUERY_RESPONSE_INVALID


def test_normalized_reference_uses_same_strict_timestamp_contract() -> None:
    with pytest.raises(ValueError, match="OSV advisory reference is invalid"):
        OsvAdvisoryReference("PYSEC-2024-1", "2026-08-06 00:00:00Z")


def test_legitimate_fractional_rfc3339_timestamp_is_accepted() -> None:
    payload = _payload(
        {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "PYSEC-2024-1",
                            "modified": "2026-08-06T00:00:00.123456789Z",
                        }
                    ]
                }
            ]
        }
    )
    assert parse_query_response(payload, 1)[0][0][0].modified.endswith("123456789Z")


@pytest.mark.parametrize(
    "limit",
    [
        parser_module.OSV_MAX_ALIASES,
        parser_module.OSV_MAX_AFFECTED_ENTRIES,
        parser_module.OSV_MAX_RANGES_PER_AFFECTED,
        parser_module.OSV_MAX_EVENTS_PER_RANGE,
        parser_module.OSV_MAX_SEVERITY_ENTRIES,
        parser_module.OSV_MAX_FIXED_VERSIONS,
        parser_module.OSV_MAX_REFERENCES,
        parser_module.OSV_MAX_VERSIONS_PER_AFFECTED,
    ],
)
def test_normalization_collection_limits_accept_boundary_and_reject_over(
    limit: int,
) -> None:
    parser_module._bounded_collection([None] * limit, limit)
    with pytest.raises(ValueError):
        parser_module._bounded_collection([None] * (limit + 1), limit)


def test_page_token_limit_is_enforced_by_query_parser() -> None:
    accepted = "x" * parser_module.OSV_MAX_PAGE_TOKEN_BYTES
    assert parse_query_response(
        _payload({"results": [{"next_page_token": accepted}]}), 1
    )[0][1] == accepted
    with pytest.raises(OsvIntegrationError) as caught:
        parse_query_response(
            _payload({"results": [{"next_page_token": accepted + "x"}]}), 1
        )
    assert caught.value.code is OsvFailureCode.QUERY_RESPONSE_INVALID


def test_query_reference_limit_is_enforced() -> None:
    references = [
        {"id": f"TEST-{index}", "modified": "2026-08-06T00:00:00Z"}
        for index in range(parser_module.OSV_MAX_QUERY_REFERENCES_PER_RESULT + 1)
    ]
    with pytest.raises(OsvIntegrationError) as caught:
        parse_query_response(_payload({"results": [{"vulns": references}]}), 1)
    assert caught.value.code is OsvFailureCode.QUERY_RESPONSE_INVALID


def test_summary_utf8_byte_limit_is_enforced() -> None:
    expected = OsvAdvisoryReference("GHSA-2345-6789-cfgh", "2026-08-06T00:00:00Z")
    accepted = _document()
    accepted["summary"] = "a" * parser_module.OSV_MAX_SUMMARY_BYTES
    assert (
        len(
            parse_advisory_response(
                _payload(accepted), expected=expected, candidate=_candidate()
            ).summary
        )
        == parser_module.OSV_MAX_SUMMARY_BYTES
    )
    document = _document()
    document["summary"] = "a" * (parser_module.OSV_MAX_SUMMARY_BYTES + 1)
    with pytest.raises(OsvIntegrationError) as caught:
        parse_advisory_response(
            _payload(document), expected=expected, candidate=_candidate()
        )
    assert caught.value.code is OsvFailureCode.ADVISORY_SCHEMA_INVALID


def test_alias_limit_is_wired_into_advisory_parsing() -> None:
    expected = OsvAdvisoryReference("GHSA-2345-6789-cfgh", "2026-08-06T00:00:00Z")
    accepted = _document()
    accepted["aliases"] = [
        f"ALIAS-{index}" for index in range(parser_module.OSV_MAX_ALIASES)
    ]
    result = parse_advisory_response(
        _payload(accepted), expected=expected, candidate=_candidate()
    )
    assert len(result.aliases) == parser_module.OSV_MAX_ALIASES

    rejected = _document()
    rejected["aliases"] = [
        f"ALIAS-{index}" for index in range(parser_module.OSV_MAX_ALIASES + 1)
    ]
    with pytest.raises(OsvIntegrationError) as caught:
        parse_advisory_response(
            _payload(rejected), expected=expected, candidate=_candidate()
        )
    assert caught.value.code is OsvFailureCode.ADVISORY_SCHEMA_INVALID

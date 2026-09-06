from __future__ import annotations

import json
from copy import deepcopy

import pytest

from securescan.scanners.syft import SyftParserError, parse_syft_json
from securescan.scanners.syft import parser as syft_parser

ROOT = "/tmp/controlled-projection"
PROJECTION_ID = "securescan-source-projection-" + "1" * 32
DIGEST = "a" * 64
BINDING = "b" * 64
PATHS = frozenset({"requirements.txt", "nested/requirements.txt"})


def _document() -> dict[str, object]:
    return {
        "artifacts": [
            {
                "id": "untrusted-upstream-id",
                "name": "requests",
                "version": "2.32.3",
                "type": "python",
                "foundBy": "python-package-cataloger",
                "locations": [{"path": "/requirements.txt"}],
                "language": "python",
                "purl": "pkg:pypi/requests@2.32.3",
                "metadata": {"secret": "must-not-persist"},
            }
        ],
        "artifactRelationships": [],
        "source": {"name": ROOT, "type": "directory", "metadata": {"path": ROOT}},
        "descriptor": {
            "name": "syft",
            "version": "1.51.0",
            "configuration": {
                "catalogers": {
                    "requested": {"default": ["directory", "file"]},
                    "used": ["python-package-cataloger"],
                }
            },
        },
        "schema": {
            "version": "16.1.10",
            "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.10.json",
        },
    }


def _parse(document: object | None = None):
    payload = json.dumps(_document() if document is None else document).encode()
    return parse_syft_json(
        payload,
        expected_source_root=ROOT,
        authorized_paths=PATHS,
        projection_id=PROJECTION_ID,
        snapshot_digest=DIGEST,
        binding_digest=BINDING,
    )


def test_successful_package_normalizes_without_metadata_or_upstream_id() -> None:
    result = _parse()
    assert result.package_count == 1
    observation = result.observations[0]
    assert observation.locations == ("requirements.txt",)
    assert observation.purl == "pkg:pypi/requests@2.32.3"
    canonical = result.canonical_json()
    assert b"must-not-persist" not in canonical
    assert b"untrusted-upstream-id" not in canonical
    assert ROOT.encode() not in canonical


def test_successful_zero_package_inventory_is_distinct() -> None:
    document = _document()
    document["artifacts"] = []
    result = _parse(document)
    assert result.package_count == 0
    assert result.observations == ()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("descriptor", {"name": "other", "version": "1.51.0"}),
        ("schema", {"version": "16.1.9", "url": "x"}),
        ("source", {"name": ROOT, "type": "image", "metadata": {"path": ROOT}}),
        ("artifacts", {}),
    ],
)
def test_wrong_core_contract_fails_closed(field: str, value: object) -> None:
    document = _document()
    document[field] = value
    with pytest.raises(SyftParserError):
        _parse(document)


@pytest.mark.parametrize(
    "field", ["artifacts", "artifactRelationships", "source", "descriptor", "schema"]
)
def test_missing_required_top_level_member_fails_closed(field: str) -> None:
    document = _document()
    del document[field]
    with pytest.raises(SyftParserError):
        _parse(document)


def test_artifact_count_and_string_bounds_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    document = _document()
    monkeypatch.setattr(syft_parser, "_MAX_ARTIFACTS", 0)
    with pytest.raises(SyftParserError):
        _parse(document)

    monkeypatch.setattr(syft_parser, "_MAX_ARTIFACTS", 250_000)
    document = _document()
    document["artifacts"][0]["name"] = "x" * 16_385  # type: ignore[index]
    with pytest.raises(SyftParserError):
        _parse(document)


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        b"not json",
        b'{"artifacts":[],"artifacts":[]}',
        b'{"value":NaN}',
        b"[]",
    ],
)
def test_invalid_json_boundaries_fail_closed(payload: bytes) -> None:
    with pytest.raises(SyftParserError):
        parse_syft_json(
            payload,
            expected_source_root=ROOT,
            authorized_paths=PATHS,
            projection_id=PROJECTION_ID,
            snapshot_digest=DIGEST,
            binding_digest=BINDING,
        )


@pytest.mark.parametrize("path", ["/../escape", "../escape", "/etc/passwd", "C:/host"])
def test_unsafe_or_unauthorized_locations_fail_closed(path: str) -> None:
    document = _document()
    document["artifacts"][0]["locations"] = [{"path": path}]  # type: ignore[index]
    with pytest.raises(SyftParserError):
        _parse(document)


def test_malformed_and_missing_purl_semantics() -> None:
    malformed = _document()
    malformed["artifacts"][0]["purl"] = "not-a-purl"  # type: ignore[index]
    with pytest.raises(SyftParserError):
        _parse(malformed)
    missing = _document()
    missing["artifacts"][0]["purl"] = ""  # type: ignore[index]
    assert _parse(missing).observations[0].purl is None


def test_missing_version_is_explicit_and_not_invented() -> None:
    document = _document()
    document["artifacts"][0]["version"] = ""  # type: ignore[index]
    observation = _parse(document).observations[0]
    assert observation.package_version is None
    assert observation.purl == "pkg:pypi/requests@2.32.3"


def test_same_package_at_two_locations_has_same_key_and_different_observation_id() -> None:
    first = _parse().observations[0]
    document = _document()
    document["artifacts"][0]["locations"] = [{"path": "/nested/requirements.txt"}]  # type: ignore[index]
    second = _parse(document).observations[0]
    assert first.package_key == second.package_key
    assert first.package_observation_id != second.package_observation_id


def test_same_package_from_two_catalogers_has_distinct_observation_identity() -> None:
    first = _parse().observations[0]
    document = _document()
    document["artifacts"][0]["foundBy"] = "other-cataloger"  # type: ignore[index]
    second = _parse(document).observations[0]
    assert first.package_key == second.package_key
    assert first.package_observation_id != second.package_observation_id


def test_coordinate_change_changes_package_key() -> None:
    first = _parse().observations[0]
    document = _document()
    document["artifacts"][0]["version"] = "2.32.4"  # type: ignore[index]
    document["artifacts"][0]["purl"] = "pkg:pypi/requests@2.32.4"  # type: ignore[index]
    assert first.package_key != _parse(document).observations[0].package_key


def test_ordering_is_deterministic_and_exact_duplicates_are_not_deduplicated() -> None:
    document = _document()
    second = deepcopy(document["artifacts"][0])  # type: ignore[index]
    second["name"] = "alpha"
    second["purl"] = "pkg:pypi/alpha@2.32.3"
    document["artifacts"] = [document["artifacts"][0], second, document["artifacts"][0]]  # type: ignore[index]
    forward = _parse(document)
    document["artifacts"] = list(reversed(document["artifacts"]))  # type: ignore[arg-type]
    reverse = _parse(document)
    assert forward.canonical_json() == reverse.canonical_json()
    assert forward.package_count == 3


def test_projection_snapshot_and_binding_identity_are_bound() -> None:
    result = _parse()
    observation = result.observations[0]
    assert observation.projection_id == PROJECTION_ID
    assert observation.snapshot_digest == DIGEST
    assert observation.binding_digest == BINDING
    assert ROOT not in observation.package_key
    assert PROJECTION_ID not in observation.package_key

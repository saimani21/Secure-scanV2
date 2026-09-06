from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from securescan.advisories.osv import OSV_SCHEMA_SHA256, canonical_json
from securescan.benchmarks.osv_s2 import (
    OSV_CONTROLLED_PLAN_SHA256,
    OSV_CONTROLLED_REPORT_SHA256,
    OSV_SERVICE_CONTRACT_SHA256,
    OSV_SERVICE_SNAPSHOT_SHA256,
    OsvBenchmarkError,
    _write_exclusive_atomic,
    build_controlled_candidates,
    build_controlled_report,
    evaluate_snapshot,
)

_ROOT = Path(__file__).resolve().parents[1]
_DIRECTORY = _ROOT / "benchmarks" / "osv"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("controlled-query-plan-v1.json", OSV_CONTROLLED_PLAN_SHA256),
        ("service-contract-v1.json", OSV_SERVICE_CONTRACT_SHA256),
        ("controlled-service-snapshot-v1.json", OSV_SERVICE_SNAPSHOT_SHA256),
        ("controlled-evaluation-v1.json", OSV_CONTROLLED_REPORT_SHA256),
    ],
)
def test_frozen_artifact_identity(name: str, expected: str) -> None:
    assert hashlib.sha256((_DIRECTORY / name).read_bytes()).hexdigest() == expected


def test_offline_replay_is_byte_deterministic() -> None:
    snapshot = json.loads((_DIRECTORY / "controlled-service-snapshot-v1.json").read_bytes())
    expected = (_DIRECTORY / "controlled-evaluation-v1.json").read_bytes()
    assert canonical_json(build_controlled_report(snapshot)) == expected
    assert evaluate_snapshot(snapshot) == evaluate_snapshot(snapshot)


def test_controlled_result_has_required_ecosystem_and_advisory_evidence() -> None:
    report = json.loads((_DIRECTORY / "controlled-evaluation-v1.json").read_bytes())
    analysis = report["analysis"]
    assert {candidate.purl_type for candidate in build_controlled_candidates()} == {
        "golang",
        "npm",
        "pypi",
    }
    assert analysis["candidate_count"] == 6
    assert analysis["zero_advisory_candidate_count"] == 3
    assert analysis["advisory_record_count"] == 6
    assert analysis["alias_group_count"] == 4
    assert analysis["finding_count"] == 4
    assert analysis["cve_aliases"]
    assert analysis["ghsa_aliases"]
    assert analysis["fixed_versions"]
    assert any(finding["cvss"] for finding in analysis["findings"])
    assert report["schema"]["sha256"] == OSV_SCHEMA_SHA256
    assert report["service_snapshot_sha256"] == OSV_SERVICE_SNAPSHOT_SHA256


def test_same_package_boundaries_are_frozen_and_return_zero_advisories() -> None:
    plan = json.loads((_DIRECTORY / "controlled-query-plan-v1.json").read_bytes())
    snapshot = json.loads(
        (_DIRECTORY / "controlled-service-snapshot-v1.json").read_bytes()
    )
    query = next(item for item in snapshot["exchanges"] if item["method"] == "POST")
    results = {
        item["package"]["purl"]: result.get("vulns", [])
        for item, result in zip(
            query["request"]["queries"], query["response"]["results"], strict=True
        )
    }
    entries = plan["packages"]
    assert {item["case_role"] for item in entries} == {
        "AFFECTED",
        "SAME_PACKAGE_FIXED_BOUNDARY",
    }
    go_boundary = next(item for item in entries if item["case_id"] == "go-fixed-boundary")
    assert go_boundary["package_version"] == "v3.0.1"
    assert go_boundary["purl"] == "pkg:golang/gopkg.in/yaml.v3@v3.0.1"
    for ecosystem_name in ("PyYAML", "minimist", "gopkg.in/yaml.v3"):
        pair = [item for item in entries if item["package_name"] == ecosystem_name]
        assert len(pair) == 2
        affected = next(item for item in pair if item["case_role"] == "AFFECTED")
        boundary = next(
            item
            for item in pair
            if item["case_role"] == "SAME_PACKAGE_FIXED_BOUNDARY"
        )
        assert results[affected["purl"]]
        assert results[boundary["purl"]] == []


def test_snapshot_contains_only_sanitized_public_fields() -> None:
    payload = (_DIRECTORY / "controlled-service-snapshot-v1.json").read_text()
    for forbidden in (
        '"details"',
        '"database_specific"',
        '"ecosystem_specific"',
        '"credits"',
        '"headers"',
    ):
        assert forbidden not in payload


def test_record_policy_refuses_file_directory_and_broken_symlink(tmp_path: Path) -> None:
    target = tmp_path / "evidence.json"
    target.write_bytes(b"history")
    with pytest.raises(OsvBenchmarkError):
        _write_exclusive_atomic(target, b"replacement")
    assert target.read_bytes() == b"history"

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(OsvBenchmarkError):
        _write_exclusive_atomic(directory, b"replacement")

    link = tmp_path / "broken"
    link.symlink_to(tmp_path / "absent")
    assert os.path.lexists(link)
    with pytest.raises(OsvBenchmarkError):
        _write_exclusive_atomic(link, b"replacement")


def test_atomic_writer_cannot_overwrite_concurrent_creator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "evidence.json"
    real_link = os.link

    def competing_link(source, destination):
        Path(destination).write_bytes(b"competing evidence")
        return real_link(source, destination)

    monkeypatch.setattr(os, "link", competing_link)
    with pytest.raises(OsvBenchmarkError):
        _write_exclusive_atomic(target, b"new evidence")
    assert target.read_bytes() == b"competing evidence"

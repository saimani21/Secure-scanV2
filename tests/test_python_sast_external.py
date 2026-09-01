from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from securescan.benchmarks.python_sast_external import (
    BENCHPROCTOR_RELEASE,
    BENCHPROCTOR_SOURCE_ID,
    CANDIDATE_CWES,
    INVENTORY_SCHEMA_VERSION,
    OWASP_CROSS_CATEGORY_XSS_CASE_IDS,
    OWASP_EXPECTED_RESULTS_METADATA,
    OWASP_RELEASE,
    OWASP_SOURCE_ID,
    Candidate,
    ExpectedResultsIdentity,
    ExternalGroundTruth,
    _download_if_missing,
    _verify_owasp_source,
    candidate_inventory_data,
    candidate_inventory_digest,
    canonical_document,
    deterministic_review_sample,
    filter_candidate_ground_truth,
    load_candidate_inventory,
    load_source_lock,
    parse_benchproctor_expected_results,
    parse_owasp_expected_results,
    source_lock_digest,
)

ROOT = Path(__file__).parent.parent
BENCHMARK_ROOT = ROOT / "benchmarks/python_sast_external"
SOURCE_LOCK_PATH = BENCHMARK_ROOT / "sources.lock.json"
INVENTORY_PATH = BENCHMARK_ROOT / "candidates.json"
SUMMARY_PATH = BENCHMARK_ROOT / "candidate-summary.json"
MODULE_PATH = ROOT / "src/securescan/benchmarks/python_sast_external.py"
SOURCE_LOCK_DIGEST = "ded3352210520814c03532686096a834c0fac95de51cdb13b02bda4a6aeefd23"
CANDIDATE_INVENTORY_DIGEST = (
    "84e60a1e411ed2f517356e2a6a11bf1fe03fc4945672d120cdb50ead9d4dd60b"
)
REVIEW_SELECTION_DIGEST = "81cb5657d9501bfd0f5aa41125813168bf811788d02d8603ade43e6482384534"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_document(path: Path, value: object) -> None:
    path.write_bytes(canonical_document(value))


def _source_lock_document() -> dict[str, object]:
    value = json.loads(SOURCE_LOCK_PATH.read_bytes())
    assert isinstance(value, dict)
    return value


def _source(document: dict[str, object], source_id: str) -> dict[str, object]:
    sources = document["sources"]
    assert isinstance(sources, list)
    result = next(item for item in sources if item["source_id"] == source_id)
    assert isinstance(result, dict)
    return result


def _ground_truth(
    case_number: int,
    *,
    source_id: str = BENCHPROCTOR_SOURCE_ID,
    framework: str = "flask",
    cwe: int = 78,
    label: str = "vulnerable",
) -> ExternalGroundTruth:
    case_id = f"BenchmarkTest{case_number:05d}"
    return ExternalGroundTruth(
        source_id=source_id,
        external_case_id=case_id,
        cwe=cwe,
        upstream_label=label,
        category="cmdi",
        framework=framework,
        relative_source_path=f"{framework}/testcode/benchmark_test_{case_number:05d}.py",
        upstream_version_id=(
            BENCHPROCTOR_RELEASE if source_id == BENCHPROCTOR_SOURCE_ID else OWASP_RELEASE
        ),
        license="Apache-2.0" if source_id == BENCHPROCTOR_SOURCE_ID else "GPL-3.0",
    )


def _candidate(case_number: int = 1) -> Candidate:
    case_id = f"BenchmarkTest{case_number:05d}"
    return Candidate(
        candidate_id=f"{BENCHPROCTOR_SOURCE_ID}/flask/{case_id}",
        category="cmdi",
        cwe=78,
        external_case_id=case_id,
        external_source_id=BENCHPROCTOR_SOURCE_ID,
        framework="flask",
        ground_truth_status="accepted",
        known_issue=None,
        license="Apache-2.0",
        provenance=f"sources.lock.json#{BENCHPROCTOR_SOURCE_ID}",
        relative_source_path=f"flask/testcode/benchmark_test_{case_number:05d}.py",
        scoring_status="pending-applicability-review",
        source_sha256="1" * 64,
        upstream_label="vulnerable",
        upstream_version_id=BENCHPROCTOR_RELEASE,
    )


def test_source_lock_is_canonical_and_digest_is_frozen() -> None:
    source_lock = load_source_lock(SOURCE_LOCK_PATH)

    assert SOURCE_LOCK_PATH.read_bytes() == canonical_document(source_lock.canonical_data())
    assert source_lock_digest(source_lock) == SOURCE_LOCK_DIGEST
    assert {source.source_id for source in source_lock.sources} == {
        OWASP_SOURCE_ID,
        BENCHPROCTOR_SOURCE_ID,
    }


def test_cached_owasp_commit_must_match_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = load_source_lock(SOURCE_LOCK_PATH).source(OWASP_SOURCE_ID)
    monkeypatch.setattr(
        "securescan.benchmarks.python_sast_external._git_output",
        lambda *_args: "0" * 40,
    )

    with pytest.raises(ValueError, match="immutable identity is invalid"):
        _verify_owasp_source(tmp_path, source)


@pytest.mark.parametrize(
    "mutation",
    (
        "wrong_commit",
        "wrong_release",
        "malformed_checksum",
        "unknown_field",
        "moving_reference",
        "duplicate_source",
    ),
)
def test_malformed_or_unpinned_source_lock_fails_closed(
    tmp_path: Path, mutation: str
) -> None:
    document = _source_lock_document()
    owasp = _source(document, OWASP_SOURCE_ID)
    benchproctor = _source(document, BENCHPROCTOR_SOURCE_ID)
    if mutation == "wrong_commit":
        identity = owasp["immutable_identity"]
        assert isinstance(identity, dict)
        identity["value"] = "0" * 40
    elif mutation == "wrong_release":
        benchproctor["release"] = "2026.07.23"
    elif mutation == "malformed_checksum":
        artifact = benchproctor["artifact"]
        assert isinstance(artifact, dict)
        artifact["sha256"] = "0" * 63
    elif mutation == "unknown_field":
        owasp["unexpected"] = True
    elif mutation == "moving_reference":
        artifact = owasp["artifact"]
        assert isinstance(artifact, dict)
        artifact["url"] = (
            "https://github.com/OWASP-Benchmark/BenchmarkPython/tree/main/"
            + str(owasp["immutable_identity"]["value"])
        )
    else:
        sources = document["sources"]
        assert isinstance(sources, list)
        sources.append(json.loads(json.dumps(owasp)))
    path = tmp_path / "sources.lock.json"
    _write_document(path, document)

    with pytest.raises(ValueError, match="source lock is invalid"):
        load_source_lock(path)


def test_owasp_expected_results_preserves_labels_and_separates_known_issue(
    tmp_path: Path,
) -> None:
    contaminated_id = min(OWASP_CROSS_CATEGORY_XSS_CASE_IDS)
    safe_id = "BenchmarkTest00001"
    source = tmp_path / "owasp"
    (source / "testcode").mkdir(parents=True)
    (source / "testcode" / f"{contaminated_id}.py").write_text(
        "value = 1\n", encoding="utf-8"
    )
    (source / "testcode" / f"{safe_id}.py").write_text("value = 2\n", encoding="utf-8")
    expected_results = source / "expectedresults-0.1.csv"
    expected_results.write_text(
        f"{OWASP_EXPECTED_RESULTS_METADATA}\n"
        f"{contaminated_id},deserialization,false,502\n"
        f"{safe_id},pathtraver,true,22\n",
        encoding="utf-8",
    )
    identity = ExpectedResultsIdentity(
        framework="flask",
        identity="expectedresults-0.1.csv",
        metadata=OWASP_EXPECTED_RESULTS_METADATA,
        relative_path="expectedresults-0.1.csv",
        sha256=_sha256(expected_results),
    )

    parsed = parse_owasp_expected_results(
        source,
        identity,
        required_known_contaminated_case_ids=frozenset({contaminated_id}),
    )
    candidates = filter_candidate_ground_truth(parsed)

    assert len(parsed) == 2
    assert len(candidates) == 1
    assert candidates[0].external_case_id == contaminated_id
    assert candidates[0].upstream_label == "safe"
    assert candidates[0].ground_truth_status == "accepted"
    assert candidates[0].known_issue == "cross-category-xss-contamination"
    assert candidates[0].scoring_status == "excluded-known-benchmark-contamination"


def test_benchproctor_expected_results_parser_uses_tiny_offline_fixture(
    tmp_path: Path,
) -> None:
    source = tmp_path / "benchproctor"
    testcode = source / "flask/testcode"
    testcode.mkdir(parents=True)
    for number in (1, 2):
        (testcode / f"benchmark_test_{number:05d}.py").write_text(
            f"value = {number}\n", encoding="utf-8"
        )
    expected_results = source / f"flask/expectedresults-{BENCHPROCTOR_RELEASE}.csv"
    expected_results.write_text(
        "# test name,category,real vulnerability,CWE\n"
        f"# python-flask-{BENCHPROCTOR_RELEASE} v{BENCHPROCTOR_RELEASE}\n"
        "# 2 test cases generated 2026-07-22\n"
        "# language=python framework=flask shape=standalone\n"
        "BenchmarkTest00001,cmdi,true,78\n"
        "BenchmarkTest00002,pathtraver,false,22\n",
        encoding="utf-8",
    )
    identity = ExpectedResultsIdentity(
        framework="flask",
        identity=f"python-flask-{BENCHPROCTOR_RELEASE}",
        metadata=f"# python-flask-{BENCHPROCTOR_RELEASE} v{BENCHPROCTOR_RELEASE}",
        relative_path=f"flask/expectedresults-{BENCHPROCTOR_RELEASE}.csv",
        sha256=_sha256(expected_results),
    )

    parsed = parse_benchproctor_expected_results(
        source, identity, release=BENCHPROCTOR_RELEASE, expected_case_count=2
    )

    assert [(item.cwe, item.upstream_label) for item in parsed] == [
        (78, "vulnerable"),
        (22, "safe"),
    ]


def test_wrong_expected_results_checksum_and_malformed_cwe_fail_closed(
    tmp_path: Path,
) -> None:
    source = tmp_path / "owasp"
    (source / "testcode").mkdir(parents=True)
    (source / "testcode/BenchmarkTest00001.py").write_text("pass\n", encoding="utf-8")
    expected_results = source / "expectedresults-0.1.csv"
    expected_results.write_text(
        f"{OWASP_EXPECTED_RESULTS_METADATA}\nBenchmarkTest00001,cmdi,true,CWE-78\n",
        encoding="utf-8",
    )
    identity = ExpectedResultsIdentity(
        framework="flask",
        identity="expectedresults-0.1.csv",
        metadata=OWASP_EXPECTED_RESULTS_METADATA,
        relative_path="expectedresults-0.1.csv",
        sha256="0" * 64,
    )
    with pytest.raises(ValueError, match="checksum mismatch"):
        parse_owasp_expected_results(
            source, identity, required_known_contaminated_case_ids=frozenset()
        )

    identity = replace(identity, sha256=_sha256(expected_results))
    with pytest.raises(ValueError, match="ground truth row is invalid"):
        parse_owasp_expected_results(
            source, identity, required_known_contaminated_case_ids=frozenset()
        )


def test_existing_artifact_with_wrong_checksum_fails_without_network(tmp_path: Path) -> None:
    artifact = tmp_path / "bundle.zip"
    artifact.write_bytes(b"not-the-locked-bundle")

    with pytest.raises(ValueError, match="checksum mismatch"):
        _download_if_missing("https://invalid.example/bundle.zip", artifact, "0" * 64)


def test_candidate_cwe_filter_is_exact() -> None:
    items = tuple(_ground_truth(index, cwe=cwe) for index, cwe in enumerate((78, 79, 22), 1))

    filtered = filter_candidate_ground_truth(items)

    assert {item.cwe for item in filtered} == {78, 79}
    assert {78, 79, 89, 94, 95, 295, 347, 377, 489, 502, 611} == CANDIDATE_CWES


def test_sampling_is_deterministic_bounded_and_order_independent() -> None:
    items = tuple(
        _ground_truth(index, label=label)
        for index, label in enumerate(("vulnerable",) * 25 + ("safe",) * 25, 1)
    )

    forward = deterministic_review_sample(items)
    reverse = deterministic_review_sample(tuple(reversed(items)))

    assert forward == reverse
    assert len(forward) == 40
    assert sum(item.upstream_label == "vulnerable" for item in forward) == 20
    assert sum(item.upstream_label == "safe" for item in forward) == 20


def test_candidate_inventory_is_canonical_and_rejects_duplicates(tmp_path: Path) -> None:
    candidate = _candidate()
    inventory = candidate_inventory_data((candidate,), SOURCE_LOCK_DIGEST)
    path = tmp_path / "candidates.json"
    _write_document(path, inventory)

    assert load_candidate_inventory(path, SOURCE_LOCK_DIGEST) == (candidate,)
    with pytest.raises(ValueError, match="candidate inventory is invalid"):
        load_candidate_inventory(path, "0" * 64)

    inventory["candidates"] = [candidate.canonical_data(), candidate.canonical_data()]
    _write_document(path, inventory)
    with pytest.raises(ValueError, match="candidate inventory is invalid"):
        load_candidate_inventory(path, SOURCE_LOCK_DIGEST)


def test_candidate_rejects_path_traversal() -> None:
    with pytest.raises(ValueError, match="candidate is invalid"):
        replace(_candidate(), relative_source_path="flask/testcode/../outside.py")


def test_candidate_schema_rejects_disputed_or_inconsistent_issue_semantics() -> None:
    with pytest.raises(ValueError, match="candidate is invalid"):
        replace(_candidate(), ground_truth_status="disputed")
    with pytest.raises(ValueError, match="candidate is invalid"):
        replace(_candidate(), known_issue="cross-category-xss-contamination")


def test_symlinked_external_source_file_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "owasp"
    (source / "testcode").mkdir(parents=True)
    outside = tmp_path / "outside.py"
    outside.write_text("pass\n", encoding="utf-8")
    (source / "testcode/BenchmarkTest00001.py").symlink_to(outside)
    expected_results = source / "expectedresults-0.1.csv"
    expected_results.write_text(
        f"{OWASP_EXPECTED_RESULTS_METADATA}\nBenchmarkTest00001,cmdi,true,78\n",
        encoding="utf-8",
    )
    identity = ExpectedResultsIdentity(
        framework="flask",
        identity="expectedresults-0.1.csv",
        metadata=OWASP_EXPECTED_RESULTS_METADATA,
        relative_path="expectedresults-0.1.csv",
        sha256=_sha256(expected_results),
    )

    with pytest.raises(ValueError, match="external benchmark file is invalid"):
        parse_owasp_expected_results(
            source, identity, required_known_contaminated_case_ids=frozenset()
        )


def test_committed_inventory_and_summary_are_deterministic_metadata_only() -> None:
    candidates = load_candidate_inventory(INVENTORY_PATH, SOURCE_LOCK_DIGEST)
    inventory = json.loads(INVENTORY_PATH.read_bytes())
    summary = json.loads(SUMMARY_PATH.read_bytes())
    serialized = INVENTORY_PATH.read_text(encoding="utf-8") + SUMMARY_PATH.read_text(
        encoding="utf-8"
    )

    assert len(candidates) == 1460
    assert candidate_inventory_digest(inventory) == CANDIDATE_INVENTORY_DIGEST
    assert summary["candidate_inventory_digest"] == CANDIDATE_INVENTORY_DIGEST
    assert summary["full_candidate_count"] == 3260
    assert summary["review_sample_count"] == 1460
    assert summary["candidate_counts_by_cwe"]["377"] == {
        "full": 0,
        "review_sample": 0,
    }
    assert summary["known_contaminated_excluded_case_count"] == {
        "full": 33,
        "review_sample": 33,
    }
    assert summary["review_selection_digest"] == REVIEW_SELECTION_DIGEST
    contaminated = [candidate for candidate in candidates if candidate.known_issue is not None]
    assert len(contaminated) == 33
    assert all(candidate.ground_truth_status == "accepted" for candidate in contaminated)
    assert all(
        candidate.known_issue == "cross-category-xss-contamination"
        and candidate.scoring_status == "excluded-known-benchmark-contamination"
        for candidate in contaminated
    )
    assert str(ROOT) not in serialized
    for forbidden in (
        '"scanner_id"',
        '"rule_id"',
        '"observed_rule"',
        '"expected_rule"',
        '"tp"',
        '"fp"',
        '"fn"',
        '"tn"',
    ):
        assert forbidden not in serialized.lower()


def test_candidate_generation_does_not_import_scanner_execution_path() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert "securescan.benchmarks.python_sast" not in imports
    assert "run_frozen_semgrep_benchmark" not in source
    assert "semgrep" not in source.lower()


def test_normal_external_benchmark_tests_are_offline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_network(*_args, **_kwargs):
        raise AssertionError("network access is forbidden in normal tests")

    monkeypatch.setattr("urllib.request.urlopen", fail_network)

    source_lock = load_source_lock(SOURCE_LOCK_PATH)
    candidates = load_candidate_inventory(INVENTORY_PATH, source_lock_digest(source_lock))

    assert len(candidates) == 1460
    assert INVENTORY_SCHEMA_VERSION == "securescan-python-sast-external-candidates-v2"

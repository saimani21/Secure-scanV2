from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from securescan.benchmarks.gitleaks_contract import (
    GITLEAKS_BENCHMARK_CONTRACT_PATH,
    GITLEAKS_BENCHMARK_CONTRACT_SCHEMA_VERSION,
    GITLEAKS_BENCHMARK_CONTRACT_SHA256,
    GITLEAKS_BENCHMARK_ID,
    GITLEAKS_BENCHMARK_MANIFEST_SCHEMA_VERSION,
    GITLEAKS_BINDING_ARTIFACT_SHA256,
    GITLEAKS_BINDING_DIGEST,
    GITLEAKS_V04E_BASELINE_COMMIT,
    GITLEAKS_V04E_BASELINE_TAG,
    GitleaksBenchmarkCase,
    GitleaksBenchmarkClassification,
    GitleaksBenchmarkExpectation,
    GitleaksBenchmarkSourceType,
    benchmark_contract_document,
    benchmark_contract_sha256,
    build_benchmark_manifest,
    canonical_benchmark_contract,
    classify_case,
    load_benchmark_manifest,
    verify_benchmark_contract,
)
from securescan.scanners.gitleaks.parser import (
    GitleaksDetectionKind,
)

ROOT = Path(__file__).parent.parent


def _case(
    *,
    case_id: str = "github-pat-positive-01",
    relative_path: str = "corpus/github-pat/positive-01.txt",
    sha256: str = "a" * 64,
    expectation: GitleaksBenchmarkExpectation = (
        GitleaksBenchmarkExpectation.EXPECTED_MATCH
    ),
    expected_rule_id: str | None = "github-pat",
    expected_detection_kind: GitleaksDetectionKind | None = (
        GitleaksDetectionKind.CONTENT
    ),
    source_type: GitleaksBenchmarkSourceType = (
        GitleaksBenchmarkSourceType.PROJECT_OWNED_SYNTHETIC
    ),
) -> GitleaksBenchmarkCase:
    return GitleaksBenchmarkCase(
        case_id=case_id,
        description="Project-owned synthetic benchmark case.",
        relative_path=relative_path,
        sha256=sha256,
        source_type=source_type,
        expectation=expectation,
        expected_rule_id=expected_rule_id,
        expected_detection_kind=expected_detection_kind,
    )


def test_contract_identity_is_frozen() -> None:
    assert GITLEAKS_BENCHMARK_ID == (
        "securescan-gitleaks-v0.4f-local-v1"
    )
    assert GITLEAKS_BENCHMARK_CONTRACT_SCHEMA_VERSION == (
        "securescan-gitleaks-benchmark-contract-v1"
    )
    assert GITLEAKS_BENCHMARK_MANIFEST_SCHEMA_VERSION == (
        "securescan-gitleaks-benchmark-manifest-v1"
    )
    assert GITLEAKS_V04E_BASELINE_COMMIT == (
        "12fc469a17fc0d118070ad30765c4f5fd0dc749a"
    )
    assert GITLEAKS_V04E_BASELINE_TAG == (
        "source-v0.4E-gitleaks-finding-identity"
    )
    assert GITLEAKS_BINDING_DIGEST == (
        "8d9f224e1c5ddabef508a26be2966f51dc2a9c2e5805ea3bffcf444b3cae9561"
    )
    assert GITLEAKS_BINDING_ARTIFACT_SHA256 == (
        "8d0e06a802158827bbe685b7970ffa075ae07f6393debbb088c3b9bf29f1bd44"
    )


def test_contract_artifact_is_literal_canonical_and_content_addressed() -> None:
    path = ROOT / GITLEAKS_BENCHMARK_CONTRACT_PATH
    payload = path.read_bytes()

    assert payload == canonical_benchmark_contract()
    assert hashlib.sha256(payload).hexdigest() == (
        GITLEAKS_BENCHMARK_CONTRACT_SHA256
    )
    assert benchmark_contract_sha256() == (
        GITLEAKS_BENCHMARK_CONTRACT_SHA256
    )


def test_contract_correlates_with_frozen_binding_artifact() -> None:
    verify_benchmark_contract(ROOT.resolve())


def test_contract_freezes_confidentiality_and_scope_boundaries() -> None:
    contract = benchmark_contract_document()

    assert contract["scanner"] == {
        "id": "gitleaks",
        "version": "8.30.1",
    }
    assert contract["execution"] == {
        "archive_traversal": False,
        "current_snapshot_only": True,
        "history_scanning": False,
        "mode": "dir",
        "network_acquisition": False,
        "recursive_decoding": False,
        "repository_inline_allow_directives": False,
    }

    confidentiality = contract["confidentiality"]
    assert isinstance(confidentiality, dict)
    assert confidentiality[
        "raw_secret_in_public_report"
    ] is False
    assert confidentiality[
        "raw_match_in_public_report"
    ] is False
    assert confidentiality[
        "gitleaks_fingerprint_in_public_report"
    ] is False
    assert confidentiality[
        "credential_hash_for_public_identity"
    ] is False
    assert confidentiality[
        "raw_scanner_stdout_persisted"
    ] is False

    maturity = contract["maturity"]
    assert isinstance(maturity, dict)
    assert maturity == {
        "benchmark_result_does_not_auto_promote": True,
        "starting_state": "scannable",
    }


@pytest.mark.parametrize(
    ("expectation", "observed", "classification"),
    (
        (
            GitleaksBenchmarkExpectation.EXPECTED_MATCH,
            True,
            GitleaksBenchmarkClassification.TP,
        ),
        (
            GitleaksBenchmarkExpectation.EXPECTED_MATCH,
            False,
            GitleaksBenchmarkClassification.FN,
        ),
        (
            GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
            True,
            GitleaksBenchmarkClassification.FP,
        ),
        (
            GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
            False,
            GitleaksBenchmarkClassification.TN,
        ),
        (
            GitleaksBenchmarkExpectation.OUT_OF_SCOPE,
            True,
            GitleaksBenchmarkClassification.OUT_OF_SCOPE,
        ),
        (
            GitleaksBenchmarkExpectation.OUT_OF_SCOPE,
            False,
            GitleaksBenchmarkClassification.OUT_OF_SCOPE,
        ),
    ),
)
def test_classification_contract_is_explicit(
    expectation: GitleaksBenchmarkExpectation,
    observed: bool,
    classification: GitleaksBenchmarkClassification,
) -> None:
    assert classify_case(expectation, observed) is classification


def test_out_of_scope_case_has_no_fake_rule_relation() -> None:
    case = _case(
        case_id="scope-sentinel-01",
        relative_path="corpus/scope/sentinel-01.txt",
        expectation=GitleaksBenchmarkExpectation.OUT_OF_SCOPE,
        expected_rule_id=None,
        expected_detection_kind=None,
        source_type=(
            GitleaksBenchmarkSourceType.PROJECT_OWNED_SCOPE_SENTINEL
        ),
    )

    assert case.expected_rule_id is None
    assert case.expected_detection_kind is None


@pytest.mark.parametrize(
    ("expectation", "rule_id", "kind"),
    (
        (
            GitleaksBenchmarkExpectation.EXPECTED_MATCH,
            None,
            GitleaksDetectionKind.CONTENT,
        ),
        (
            GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
            "github-pat",
            None,
        ),
        (
            GitleaksBenchmarkExpectation.OUT_OF_SCOPE,
            "github-pat",
            GitleaksDetectionKind.CONTENT,
        ),
    ),
)
def test_invalid_case_relation_fails_closed(
    expectation: GitleaksBenchmarkExpectation,
    rule_id: str | None,
    kind: GitleaksDetectionKind | None,
) -> None:
    with pytest.raises(
        ValueError,
        match="benchmark case is invalid",
    ):
        _case(
            expectation=expectation,
            expected_rule_id=rule_id,
            expected_detection_kind=kind,
        )


def test_manifest_is_ordered_unique_and_content_addressed() -> None:
    first = _case(
        case_id="a-case",
        relative_path="corpus/a.txt",
        sha256="a" * 64,
    )
    second = _case(
        case_id="b-case",
        relative_path="corpus/b.txt",
        sha256="b" * 64,
        expectation=(
            GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH
        ),
        source_type=(
            GitleaksBenchmarkSourceType.PROJECT_OWNED_NEAR_MISS
        ),
    )

    manifest = build_benchmark_manifest((second, first))

    assert tuple(
        case.case_id
        for case in manifest.cases
    ) == ("a-case", "b-case")
    assert len(manifest.corpus_digest) == 64
    assert manifest.contract_sha256 == (
        GITLEAKS_BENCHMARK_CONTRACT_SHA256
    )


def test_manifest_rejects_duplicate_paths() -> None:
    first = _case(
        case_id="a-case",
        relative_path="corpus/same.txt",
    )
    second = _case(
        case_id="b-case",
        relative_path="corpus/same.txt",
    )

    with pytest.raises(
        ValueError,
        match="manifest is invalid",
    ):
        build_benchmark_manifest((first, second))


def test_manifest_loader_verifies_files_and_rejects_unlisted_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "gitleaks"
    corpus = root / "corpus"
    corpus.mkdir(parents=True)

    case_path = corpus / "case.txt"
    case_path.write_bytes(b"synthetic benchmark data\n")
    file_sha256 = hashlib.sha256(
        case_path.read_bytes()
    ).hexdigest()

    case = _case(
        case_id="case-01",
        relative_path="corpus/case.txt",
        sha256=file_sha256,
    )
    manifest = build_benchmark_manifest((case,))

    manifest_path = root / "manifest.json"
    manifest_path.write_bytes(manifest.canonical_json())

    assert (
        load_benchmark_manifest(manifest_path)
        == manifest
    )

    (corpus / "unlisted.txt").write_text(
        "not declared\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="corpus is invalid",
    ):
        load_benchmark_manifest(manifest_path)


def test_manifest_loader_rejects_changed_case_bytes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "gitleaks"
    corpus = root / "corpus"
    corpus.mkdir(parents=True)

    case_path = corpus / "case.txt"
    case_path.write_bytes(b"initial\n")
    sha256 = hashlib.sha256(
        case_path.read_bytes()
    ).hexdigest()

    manifest = build_benchmark_manifest(
        (
            _case(
                case_id="case-01",
                relative_path="corpus/case.txt",
                sha256=sha256,
            ),
        )
    )
    manifest_path = root / "manifest.json"
    manifest_path.write_bytes(manifest.canonical_json())

    case_path.write_bytes(b"changed\n")

    with pytest.raises(
        ValueError,
        match="corpus is invalid",
    ):
        load_benchmark_manifest(manifest_path)


def test_contract_artifact_contains_no_benchmark_secret_values() -> None:
    document = json.loads(
        canonical_benchmark_contract()
    )

    assert "Secret" not in document
    assert "Match" not in document
    assert "Fingerprint" not in document

    binding = document["binding"]
    assert isinstance(binding, dict)
    assert "secret" not in binding
    assert "credential" not in binding


def test_v04f1_performs_no_scanner_execution() -> None:
    contract = benchmark_contract_document()

    assert "results" not in contract
    assert "metrics" not in contract
    assert "observations" not in contract
    assert "maturity_decision" not in contract


def test_manifest_loader_rejects_noncanonical_case_order(
    tmp_path: Path,
) -> None:
    root = tmp_path / "gitleaks"
    corpus = root / "corpus"
    corpus.mkdir(parents=True)

    a_path = corpus / "a.txt"
    b_path = corpus / "b.txt"
    a_path.write_bytes(b"a\n")
    b_path.write_bytes(b"b\n")

    first = _case(
        case_id="a-case",
        relative_path="corpus/a.txt",
        sha256=hashlib.sha256(
            a_path.read_bytes()
        ).hexdigest(),
    )
    second = _case(
        case_id="b-case",
        relative_path="corpus/b.txt",
        sha256=hashlib.sha256(
            b_path.read_bytes()
        ).hexdigest(),
    )

    manifest = build_benchmark_manifest(
        (first, second)
    )
    document = manifest.canonical_data()

    cases = document["cases"]
    assert isinstance(cases, list)
    document["cases"] = list(
        reversed(cases)
    )

    manifest_path = root / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            document,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="manifest is invalid",
    ):
        load_benchmark_manifest(
            manifest_path
        )


def test_contract_verification_rejects_symlinked_artifact(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"

    contract_path = (
        repository
        / GITLEAKS_BENCHMARK_CONTRACT_PATH
    )
    binding_path = (
        repository
        / "benchmarks/gitleaks/gitleaks-binding-v1.json"
    )

    contract_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    real_contract = (
        tmp_path / "real-contract.json"
    )
    real_contract.write_bytes(
        canonical_benchmark_contract()
    )
    contract_path.symlink_to(
        real_contract
    )

    source_binding = (
        ROOT
        / "benchmarks/gitleaks/gitleaks-binding-v1.json"
    )
    binding_path.write_bytes(
        source_binding.read_bytes()
    )

    with pytest.raises(
        ValueError,
        match="contract is invalid",
    ):
        verify_benchmark_contract(
            repository.resolve()
        )


def test_manifest_loader_rejects_symlinked_manifest(
    tmp_path: Path,
) -> None:
    root = tmp_path / "gitleaks"
    corpus = root / "corpus"
    corpus.mkdir(parents=True)

    case_path = corpus / "case.txt"
    case_path.write_bytes(b"fixture\n")

    case = _case(
        case_id="case-01",
        relative_path="corpus/case.txt",
        sha256=hashlib.sha256(
            case_path.read_bytes()
        ).hexdigest(),
    )
    manifest = build_benchmark_manifest((case,))

    real_manifest = tmp_path / "real-manifest.json"
    real_manifest.write_bytes(
        manifest.canonical_json()
    )

    linked_manifest = root / "manifest.json"
    linked_manifest.symlink_to(real_manifest)

    with pytest.raises(
        ValueError,
        match="document is invalid",
    ):
        load_benchmark_manifest(linked_manifest)


def test_manifest_loader_rejects_symlinked_corpus_directory(
    tmp_path: Path,
) -> None:
    root = tmp_path / "gitleaks"
    root.mkdir()

    external_corpus = tmp_path / "external-corpus"
    external_corpus.mkdir()

    external_case = external_corpus / "case.txt"
    external_case.write_bytes(b"fixture\n")

    (root / "corpus").symlink_to(
        external_corpus,
        target_is_directory=True,
    )

    case = _case(
        case_id="case-01",
        relative_path="corpus/case.txt",
        sha256=hashlib.sha256(
            external_case.read_bytes()
        ).hexdigest(),
    )
    manifest = build_benchmark_manifest((case,))

    manifest_path = root / "manifest.json"
    manifest_path.write_bytes(
        manifest.canonical_json()
    )

    with pytest.raises(
        ValueError,
        match="corpus is invalid",
    ):
        load_benchmark_manifest(manifest_path)

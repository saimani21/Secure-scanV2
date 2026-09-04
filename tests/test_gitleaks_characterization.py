from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from securescan.benchmarks.gitleaks_characterization import (
    GITLEAKS_CHARACTERIZATION_ID,
    GITLEAKS_CHARACTERIZATION_PATH,
    GITLEAKS_CHARACTERIZATION_SCHEMA_VERSION,
    GITLEAKS_CHARACTERIZATION_SHA256,
    GITLEAKS_F3B_REPORT_PATH,
    GITLEAKS_F3B_REPORT_SHA256,
    GITLEAKS_F4A_CONTRACT_PATH,
    GITLEAKS_F4A_CONTRACT_SHA256,
    GITLEAKS_F4A_CORPUS_PATH,
    GITLEAKS_F4A_MANIFEST_PATH,
    GITLEAKS_F4A_MANIFEST_SHA256,
    GITLEAKS_F4B2_RESULT_PATH,
    GITLEAKS_F4B2_RESULT_SHA256,
    GitleaksCharacterizationCategory,
    GitleaksCharacterizationError,
    canonical_gitleaks_characterization,
    generate_gitleaks_characterization,
    verify_gitleaks_characterization,
)

ROOT = Path(__file__).resolve().parents[1]
_DOCUMENT_PATHS = (
    GITLEAKS_F3B_REPORT_PATH,
    GITLEAKS_F4A_CONTRACT_PATH,
    GITLEAKS_F4A_MANIFEST_PATH,
    GITLEAKS_F4B2_RESULT_PATH,
    GITLEAKS_CHARACTERIZATION_PATH,
)


def _copy_evidence(tmp_path: Path) -> Path:
    root = (tmp_path / "repository").resolve()
    for relative in _DOCUMENT_PATHS:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    shutil.copytree(ROOT / GITLEAKS_F4A_CORPUS_PATH, root / GITLEAKS_F4A_CORPUS_PATH)
    return root


def _rewrite_json(
    root: Path,
    relative: str,
    mutate: Callable[[dict[str, object]], None],
) -> None:
    path = root / relative
    document = json.loads(path.read_bytes())
    mutate(document)
    path.write_bytes(canonical_gitleaks_characterization(document))


def _rejects(root: Path) -> None:
    with pytest.raises(
        GitleaksCharacterizationError,
        match="^Gitleaks characterization evidence is invalid$",
    ):
        verify_gitleaks_characterization(root)


def test_exact_frozen_evidence_and_generated_characterization_are_accepted() -> None:
    document = verify_gitleaks_characterization(ROOT.resolve())

    assert document == generate_gitleaks_characterization(ROOT.resolve())
    assert document["schema_version"] == GITLEAKS_CHARACTERIZATION_SCHEMA_VERSION
    assert document["characterization_id"] == GITLEAKS_CHARACTERIZATION_ID
    assert document["maturity"] == "SCANNABLE"
    assert len(document["characterizations"]) == 6
    assert canonical_gitleaks_characterization(document) == (
        ROOT / GITLEAKS_CHARACTERIZATION_PATH
    ).read_bytes()


def test_characterization_binds_all_frozen_evidence_identities() -> None:
    bindings = verify_gitleaks_characterization(ROOT.resolve())["evidence_bindings"]

    assert bindings == {
        "f3b": {
            "baseline_commit": "d183336c129977c4279cd1058bbe060742de0e54",
            "baseline_tag": "source-v0.4F3B-gitleaks-initial-baseline",
            "report_sha256": GITLEAKS_F3B_REPORT_SHA256,
        },
        "f4a": {
            "baseline_commit": "526ce3192885c6fc04ae8b7ac84346466809ca4e",
            "baseline_tag": "source-v0.4F4A-gitleaks-adversarial-prescan",
            "contract_sha256": GITLEAKS_F4A_CONTRACT_SHA256,
            "corpus_digest": "dfd3ccbcb6537b7de35cc9bce130e9dabd0f72ef5ff0fc1f10ef7a303bf90c22",
            "manifest_sha256": GITLEAKS_F4A_MANIFEST_SHA256,
        },
        "f4b1": {
            "baseline_commit": "5f8ef71273b7b7dc7818be006c11c3aa3e91d160",
            "baseline_tag": "source-v0.4F4B1-gitleaks-adversarial-harness",
        },
        "f4b2": {
            "baseline_commit": "52b7b71be1636d5d5cf404174ccec7159f2e777e",
            "baseline_tag": "source-v0.4F4B2-gitleaks-adversarial-result",
            "result_sha256": GITLEAKS_F4B2_RESULT_SHA256,
        },
    }


def test_all_six_conservative_characterization_categories_are_exact() -> None:
    rows = verify_gitleaks_characterization(ROOT.resolve())["characterizations"]

    assert {row["category"] for row in rows} == {
        category.value for category in GitleaksCharacterizationCategory
    }
    assert len({row["characterization_id"] for row in rows}) == 6
    assert all(
        set(row)
        == {
            "affected_rule_ids",
            "category",
            "characterization_id",
            "claim_boundary",
            "evidence",
            "observation",
            "product_implication",
        }
        for row in rows
    )


def test_fail_closed_explicitly_binds_confidentiality_failure_hostile_test() -> None:
    rows = verify_gitleaks_characterization(ROOT.resolve())["characterizations"]
    by_id = {row["characterization_id"]: row for row in rows}
    test_id = "test_raw_projection_sentinel_leak_fails_confidentiality"

    fail_closed = by_id["incomplete-execution-never-clean"]["evidence"][0]
    confidentiality = by_id["credential-independent-canonical-evidence"]["evidence"][0]
    assert test_id in fail_closed["test_ids"]
    assert test_id in confidentiality["test_ids"]


def test_f3b_mutation_is_rejected(tmp_path: Path) -> None:
    root = _copy_evidence(tmp_path)
    _rewrite_json(root, GITLEAKS_F3B_REPORT_PATH, lambda value: value.update(scanner_version="0"))
    _rejects(root)


@pytest.mark.parametrize("relative", (GITLEAKS_F4A_CONTRACT_PATH, GITLEAKS_F4A_MANIFEST_PATH))
def test_f4a_identity_mutation_is_rejected(tmp_path: Path, relative: str) -> None:
    root = _copy_evidence(tmp_path)
    _rewrite_json(root, relative, lambda value: value.update(adversarial_id="changed"))
    _rejects(root)


def test_f4a_corpus_mutation_is_rejected(tmp_path: Path) -> None:
    root = _copy_evidence(tmp_path)
    fixture = root / GITLEAKS_F4A_CORPUS_PATH / "pkcs12-file/one-byte.p12"
    fixture.write_bytes(b"changed")
    _rejects(root)


def test_f4b2_result_mutation_is_rejected(tmp_path: Path) -> None:
    root = _copy_evidence(tmp_path)
    _rewrite_json(root, GITLEAKS_F4B2_RESULT_PATH, lambda value: value.update(scanner_version="0"))
    _rejects(root)


def test_f4b2_case_result_mutation_is_rejected(tmp_path: Path) -> None:
    root = _copy_evidence(tmp_path)

    def mutate(value: dict[str, object]) -> None:
        value["cases"][0]["result"] = "FAIL"  # type: ignore[index]

    _rewrite_json(root, GITLEAKS_F4B2_RESULT_PATH, mutate)
    _rejects(root)


def test_missing_required_f4b2_case_is_rejected(tmp_path: Path) -> None:
    root = _copy_evidence(tmp_path)

    def mutate(value: dict[str, object]) -> None:
        value["cases"].pop()  # type: ignore[union-attr]

    _rewrite_json(root, GITLEAKS_F4B2_RESULT_PATH, mutate)
    _rejects(root)


def test_extra_f4b2_case_is_rejected(tmp_path: Path) -> None:
    root = _copy_evidence(tmp_path)

    def mutate(value: dict[str, object]) -> None:
        value["cases"].append(dict(value["cases"][0], case_id="extra"))  # type: ignore[union-attr,index]

    _rewrite_json(root, GITLEAKS_F4B2_RESULT_PATH, mutate)
    _rejects(root)


@pytest.mark.parametrize(
    "field",
    ("unexpected_cross_rule_observations", "unexpected_detection_kind_observations"),
)
def test_unexpected_f4b2_observation_is_rejected(tmp_path: Path, field: str) -> None:
    root = _copy_evidence(tmp_path)

    def mutate(value: dict[str, object]) -> None:
        value[field] = [{"finding_instance_id": "a" * 64}]

    _rewrite_json(root, GITLEAKS_F4B2_RESULT_PATH, mutate)
    _rejects(root)


@pytest.mark.parametrize(("field", "value"), (("pass_count", 12), ("fail_count", 1)))
def test_f4b2_pass_fail_count_mutation_is_rejected(
    tmp_path: Path,
    field: str,
    value: int,
) -> None:
    root = _copy_evidence(tmp_path)
    _rewrite_json(root, GITLEAKS_F4B2_RESULT_PATH, lambda document: document.update({field: value}))
    _rejects(root)


def test_f4b2_parsed_finding_count_mutation_is_rejected(tmp_path: Path) -> None:
    root = _copy_evidence(tmp_path)

    def mutate(value: dict[str, object]) -> None:
        value["execution"]["parsed_finding_count"] = 4  # type: ignore[index]

    _rewrite_json(root, GITLEAKS_F4B2_RESULT_PATH, mutate)
    _rejects(root)


def test_noncanonical_characterization_json_is_rejected(tmp_path: Path) -> None:
    root = _copy_evidence(tmp_path)
    path = root / GITLEAKS_CHARACTERIZATION_PATH
    document = json.loads(path.read_bytes())
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    _rejects(root)


def test_duplicate_key_characterization_json_is_rejected(tmp_path: Path) -> None:
    root = _copy_evidence(tmp_path)
    path = root / GITLEAKS_CHARACTERIZATION_PATH
    payload = path.read_bytes()
    path.write_bytes(b'{"schema_version":"duplicate",' + payload[1:])
    _rejects(root)


def test_nonfinite_characterization_json_is_rejected(tmp_path: Path) -> None:
    root = _copy_evidence(tmp_path)
    path = root / GITLEAKS_CHARACTERIZATION_PATH
    payload = path.read_bytes()
    path.write_bytes(payload[:-2] + b',"nonfinite":NaN}\n')
    _rejects(root)


@pytest.mark.parametrize("relative", _DOCUMENT_PATHS)
def test_missing_evidence_document_is_rejected(tmp_path: Path, relative: str) -> None:
    root = _copy_evidence(tmp_path)
    (root / relative).unlink()
    _rejects(root)


@pytest.mark.parametrize("relative", _DOCUMENT_PATHS)
def test_symlinked_evidence_document_is_rejected(tmp_path: Path, relative: str) -> None:
    root = _copy_evidence(tmp_path)
    path = root / relative
    target = tmp_path / (Path(relative).name + ".target")
    shutil.copy2(path, target)
    path.unlink()
    path.symlink_to(target)
    _rejects(root)


def test_symlinked_f4a_corpus_fixture_is_rejected(tmp_path: Path) -> None:
    root = _copy_evidence(tmp_path)
    fixture = root / GITLEAKS_F4A_CORPUS_PATH / "pkcs12-file/one-byte.p12"
    target = tmp_path / "fixture.target"
    shutil.copy2(fixture, target)
    fixture.unlink()
    fixture.symlink_to(target)
    _rejects(root)


def test_generation_is_deterministic_and_artifact_digest_is_frozen() -> None:
    first = canonical_gitleaks_characterization(
        generate_gitleaks_characterization(ROOT.resolve())
    )
    second = canonical_gitleaks_characterization(
        generate_gitleaks_characterization(ROOT.resolve())
    )

    assert first == second == (ROOT / GITLEAKS_CHARACTERIZATION_PATH).read_bytes()
    assert hashlib.sha256(first).hexdigest() == GITLEAKS_CHARACTERIZATION_SHA256


def test_characterization_has_no_accuracy_reinterpretation_or_sensitive_values() -> None:
    payload = (ROOT / GITLEAKS_CHARACTERIZATION_PATH).read_bytes()
    document = json.loads(payload)

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | set().union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    assert not {
        "precision",
        "recall",
        "f1",
        "tp",
        "tn",
        "fp",
        "fn",
        "overall",
        "projection_id",
        "projection_digest",
        "context_digest",
        "parse_result_digest",
        "stdout_bytes",
        "stderr_bytes",
        "finding_instance_id",
    } & keys(document)
    assert str(ROOT).encode() not in payload
    assert b"ghp_" not in payload
    sentinel_pattern = re.compile(rb"(?:api[_-]?key|secret|token)\s*[:=]\s*[\"']([^\"']+)")
    for fixture in (ROOT / GITLEAKS_F4A_CORPUS_PATH).rglob("*"):
        if fixture.is_file():
            for sentinel in sentinel_pattern.findall(fixture.read_bytes()):
                assert sentinel not in payload


def test_characterization_layer_has_no_scanner_execution_path() -> None:
    source = (
        ROOT / "src/securescan/benchmarks/gitleaks_characterization.py"
    ).read_text()

    assert "subprocess" not in source
    assert "GitleaksSourceExecutionBridge" not in source
    assert "gitleaks dir" not in source
    assert "Popen" not in source
    assert os.path.lexists(ROOT / GITLEAKS_F4B2_RESULT_PATH)

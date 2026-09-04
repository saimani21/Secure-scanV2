from __future__ import annotations

import hashlib
import json
import math
import shutil
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from securescan.benchmarks import gitleaks_adversarial as adversarial
from securescan.benchmarks.gitleaks_adversarial import (
    GITLEAKS_ADVERSARIAL_CASE_COUNT,
    GITLEAKS_ADVERSARIAL_CONTRACT_PATH,
    GITLEAKS_ADVERSARIAL_CONTRACT_SHA256,
    GITLEAKS_ADVERSARIAL_CORPUS_DIGEST,
    GITLEAKS_ADVERSARIAL_MANIFEST_PATH,
    GITLEAKS_ADVERSARIAL_MANIFEST_SHA256,
    GITLEAKS_ADVERSARIAL_RESULT_PATH,
    GITLEAKS_F3B_BASELINE_COMMIT,
    GITLEAKS_F3B_BASELINE_PATH,
    GITLEAKS_F3B_BASELINE_SHA256,
    GITLEAKS_F3B_BASELINE_TAG,
    GitleaksAdversarialExpectation,
    GitleaksAdversarialMechanism,
    adversarial_corpus_digest,
    load_gitleaks_adversarial_contract,
    load_gitleaks_adversarial_manifest,
    shannon_entropy,
    verify_gitleaks_adversarial,
)
from securescan.benchmarks.gitleaks_contract import GITLEAKS_BINDING_DIGEST
from securescan.scanners.gitleaks import GitleaksDetectionKind

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / GITLEAKS_ADVERSARIAL_CONTRACT_PATH
MANIFEST = ROOT / GITLEAKS_ADVERSARIAL_MANIFEST_PATH
CORPUS = ROOT / "benchmarks/gitleaks/adversarial-corpus"


def _copy_checkpoint(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    destination = root / "benchmarks/gitleaks"
    destination.mkdir(parents=True)
    shutil.copy2(CONTRACT, destination / CONTRACT.name)
    shutil.copy2(MANIFEST, destination / MANIFEST.name)
    shutil.copy2(
        ROOT / GITLEAKS_F3B_BASELINE_PATH,
        destination / Path(GITLEAKS_F3B_BASELINE_PATH).name,
    )
    shutil.copytree(CORPUS, destination / "adversarial-corpus")
    return root.resolve()


def _case(case_id: str):
    return next(
        case
        for case in load_gitleaks_adversarial_manifest(MANIFEST).cases
        if case.case_id == case_id
    )


def test_frozen_contract_manifest_and_baseline_identities(tmp_path: Path) -> None:
    manifest = verify_gitleaks_adversarial(_copy_checkpoint(tmp_path))
    contract_document = json.loads(CONTRACT.read_bytes())

    assert hashlib.sha256(CONTRACT.read_bytes()).hexdigest() == (
        GITLEAKS_ADVERSARIAL_CONTRACT_SHA256
    )
    assert hashlib.sha256(MANIFEST.read_bytes()).hexdigest() == (
        GITLEAKS_ADVERSARIAL_MANIFEST_SHA256
    )
    assert manifest.corpus_digest == GITLEAKS_ADVERSARIAL_CORPUS_DIGEST
    assert adversarial_corpus_digest(manifest.cases) == manifest.corpus_digest
    assert contract_document["scanner"] == {"id": "gitleaks", "version": "8.30.1"}
    assert contract_document["binding_digest"] == GITLEAKS_BINDING_DIGEST
    assert contract_document["baseline"] == {
        "commit": GITLEAKS_F3B_BASELINE_COMMIT,
        "report_sha256": GITLEAKS_F3B_BASELINE_SHA256,
        "tag": GITLEAKS_F3B_BASELINE_TAG,
    }
    assert (
        hashlib.sha256((ROOT / GITLEAKS_F3B_BASELINE_PATH).read_bytes()).hexdigest()
        == GITLEAKS_F3B_BASELINE_SHA256
    )


@pytest.mark.parametrize("mutation", ("missing", "modified", "symlink"))
def test_frozen_f3b_baseline_mutations_fail_closed(tmp_path: Path, mutation: str) -> None:
    root = _copy_checkpoint(tmp_path)
    baseline = root / GITLEAKS_F3B_BASELINE_PATH
    if mutation == "missing":
        baseline.unlink()
    elif mutation == "modified":
        baseline.write_bytes(b"modified historical evidence\n")
    else:
        target = tmp_path / "baseline-target.json"
        shutil.copy2(ROOT / GITLEAKS_F3B_BASELINE_PATH, target)
        baseline.unlink()
        baseline.symlink_to(target)

    with pytest.raises(ValueError, match="F3B baseline is invalid"):
        verify_gitleaks_adversarial(root)


def test_correct_frozen_f3b_baseline_succeeds(tmp_path: Path) -> None:
    root = _copy_checkpoint(tmp_path)

    manifest = verify_gitleaks_adversarial(root)

    assert len(manifest.cases) == GITLEAKS_ADVERSARIAL_CASE_COUNT
    assert (
        hashlib.sha256((root / GITLEAKS_F3B_BASELINE_PATH).read_bytes()).hexdigest()
        == GITLEAKS_F3B_BASELINE_SHA256
    )


def test_f3b_baseline_replacement_between_lstat_and_open_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _copy_checkpoint(tmp_path)
    baseline = root / GITLEAKS_F3B_BASELINE_PATH
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(b"replacement historical evidence\n")
    real_open = adversarial.os.open
    replaced = False

    def replace_before_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal replaced
        if not replaced and Path(path) == baseline:
            replaced = True
            baseline.unlink()
            baseline.symlink_to(replacement)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(adversarial.os, "open", replace_before_open)

    with pytest.raises(ValueError, match="^Gitleaks F3B baseline is invalid$"):
        verify_gitleaks_adversarial(root)
    assert replaced is True


def test_exact_case_accounting_and_characterization_vocabulary() -> None:
    cases = load_gitleaks_adversarial_contract(CONTRACT)
    counts = Counter(case.expectation for case in cases)
    mechanisms = Counter(case.mechanism for case in cases)

    assert len(cases) == GITLEAKS_ADVERSARIAL_CASE_COUNT == 13
    assert tuple(case.case_id for case in cases) == tuple(sorted(case.case_id for case in cases))
    assert counts == Counter(
        {
            GitleaksAdversarialExpectation.EXPECTED_ABSENT: 8,
            GitleaksAdversarialExpectation.EXPECTED_OBSERVED: 5,
        }
    )
    assert mechanisms == Counter(
        {
            GitleaksAdversarialMechanism.CONTROL: 2,
            GitleaksAdversarialMechanism.DIRECTORY_EMPTY_FILE_SKIP: 2,
            GitleaksAdversarialMechanism.GLOBAL_PATH_ALLOWLIST: 2,
            GitleaksAdversarialMechanism.PATH_ONLY_DETECTION: 3,
            GitleaksAdversarialMechanism.PATH_PATTERN_BOUNDARY: 1,
            GitleaksAdversarialMechanism.RULE_ENTROPY: 1,
            GitleaksAdversarialMechanism.RULE_STOPWORD: 2,
        }
    )
    assert all(case.expected_rule_id for case in cases)
    assert all(isinstance(case.expected_detection_kind, GitleaksDetectionKind) for case in cases)
    serialized = CONTRACT.read_text(encoding="utf-8") + MANIFEST.read_text(encoding="utf-8")
    assert not any(term in serialized for term in ('"precision"', '"recall"', '"f1"'))
    assert "scanner_result" not in serialized


def test_generic_recipes_statically_isolate_stopword_entropy_and_control() -> None:
    values = {}
    for case_id in (
        "generic-stopword-alpha-lower",
        "generic-stopword-alpha-mixed",
        "generic-high-entropy-control",
        "generic-low-entropy",
    ):
        payload = (ROOT / "benchmarks/gitleaks" / _case(case_id).relative_path).read_bytes()
        match = adversarial._GENERIC_ASSIGNMENT.search(payload)
        assert match is not None
        values[case_id] = match.group(1)

    assert b"alpha" in values["generic-stopword-alpha-lower"].lower()
    assert b"alpha" in values["generic-stopword-alpha-mixed"].lower()
    assert shannon_entropy(values["generic-stopword-alpha-lower"]) >= 3.5
    assert shannon_entropy(values["generic-stopword-alpha-mixed"]) >= 3.5
    assert values["generic-high-entropy-control"] == b"Q7vN2xK9mR4tP6wZ"
    assert b"alpha" not in values["generic-high-entropy-control"].lower()
    assert shannon_entropy(values["generic-high-entropy-control"]) >= 3.5
    assert values["generic-low-entropy"] == b"A1A1A1A1A1A1A1A1"
    assert not values["generic-low-entropy"].isalpha()
    assert shannon_entropy(values["generic-low-entropy"]) < 3.5
    assert math.isclose(shannon_entropy(b"abab"), 1.0)


def test_pkcs12_and_global_allowlist_static_boundaries() -> None:
    assert adversarial._PKCS12_PATH.search("adversarial-corpus/pkcs12-file/zero-byte.p12")
    assert adversarial._PKCS12_PATH.search("adversarial-corpus/pkcs12-file/zero-byte.pfx")
    assert adversarial._PKCS12_PATH.search("adversarial-corpus/pkcs12-file/uppercase.P12")
    assert not adversarial._PKCS12_PATH.search("adversarial-corpus/pkcs12-file/not-pkcs12.p12.txt")
    assert (CORPUS / "pkcs12-file/zero-byte.p12").stat().st_size == 0
    assert (CORPUS / "pkcs12-file/zero-byte.pfx").stat().st_size == 0
    for name in ("one-byte.p12", "one-byte.pfx", "uppercase.P12", "not-pkcs12.p12.txt"):
        assert (CORPUS / "pkcs12-file" / name).read_bytes() == b"x"

    node = _case("global-node-modules").relative_path
    vendor = _case("global-vendor-github").relative_path
    docs = _case("global-docs-control").relative_path
    assert adversarial._NODE_MODULES_PATH.search(node)
    assert adversarial._VENDOR_GITHUB_PATH.search(vendor)
    assert not adversarial._NODE_MODULES_PATH.search(docs)
    assert not adversarial._VENDOR_GITHUB_PATH.search(docs)


@pytest.mark.parametrize("mutation", ("missing", "extra", "content", "file-symlink"))
def test_corpus_mutations_fail_closed(tmp_path: Path, mutation: str) -> None:
    root = _copy_checkpoint(tmp_path)
    fixture = root / "benchmarks/gitleaks/adversarial-corpus/pkcs12-file/one-byte.p12"
    if mutation == "missing":
        fixture.unlink()
    elif mutation == "extra":
        (fixture.parent / "extra.txt").write_text("extra", encoding="utf-8")
    elif mutation == "content":
        fixture.write_bytes(b"y")
    else:
        target = tmp_path / "outside"
        target.write_bytes(b"x")
        fixture.unlink()
        fixture.symlink_to(target)

    with pytest.raises(ValueError):
        verify_gitleaks_adversarial(root)


@pytest.mark.parametrize("component", ("root", "intermediate"))
def test_symlinked_corpus_directory_fails_closed(tmp_path: Path, component: str) -> None:
    root = _copy_checkpoint(tmp_path)
    corpus = root / "benchmarks/gitleaks/adversarial-corpus"
    if component == "root":
        real = tmp_path / "real-corpus"
        corpus.rename(real)
        corpus.symlink_to(real, target_is_directory=True)
    else:
        generic = corpus / "generic-api-key"
        real = tmp_path / "real-generic"
        generic.rename(real)
        generic.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValueError):
        verify_gitleaks_adversarial(root)


@pytest.mark.parametrize("invalid", ("duplicate", "nonfinite", "noncanonical"))
def test_json_contract_failures_are_closed(tmp_path: Path, invalid: str) -> None:
    path = tmp_path / "contract.json"
    payload = CONTRACT.read_text(encoding="utf-8")
    if invalid == "duplicate":
        payload = payload.replace("{", '{"schema_version":"duplicate",', 1)
    elif invalid == "nonfinite":
        payload = payload[:-2] + ',"invalid":NaN}\n'
    else:
        payload = json.dumps(json.loads(payload), indent=2, sort_keys=True) + "\n"
    path.write_text(payload, encoding="utf-8")

    with pytest.raises(ValueError):
        load_gitleaks_adversarial_contract(path)


def test_manifest_dataclasses_reject_duplicate_identity_and_bad_digest() -> None:
    manifest = load_gitleaks_adversarial_manifest(MANIFEST)
    with pytest.raises(ValueError):
        replace(manifest, cases=(manifest.cases[0], *manifest.cases[:-1]))
    with pytest.raises(ValueError):
        replace(manifest, corpus_digest="A" * 64)


@pytest.mark.parametrize("entry_kind", ("regular", "directory", "valid-symlink", "broken-symlink"))
def test_any_preexisting_f4_result_entry_fails_closed(tmp_path: Path, entry_kind: str) -> None:
    root = _copy_checkpoint(tmp_path)
    result = root / GITLEAKS_ADVERSARIAL_RESULT_PATH
    if entry_kind == "regular":
        result.write_bytes(b"not F4 evidence\n")
    elif entry_kind == "directory":
        result.mkdir()
    elif entry_kind == "valid-symlink":
        target = tmp_path / "result-target.json"
        target.write_bytes(b"not F4 evidence\n")
        result.symlink_to(target)
    else:
        result.symlink_to(tmp_path / "missing-result-target.json")

    with pytest.raises(ValueError, match="result must not exist"):
        verify_gitleaks_adversarial(root)


def test_f4a_has_no_result_artifact_or_scanner_execution_surface(tmp_path: Path) -> None:
    checkpoint = _copy_checkpoint(tmp_path)
    with pytest.raises(FileNotFoundError):
        (checkpoint / GITLEAKS_ADVERSARIAL_RESULT_PATH).lstat()
    source = (ROOT / "src/securescan/benchmarks/gitleaks_adversarial.py").read_text(
        encoding="utf-8"
    )
    assert "subprocess" not in source
    assert "gitleaks dir" not in source
    assert "def precision" not in source
    assert "def recall" not in source
    assert "def f1" not in source.lower()

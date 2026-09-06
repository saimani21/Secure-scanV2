from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from securescan.benchmarks.checkov_s3 import (
    CHECKOV_BINDING_ARTIFACT_SHA256,
    CHECKOV_CONTROLLED_REPORT_SHA256,
    CHECKOV_CORPUS_DIGEST,
    CHECKOV_CORPUS_MANIFEST_SHA256,
    CHECKOV_TOOLCHAIN_ARTIFACT_SHA256,
    CheckovBenchmarkError,
    _canonical_json,
    _verify_corpus,
    _write_exclusive,
    build_controlled_checkov_report,
    verify_frozen_checkov_evidence,
)

ROOT = Path(__file__).resolve().parents[1]


def test_frozen_artifact_identities() -> None:
    artifacts = (
        ("binding-v1.json", CHECKOV_BINDING_ARTIFACT_SHA256),
        ("controlled-corpus-manifest-v1.json", CHECKOV_CORPUS_MANIFEST_SHA256),
        ("controlled-evaluation-v1.json", CHECKOV_CONTROLLED_REPORT_SHA256),
        ("toolchain-characterization-v1.json", CHECKOV_TOOLCHAIN_ARTIFACT_SHA256),
    )
    for name, expected in artifacts:
        payload = (ROOT / "benchmarks" / "checkov" / name).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == expected
    assert CHECKOV_CORPUS_DIGEST == (
        "be2c1fb0760329d1923f851e17e926d471ca9dd403eba7072ef7d227a09aaca6"
    )


def test_frozen_evidence_and_controlled_report_replay() -> None:
    verify_frozen_checkov_evidence(ROOT)
    generated = _canonical_json(build_controlled_checkov_report(ROOT))
    recorded = (ROOT / "benchmarks" / "checkov" / "controlled-evaluation-v1.json").read_bytes()
    assert generated == recorded


def test_second_hash_locked_environment_reproduces_normalized_report() -> None:
    raw = os.environ.get("SECURESCAN_CHECKOV_SECOND_EXECUTABLE")
    if raw is None:
        pytest.skip("second explicitly prepared Checkov environment not supplied")
    second = Path(raw).resolve()
    first = (ROOT / ".venv-checkov-3.3.16/bin/checkov").resolve()
    assert hashlib.sha256(first.read_bytes()).hexdigest() != hashlib.sha256(
        second.read_bytes()
    ).hexdigest()
    assert _canonical_json(
        build_controlled_checkov_report(ROOT, executable_path=second)
    ) == _canonical_json(build_controlled_checkov_report(ROOT, executable_path=first))


def test_toolchain_characterization_records_path_independence() -> None:
    data = json.loads(
        (ROOT / "benchmarks/checkov/toolchain-characterization-v1.json").read_text()
    )
    assert data["distribution_count"] == 97
    assert data["distribution_inventory_sha256"]["identical"] is True
    assert data["launcher"] == {
        "environment_a_sha256": (
            "19cb67582327e8faebb1bb99f129c6879f58bacc693cc70ff52197ebe976d0d5"
        ),
        "environment_b_sha256": (
            "fdb4ef1de1b5dcff8a99ffcb3645491981dbcad2bb1c978a1b20198a9c793f70"
        ),
        "hashes_differ": True,
        "normalized_template_sha256": (
            "51a09ff89b7771a501ab20498ee396369185f5781eedae24fe9940410fa135b4"
        ),
        "path_dependent": True,
        "universal_identity": False,
    }
    assert data["normalized_controlled_report"]["identical"] is True


def test_controlled_report_has_five_relations_and_expected_accounting() -> None:
    report = json.loads(
        (ROOT / "benchmarks" / "checkov" / "controlled-evaluation-v1.json").read_text()
    )
    assert len(report["controlled_relations"]) == 5
    assert all(item["failed_observed"] for item in report["controlled_relations"])
    assert all(item["passed_observed"] for item in report["controlled_relations"])
    result = report["normalized_result"]
    assert result["observation_count"] == 74
    assert len(result["findings"]) == 74
    assert len(result["suppressions"]) == 1
    assert len(result["gaps"]) == 1
    assert sum(item["passed_count"] for item in result["framework_outcomes"]) == 236
    assert result["suppressions"][0]["reason"] == "controlled accepted risk"
    assert result["gaps"][0]["code"] == "CHECKOV_PARSE_GAP"
    assert report["authority_boundary"]["excluded_check_observations"] == 0
    assert report["authority_boundary"]["unrelated_configuration_control_observed"] == {
        "check_id": "CKV_AWS_18",
        "path": "terraform/authority-secret/main.tf",
        "resource": "aws_s3_bucket.authority_control",
    }


def test_recorded_evidence_contains_no_raw_or_host_sensitive_payload() -> None:
    payload = (ROOT / "benchmarks" / "checkov" / "controlled-evaluation-v1.json").read_bytes()
    assert b"/home/" not in payload
    assert b"RAW_SECRET" not in payload
    assert b"results_configuration" not in payload
    assert b'"code_block":' not in payload
    assert b'"evaluations":' not in payload
    assert b'"connected_node":' not in payload


def test_modified_corpus_fails_integrity(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    source = ROOT / "benchmarks" / "checkov"
    destination = root / "benchmarks" / "checkov"
    destination.mkdir(parents=True)
    (destination / "controlled-corpus-manifest-v1.json").write_bytes(
        (source / "controlled-corpus-manifest-v1.json").read_bytes()
    )
    for item in (source / "corpus").rglob("*"):
        if item.is_file():
            target = destination / "corpus" / item.relative_to(source / "corpus")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(item.read_bytes())
    (destination / "corpus" / "terraform" / "fail" / "main.tf").write_text("changed")
    with pytest.raises(CheckovBenchmarkError):
        _verify_corpus(root)


def test_atomic_writer_writes_exact_bytes_once(tmp_path: Path) -> None:
    destination = tmp_path / "evidence.json"
    _write_exclusive(destination, b'{"complete":true}\n')
    assert destination.read_bytes() == b'{"complete":true}\n'


def test_atomic_writer_permits_exact_zero_length_payload(tmp_path: Path) -> None:
    destination = tmp_path / "evidence.json"
    _write_exclusive(destination, b"")
    assert destination.read_bytes() == b""


def test_atomic_writer_handles_zero_and_partial_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "evidence.json"
    real_write = os.write

    def partial_write(descriptor: int, payload: bytes) -> int:
        return real_write(descriptor, payload[: max(1, len(payload) // 3)])

    monkeypatch.setattr(os, "write", partial_write)
    _write_exclusive(destination, b"0123456789abcdef")
    assert destination.read_bytes() == b"0123456789abcdef"


@pytest.mark.parametrize("entry_kind", ["file", "directory", "symlink"])
def test_atomic_writer_preserves_every_existing_entry(tmp_path: Path, entry_kind: str) -> None:
    destination = tmp_path / "evidence.json"
    if entry_kind == "file":
        destination.write_bytes(b"existing")
    elif entry_kind == "directory":
        destination.mkdir()
    else:
        destination.symlink_to(tmp_path / "missing-target")
    before = destination.lstat()
    with pytest.raises(CheckovBenchmarkError):
        _write_exclusive(destination, b"replacement")
    after = destination.lstat()
    assert (before.st_mode, before.st_ino) == (after.st_mode, after.st_ino)
    if entry_kind == "file":
        assert destination.read_bytes() == b"existing"


def test_atomic_writer_concurrent_creator_wins_without_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "evidence.json"
    real_link = os.link

    def racing_link(source: Path, target: Path, *, follow_symlinks: bool = True) -> None:
        Path(target).write_bytes(b"concurrent")
        real_link(source, target, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "link", racing_link)
    with pytest.raises(CheckovBenchmarkError):
        _write_exclusive(destination, b"ours")
    assert destination.read_bytes() == b"concurrent"
    assert not list(tmp_path.glob(".evidence.json.*"))


def test_atomic_writer_failure_leaves_no_final_or_staging_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "evidence.json"

    def failed_write(_descriptor: int, _payload: bytes) -> int:
        raise OSError

    monkeypatch.setattr(os, "write", failed_write)
    with pytest.raises(CheckovBenchmarkError):
        _write_exclusive(destination, b"payload")
    assert not os.path.lexists(destination)
    assert not list(tmp_path.glob(".evidence.json.*"))


@pytest.mark.parametrize("failure_call", [1, 2])
def test_atomic_writer_fsync_failure_leaves_no_final_or_staging_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_call: int
) -> None:
    destination = tmp_path / "evidence.json"
    real_fsync = os.fsync
    calls = 0

    def failed_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == failure_call:
            raise OSError
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", failed_fsync)
    with pytest.raises(CheckovBenchmarkError):
        _write_exclusive(destination, b"payload")
    assert not os.path.lexists(destination)
    assert not list(tmp_path.glob(".evidence.json.*"))

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from securescan.benchmarks.unified_evidence_s4 import (
    CONTROLLED_REPORT_PATH,
    CONTROLLED_REPORT_SHA256,
    UnifiedEvidenceBenchmarkError,
    build_controlled_artifact,
    build_controlled_unified_report,
    main,
)
from securescan.evidence import EvidenceAuthority, FindingCategory, PackageSubject

ROOT = Path(__file__).resolve().parents[1]


def test_recorded_controlled_artifact_replays_byte_for_byte() -> None:
    expected = (ROOT / CONTROLLED_REPORT_PATH).read_bytes()
    first = build_controlled_artifact(ROOT)
    second = build_controlled_artifact(ROOT)
    assert first == second == expected
    assert hashlib.sha256(expected).hexdigest() == CONTROLLED_REPORT_SHA256
    assert main(["check"]) == 0


def test_controlled_report_contains_each_authority_and_required_counts() -> None:
    report = build_controlled_unified_report(ROOT)
    assert {item.category for item in report.findings} == set(FindingCategory)
    assert {item.authority for item in report.evidence} == {
        EvidenceAuthority.SEMGREP,
        EvidenceAuthority.GITLEAKS,
        EvidenceAuthority.SYFT,
        EvidenceAuthority.OSV,
        EvidenceAuthority.CHECKOV,
    }
    assert {
        "components": len(report.components),
        "evidence": len(report.evidence),
        "findings": len(report.findings),
        "suppressions": len(report.suppressions),
        "gaps": len(report.gaps),
        "coverage_outcomes": len(report.coverage_outcomes),
    } == {
        "components": 1,
        "evidence": 6,
        "findings": 4,
        "suppressions": 1,
        "gaps": 1,
        "coverage_outcomes": 9,
    }


def test_controlled_report_carries_artifact_and_producer_consumer_provenance() -> None:
    report = build_controlled_unified_report(ROOT)
    semgrep = next(item for item in report.evidence if item.authority is EvidenceAuthority.SEMGREP)
    artifact = semgrep.provenance.sanitized_artifact  # type: ignore[union-attr]
    assert artifact.sanitized is True
    assert artifact.artifact_kind == "sanitized_native_report"
    assert artifact.media_type == "application/json"

    osv_finding = next(item for item in report.findings if isinstance(item.subject, PackageSubject))
    syft = next(
        item for item in report.evidence if item.evidence_id in osv_finding.supporting_evidence_refs
    )
    osv = next(
        item for item in report.evidence if item.evidence_id in osv_finding.primary_evidence_refs
    )
    assert syft.component_refs == (osv_finding.subject.component_ref,)
    assert syft.provenance.projection_id == osv.provenance.projection_id  # type: ignore[union-attr]
    assert syft.provenance.projection_digest == osv.provenance.snapshot_digest  # type: ignore[union-attr]
    assert syft.provenance.binding_digest == osv.provenance.syft_binding_digest  # type: ignore[union-attr]


def test_controlled_replay_has_no_process_or_network_side_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external side effect attempted")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert build_controlled_unified_report(ROOT).findings


def test_frozen_input_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    for relative in (
        "benchmarks/python_sast/initial-v0.3e-baseline.json",
        "benchmarks/gitleaks/realworld/realworld-result-v1.json",
        "benchmarks/syft/controlled-s1-evidence.json",
        "benchmarks/osv/controlled-evaluation-v1.json",
        "benchmarks/checkov/controlled-evaluation-v1.json",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    target = tmp_path / "benchmarks/syft/controlled-s1-evidence.json"
    target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(UnifiedEvidenceBenchmarkError):
        build_controlled_artifact(tmp_path)


def test_report_mode_does_not_modify_recorded_artifact(capsysbinary) -> None:
    path = ROOT / CONTROLLED_REPORT_PATH
    before = path.read_bytes()
    before_stat = path.stat()
    assert main(["report"]) == 0
    assert capsysbinary.readouterr().out == before
    assert path.read_bytes() == before
    assert path.stat().st_mtime_ns == before_stat.st_mtime_ns


def test_record_mode_refuses_to_overwrite_existing_artifact() -> None:
    assert os.path.lexists(ROOT / CONTROLLED_REPORT_PATH)
    with pytest.raises(UnifiedEvidenceBenchmarkError):
        main(["record"])


def test_controlled_artifact_contains_no_private_or_raw_scanner_material() -> None:
    payload = (ROOT / CONTROLLED_REPORT_PATH).read_bytes().lower()
    forbidden = (
        b"ghp_",
        b"raw_secret",
        b'"match"',
        b'"secret"',
        b"code_block",
        b"variable_evaluation",
        b"connected_node",
        b"stdout",
        b"stderr",
        b"raw_json",
        b"/home/",
        b"/tmp/",
    )
    assert all(value not in payload for value in forbidden)

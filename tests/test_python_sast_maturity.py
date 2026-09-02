from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

import securescan.benchmarks.python_sast_maturity as maturity_module
from securescan.benchmarks.python_sast_maturity import (
    BASELINE_COMMIT,
    BASELINE_TAG,
    FROZEN_FILE_SHA256,
    MaturityEvidenceError,
    build_maturity_decision,
    canonical_document,
    load_frozen_evidence,
    render_markdown,
    verify_baseline,
    write_artifacts,
)
from securescan.source.enums import AnalysisCapability, SourceSupportState

ROOT = Path(__file__).parent.parent


@pytest.fixture(scope="module")
def decision() -> dict[str, object]:
    return build_maturity_decision(ROOT)


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {item for nested in value.values() for item in _all_keys(nested)}
    if isinstance(value, list):
        return {item for nested in value for item in _all_keys(nested)}
    return set()


def _all_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _all_strings(nested)]
    if isinstance(value, list):
        return [item for nested in value for item in _all_strings(nested)]
    return []


def test_exact_f2e5_baseline_tag_and_ancestry() -> None:
    assert BASELINE_TAG == "source-v0.3F2E5-python-sast-realworld-evaluation-v2"
    assert BASELINE_COMMIT == "a3bf97fdb933e354f7b74231ba27b2d4cd6da3db"
    assert maturity_module._git_text(
        ROOT, "rev-parse", f"{BASELINE_TAG}^{{commit}}"
    ) == BASELINE_COMMIT
    assert maturity_module._git_is_ancestor(ROOT, BASELINE_COMMIT)
    verify_baseline(ROOT)


def test_wrong_baseline_resolution_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def hostile_git_text(_root: Path, *arguments: str) -> str:
        if arguments == ("branch", "--show-current"):
            return "source/v0.3-semgrep"
        return "0" * 40

    monkeypatch.setattr(maturity_module, "_git_text", hostile_git_text)
    monkeypatch.setattr(
        maturity_module,
        "_git_is_ancestor",
        lambda *_arguments: pytest.fail("ancestry must not run for a wrong tag target"),
    )
    with pytest.raises(MaturityEvidenceError, match="baseline binding is invalid"):
        verify_baseline(ROOT)


def test_nonancestor_head_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def frozen_git_text(_root: Path, *arguments: str) -> str:
        if arguments == ("branch", "--show-current"):
            return "source/v0.3-semgrep"
        return BASELINE_COMMIT

    monkeypatch.setattr(maturity_module, "_git_text", frozen_git_text)
    monkeypatch.setattr(maturity_module, "_git_is_ancestor", lambda *_arguments: False)
    with pytest.raises(MaturityEvidenceError, match="baseline binding is invalid"):
        verify_baseline(ROOT)


@pytest.mark.parametrize("relative_path", tuple(FROZEN_FILE_SHA256))
def test_every_frozen_file_identity_mismatch_fails_closed(
    relative_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = maturity_module._file_digest

    def hostile_digest(path: Path) -> str:
        return "0" * 64 if path == ROOT / relative_path else original(path)

    monkeypatch.setattr(maturity_module, "_file_digest", hostile_digest)
    with pytest.raises(MaturityEvidenceError, match="frozen evidence identity changed"):
        load_frozen_evidence(ROOT)


def test_generator_invokes_only_controlled_git_subprocesses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = maturity_module.subprocess.run
    commands: list[tuple[str, ...]] = []

    def guarded_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(tuple(arguments))
        assert arguments[0] == "git"
        return original(arguments, **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(maturity_module.subprocess, "run", guarded_run)
    build_maturity_decision(ROOT)
    assert commands
    assert all(command[0] == "git" and "semgrep" not in command for command in commands)


def test_generator_does_not_mutate_frozen_evidence() -> None:
    before = {
        relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        for relative in FROZEN_FILE_SHA256
    }
    build_maturity_decision(ROOT)
    after = {
        relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        for relative in FROZEN_FILE_SHA256
    }
    assert before == FROZEN_FILE_SHA256
    assert after == before


def test_all_17_rules_are_accounted_with_required_fields(
    decision: dict[str, object],
) -> None:
    matrix = decision["rule_evidence_matrix"]
    assert isinstance(matrix, list)
    assert len(matrix) == 17
    assert len({item["rule_id"] for item in matrix}) == 17
    required = {
        "rule_id",
        "cwes",
        "claim_class",
        "production_status",
        "f1_local_positive_evidence_count",
        "f1_local_negative_evidence_count",
        "external_synthetic_positive_evidence_count",
        "external_synthetic_negative_evidence_count",
        "realworld_applicable_cve_count",
        "realworld_discrimination_evidence",
        "known_semantic_limitations",
        "evidence_strength",
    }
    assert all(set(item) == required for item in matrix)
    assert all(item["f1_local_positive_evidence_count"] == 3 for item in matrix)
    assert all(item["f1_local_negative_evidence_count"] == 3 for item in matrix)


def test_coverage_and_evidence_strength_are_conservative(
    decision: dict[str, object],
) -> None:
    coverage = decision["coverage_summary"]
    assert coverage["production_rule_count"] == 17
    assert coverage["local_controlled"] == {
        "represented_rules": 17,
        "rules_with_negative_evidence": 17,
        "rules_with_positive_evidence": 17,
        "total_rules": 17,
    }
    assert coverage["external_synthetic"] == {
        "evidence_basis": "FROZEN_HISTORICAL_V1_EXPECTATIONS",
        "rules_with_any_evidence": 10,
        "rules_with_both_positive_and_negative_evidence": 4,
        "rules_with_negative_evidence": 6,
        "rules_with_positive_evidence": 8,
        "total_rules": 17,
    }
    assert coverage["real_world"]["represented_rule_count"] == 4
    assert coverage["real_world"]["unrepresented_rule_count"] == 13
    assert decision["evidence_strength_distribution"] == {
        "CONTROLLED_ONLY": 7,
        "CONTROLLED_PLUS_EXTERNAL": 6,
        "CONTROLLED_PLUS_REAL_WORLD": 4,
    }


def test_exact_frozen_metrics_are_copied_without_promotion(
    decision: dict[str, object],
) -> None:
    evidence = decision["evidence"]
    assert evidence["F1_controlled_local"]["result"] == {
        "f1": "1.0000",
        "fn": 0,
        "fp": 0,
        "precision": "1.0000",
        "recall": "1.0000",
        "tn": 51,
        "tp": 51,
    }
    assert evidence["F2D_external_synthetic"]["result"] == {
        "f1": "1.0000",
        "fn": 0,
        "fp": 0,
        "precision": "1.0000",
        "recall": "1.0000",
        "tn": 179,
        "tp": 400,
    }
    assert evidence["F2E5_corrected_real_world"]["claim_conformance"] == {
        "f1": "1.0000",
        "fn": 0,
        "fp": 0,
        "precision": "1.0000",
        "recall": "1.0000",
        "tn": 3,
        "tp": 11,
    }
    assert decision["maturity"] == SourceSupportState.SCANNABLE.value
    assert decision["maturity"] != SourceSupportState.BENCHMARKED.value


def test_realworld_representation_is_exact(decision: dict[str, object]) -> None:
    realworld = decision["coverage_summary"]["real_world"]
    assert realworld["represented_rules"] == [
        "securescan.python.dangerous-eval",
        "securescan.python.os-system",
        "securescan.python.subprocess-shell-true",
        "securescan.python.unsafe-pickle-load",
    ]
    assert realworld["unrepresented_rule_status"] == (
        "NO_APPLICABLE_REAL_WORLD_EVIDENCE_IN_CURRENT_CORPUS"
    )


def test_supported_and_prohibited_claim_boundaries(decision: dict[str, object]) -> None:
    supported_claims = decision["supported_claims"]
    supported = " ".join(supported_claims)
    prohibited = set(decision["prohibited_claims"])
    f1_claim = next(item for item in supported_claims if item.startswith("All 17 rules"))
    assert "controlled" in f1_claim.casefold()
    assert "project-owned" in f1_claim.casefold()
    assert "independent" not in f1_claim.casefold()
    assert "100% accuracy" not in supported.casefold()
    assert "universal 1.0000 precision or recall" in prohibited
    assert "complete Python SAST coverage" in prohibited
    assert "taint analysis" in prohibited
    assert "interprocedural dataflow analysis" in prohibited
    assert "zero false positives in arbitrary repositories" in prohibited
    assert "zero false negatives in arbitrary repositories" in prohibited


def test_maturity_is_in_defined_project_vocabulary(decision: dict[str, object]) -> None:
    assert decision["capability"] == AnalysisCapability.PYTHON_SAST.value
    assert decision["maturity"] in {item.value for item in SourceSupportState}


def test_generation_is_canonical_and_deterministic() -> None:
    first = build_maturity_decision(ROOT)
    second = build_maturity_decision(ROOT)
    assert canonical_document(first) == canonical_document(second)
    assert render_markdown(first) == render_markdown(second)


def test_recorded_artifacts_match_the_generator(decision: dict[str, object]) -> None:
    assert (
        ROOT / "benchmarks/python_sast/python-sast-maturity-decision-v1.json"
    ).read_bytes() == canonical_document(decision)
    assert (ROOT / "docs/python-sast-maturity-v1.md").read_bytes() == render_markdown(
        decision
    )


def test_artifacts_have_no_timestamps_host_paths_or_mutable_head(
    decision: dict[str, object],
) -> None:
    keys = {item.casefold() for item in _all_keys(decision)}
    assert not keys & {"timestamp", "generated_at", "current_head", "execution_head"}
    strings = _all_strings(decision)
    assert not any(item.startswith("/home/") or item.startswith("/tmp/") for item in strings)
    assert decision["baseline_commit"] == BASELINE_COMMIT


def test_explicit_artifact_recording_is_idempotent_and_protected(
    tmp_path: Path,
) -> None:
    json_path = tmp_path / "decision.json"
    markdown_path = tmp_path / "decision.md"
    assert write_artifacts(json_path, markdown_path, b"json\n", b"markdown\n") is True
    assert write_artifacts(json_path, markdown_path, b"json\n", b"markdown\n") is False
    with pytest.raises(FileExistsError, match="already differs"):
        write_artifacts(json_path, markdown_path, b"changed\n", b"markdown\n")

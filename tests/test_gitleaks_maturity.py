from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

import securescan.benchmarks.gitleaks_maturity as maturity_module
from securescan.benchmarks.gitleaks_maturity import (
    GITLEAKS_F5_BASELINE_COMMIT,
    GITLEAKS_F5C_BASELINE_TAG,
    GITLEAKS_F5D_BASELINE_TAG,
    GITLEAKS_FINAL_CAPABILITY_PATH,
    GITLEAKS_FINAL_CAPABILITY_SCHEMA_VERSION,
    GITLEAKS_FINAL_CAPABILITY_SHA256,
    LIMITATION_STATEMENT,
    SUPPORTED_CLAIM,
    GitleaksCapabilityClaimState,
    GitleaksMaturityEvidenceError,
    build_gitleaks_final_capability,
    canonical_gitleaks_final_capability,
    verify_f5_baseline,
    verify_gitleaks_final_capability,
)

ROOT = Path(__file__).resolve().parents[1]
_FROZEN_EVIDENCE = {
    "benchmarks/gitleaks/gitleaks-binding-v1.json": (
        "8d0e06a802158827bbe685b7970ffa075ae07f6393debbb088c3b9bf29f1bd44"
    ),
    "src/securescan/scanners/gitleaks/config/securescan-gitleaks-v1.toml": (
        "ca699281a4752ca677d7f1c1c22d97d2afca9c169eae28054486d4d95bae7fb4"
    ),
    "src/securescan/scanners/gitleaks/config/securescan-gitleaks-v1.ignore": (
        "c5f2fc626c9cae855bbf0261d37ea80600cb65a270483a2df536a6c1c60e8f85"
    ),
    "benchmarks/gitleaks/initial-v0.4f-baseline.json": (
        "62f9c00f79c659d56490a181de231f0aa3cdca6a418f2ca5a9215f7ed1bbbb34"
    ),
    "benchmarks/gitleaks/adversarial-v1-characterization.json": (
        "0687a8ec0ea9bdc1cb1d7a5c44dea5872b8a3c86cc3903b0d2e972ccef982404"
    ),
    "benchmarks/gitleaks/realworld/acquisition-manifest-v1.json": (
        "3a7f55e43210427974985c4e4009a1027fc4db12f3d94e119b490df8f0fc3b52"
    ),
    "benchmarks/gitleaks/realworld/realworld-result-v1.json": (
        "33062f73834e348492349ce00b509f478ed5509b4b1b40183eba034be3a74313"
    ),
    "benchmarks/gitleaks/realworld/realworld-repeatability-v1.json": (
        "8fde25f35da87d1e9abff97e087bf8bdb77116f622095b08e040278c21332303"
    ),
}

_CLAIMS_BY_STATE = {
    "SUPPORTED": {
        "current-snapshot-secret-detection",
        "repository-wide-applicability-planning",
        "sanitized-content-findings",
        "validated-path-only-pkcs12-findings",
        "deterministic-structural-finding-identity",
        "bounded-execution",
        "execution-failure-semantics",
        "fail-closed-parser",
        "exact-immutable-source-projection-execution",
        "repeatable-structural-observations-on-frozen-f5-snapshots",
        "no-raw-secret-persistence",
        "canonical-evidence-generation",
    },
    "LIMITED": {
        "detector-coverage",
        "generic-api-key-detection",
        "pkcs12-directory-detection",
        "repository-byte-coverage",
        "interpretation-of-real-world-findings",
        "real-world-generalization",
        "benchmark-accuracy-scope",
        "network-isolation-assurance",
        "link-fragment-output-compatibility",
    },
    "NOT_SUPPORTED": {
        "git-history-scanning",
        "live-credential-validation",
        "provider-api-validation",
        "exploitability-analysis",
        "credential-reachability-analysis",
        "universal-secret-detection",
        "zero-false-negatives",
        "universal-precision-recall",
        "remote-repository-acquisition-as-scanner-feature",
        "cross-tool-correlation",
        "automatic-lifecycle-deduplication",
        "secret-rotation-tracking",
        "dynamic-runtime-validation",
    },
}


@pytest.fixture(scope="module")
def decision() -> dict[str, object]:
    return build_gitleaks_final_capability(ROOT)


def _digests() -> dict[str, str]:
    return {
        relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        for relative in _FROZEN_EVIDENCE
    }


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | set().union(*(_all_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value)) if value else set()
    return set()


def _all_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _all_strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _all_strings(child)]
    return []


def test_f5c_and_f5d_tags_resolve_to_exact_frozen_commit_and_are_ancestral() -> None:
    assert GITLEAKS_F5_BASELINE_COMMIT == "ce577fdb882b5e33578b28f467dcfce4b06f4404"
    assert maturity_module._git_text(
        ROOT, "rev-parse", f"{GITLEAKS_F5C_BASELINE_TAG}^{{commit}}"
    ) == GITLEAKS_F5_BASELINE_COMMIT
    assert maturity_module._git_text(
        ROOT, "rev-parse", f"{GITLEAKS_F5D_BASELINE_TAG}^{{commit}}"
    ) == GITLEAKS_F5_BASELINE_COMMIT
    assert maturity_module._git_is_ancestor(ROOT, GITLEAKS_F5_BASELINE_COMMIT)
    verify_f5_baseline(ROOT)


def test_wrong_f5_tag_resolution_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def hostile_git_text(_root: Path, *arguments: str) -> str:
        if arguments == ("branch", "--show-current"):
            return "source/v0.3-semgrep"
        return "0" * 40

    monkeypatch.setattr(maturity_module, "_git_text", hostile_git_text)
    monkeypatch.setattr(
        maturity_module,
        "_git_is_ancestor",
        lambda *_arguments: pytest.fail("ancestry must not run after wrong tag resolution"),
    )
    with pytest.raises(GitleaksMaturityEvidenceError):
        verify_f5_baseline(ROOT)


def test_divergent_f5_history_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def frozen_git_text(_root: Path, *arguments: str) -> str:
        if arguments == ("branch", "--show-current"):
            return "source/v0.3-semgrep"
        return GITLEAKS_F5_BASELINE_COMMIT

    monkeypatch.setattr(maturity_module, "_git_text", frozen_git_text)
    monkeypatch.setattr(maturity_module, "_git_is_ancestor", lambda *_arguments: False)
    with pytest.raises(GitleaksMaturityEvidenceError):
        verify_f5_baseline(ROOT)


def test_final_matrix_has_exact_claim_states(decision: dict[str, object]) -> None:
    matrix = decision["claim_matrix"]
    assert isinstance(matrix, list)
    actual = {
        state.value: {
            row["claim_id"] for row in matrix if row["state"] == state.value
        }
        for state in GitleaksCapabilityClaimState
    }
    assert actual == _CLAIMS_BY_STATE
    assert decision["claim_state_counts"] == {
        "SUPPORTED": 12,
        "LIMITED": 9,
        "NOT_SUPPORTED": 13,
    }
    assert all(set(row) == {"boundary", "claim_id", "evidence", "state"} for row in matrix)
    evidence_ids = set(decision["evidence"])
    assert {
        evidence_id for row in matrix for evidence_id in row["evidence"]
    } <= evidence_ids


def test_final_supported_and_limitation_language_is_exact(
    decision: dict[str, object],
) -> None:
    assert decision["supported_claim"] == SUPPORTED_CLAIM
    assert decision["final_limitation"] == LIMITATION_STATEMENT
    assert "current-snapshot" in SUPPORTED_CLAIM
    assert "confidentiality-preserving" in SUPPORTED_CLAIM
    assert "does not claim exhaustive secret detection" in LIMITATION_STATEMENT


def test_maturity_remains_scannable_and_benchmarked_gate_is_explicit(
    decision: dict[str, object],
) -> None:
    assert decision["capability"] == "secret_detection"
    assert decision["maturity"] == "SCANNABLE"
    assert decision["maturity"] != "BENCHMARKED"
    assert decision["target_1_integration_status"] == "COMPLETE"
    maturity = decision["maturity_decision"]
    assert len(maturity["why_not_benchmarked"]) == 6
    assert "broader frozen capability corpus" in maturity[
        "future_benchmarked_requirement"
    ]
    assert maturity["benchmarked_never_means"] == [
        "exhaustive detection",
        "live credential validity",
        "ecosystem-wide accuracy",
        "zero false negatives",
    ]


def test_exact_frozen_evidence_is_reconciled_without_reinterpretation(
    decision: dict[str, object],
) -> None:
    evidence = decision["evidence"]
    assert evidence["F3B"]["metrics"] == {
        "fn": 3,
        "fp": 0,
        "tn": 23,
        "tp": 22,
    }
    assert evidence["F4"] == {
        "evidence_type": "ADVERSARIAL_CHARACTERIZATION",
        "expected_outcome_count": 13,
        "passed_outcome_count": 13,
        "sha256": _FROZEN_EVIDENCE[
            "benchmarks/gitleaks/adversarial-v1-characterization.json"
        ],
    }
    assert evidence["F5B3"]["repositories"] == [
        "charmbracelet/gum",
        "pallets/click",
        "pallets/flask",
        "Quad4-Software/Reticulum-Go",
        "golang/go",
        "SSLMate/go-pkcs12",
    ]
    assert evidence["F5C"]["per_repository_finding_counts"] == [
        0,
        0,
        6,
        8,
        123,
        1,
    ]
    assert evidence["F5C"]["parsed_finding_count"] == 138
    assert evidence["F5C"]["unique_structural_identity_count"] == 138
    assert evidence["F5D"]["missing_from_run2"] == 0
    assert evidence["F5D"]["new_in_run2"] == 0
    assert evidence["F5D"]["canonical_structural_sets_equal"] is True


def test_generator_invokes_only_controlled_git_subprocesses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = subprocess.run
    commands: list[tuple[str, ...]] = []

    def guarded_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(tuple(arguments))
        assert arguments[0] == "git"
        return original(arguments, **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(maturity_module.subprocess, "run", guarded_run)
    build_gitleaks_final_capability(ROOT)
    assert commands
    assert all(command[0] == "git" and "gitleaks" not in command for command in commands)


def test_generator_is_deterministic_safe_and_does_not_mutate_frozen_evidence() -> None:
    before = _digests()
    first = build_gitleaks_final_capability(ROOT)
    second = build_gitleaks_final_capability(ROOT)
    after = _digests()
    assert before == _FROZEN_EVIDENCE
    assert after == before
    assert canonical_gitleaks_final_capability(first) == canonical_gitleaks_final_capability(
        second
    )
    keys = {key.casefold() for key in _all_keys(first)}
    assert not keys & {
        "current_head",
        "execution_head",
        "generated_at",
        "match",
        "secret",
        "stderr_bytes",
        "stdout_bytes",
        "timestamp",
    }
    assert not any(
        value.startswith("/home/") or value.startswith("/tmp/")
        for value in _all_strings(first)
    )


def test_recorded_final_capability_is_exact_canonical_replay(
    decision: dict[str, object],
) -> None:
    payload = (ROOT / GITLEAKS_FINAL_CAPABILITY_PATH).read_bytes()
    assert payload == canonical_gitleaks_final_capability(decision)
    assert hashlib.sha256(payload).hexdigest() == GITLEAKS_FINAL_CAPABILITY_SHA256
    assert verify_gitleaks_final_capability(ROOT) == decision


def test_final_artifact_schema_and_frozen_baseline_are_explicit(
    decision: dict[str, object],
) -> None:
    assert decision["schema_version"] == GITLEAKS_FINAL_CAPABILITY_SCHEMA_VERSION
    assert decision["baseline"] == {
        "commit": GITLEAKS_F5_BASELINE_COMMIT,
        "tags": [GITLEAKS_F5C_BASELINE_TAG, GITLEAKS_F5D_BASELINE_TAG],
    }


def test_current_documentation_closes_target_and_historicalizes_prior_absence() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    benchmark_readme = (ROOT / "benchmarks/gitleaks/README.md").read_text(
        encoding="utf-8"
    )
    realworld_readme = (ROOT / "benchmarks/gitleaks/realworld/README.md").read_text(
        encoding="utf-8"
    )
    status = (ROOT / "docs/source-v1-status.md").read_text(encoding="utf-8")
    combined = "\n".join((readme, benchmark_readme, realworld_readme, status))
    normalized = " ".join(combined.split())
    assert (
        "v0.4F6 | Gitleaks final evidence and maturity reconciliation | "
        "COMPLETE"
    ) in status
    assert "GITLEAKS TARGET-1 INTEGRATION: COMPLETE" in status
    assert "SECRET_DETECTION = SCANNABLE" in combined
    assert "At the F5B3 checkpoint, no real-world result existed." in normalized
    assert "No real-world result artifact exists" not in status

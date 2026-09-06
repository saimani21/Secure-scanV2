from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from contextlib import suppress
from enum import StrEnum
from pathlib import Path
from typing import Final

from securescan.benchmarks.gitleaks_characterization import (
    GITLEAKS_CHARACTERIZATION_SHA256,
    verify_gitleaks_characterization,
)
from securescan.benchmarks.gitleaks_realworld_acquisition import (
    GITLEAKS_REALWORLD_ACQUIRED_MANIFEST_SHA256,
    verify_gitleaks_realworld_acquisition,
)
from securescan.benchmarks.gitleaks_realworld_contract import (
    GITLEAKS_BINDING_ARTIFACT_SHA256,
    GITLEAKS_BINDING_DIGEST,
    GITLEAKS_CONFIG_SHA256,
    GITLEAKS_F3B_REPORT_SHA256,
    GITLEAKS_IGNORE_SHA256,
    GITLEAKS_MATURITY,
    GITLEAKS_SCANNER_ID,
    GITLEAKS_SCANNER_VERSION,
)
from securescan.benchmarks.gitleaks_realworld_evaluation import (
    GITLEAKS_REALWORLD_REPEATABILITY_SHA256,
    GITLEAKS_REALWORLD_RESULT_SHA256,
    GITLEAKS_REALWORLD_RUN2_SHA256,
    verify_gitleaks_realworld_evidence,
)
from securescan.source.enums import AnalysisCapability

GITLEAKS_FINAL_CAPABILITY_SCHEMA_VERSION: Final = (
    "securescan-gitleaks-final-capability-v1"
)
GITLEAKS_FINAL_CAPABILITY_PATH: Final = (
    "benchmarks/gitleaks/final-capability-v1.json"
)
GITLEAKS_F5_BASELINE_COMMIT: Final = "ce577fdb882b5e33578b28f467dcfce4b06f4404"
GITLEAKS_F5C_BASELINE_TAG: Final = "source-v0.4F5C-gitleaks-realworld-execution"
GITLEAKS_F5D_BASELINE_TAG: Final = (
    "source-v0.4F5D-gitleaks-realworld-repeatability"
)
GITLEAKS_EXECUTABLE_SHA256: Final = (
    "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509"
)
GITLEAKS_FINAL_CAPABILITY_SHA256: Final = (
    "44d870d3e787f7c2ccffdcc4c5af2cc06eaaa20533423e1c9e0bdc93c60b895e"
)

_BRANCH: Final = "source/v0.3-semgrep"
_CONTROLLED_GIT_PATH: Final = "/usr/bin:/bin"
_MAX_DOCUMENT_BYTES: Final = 64 * 1024
_F5_REPOSITORIES: Final = (
    "charmbracelet/gum",
    "pallets/click",
    "pallets/flask",
    "Quad4-Software/Reticulum-Go",
    "golang/go",
    "SSLMate/go-pkcs12",
)
_F5_REPOSITORY_IDS: Final = (
    "charmbracelet-gum",
    "pallets-click",
    "pallets-flask",
    "quad4-software-reticulum-go",
    "golang-go",
    "sslmate-go-pkcs12",
)

SUPPORTED_CLAIM: Final = (
    "SecureScan Source v1 provides deterministic, current-snapshot secret detection "
    "through a pinned and verified Gitleaks 8.30.1 integration. Findings are parsed "
    "through a fail-closed confidentiality-preserving boundary and receive stable "
    "structural identities. Controlled benchmark, adversarial, acquisition, and "
    "real-world repeatability evidence are frozen and reproducible."
)
LIMITATION_STATEMENT: Final = (
    "This capability does not claim exhaustive secret detection, Git-history "
    "coverage, credential validity, exploitability, universal detector accuracy, or "
    "inspection of every selected byte. Upstream Gitleaks rules, allowlists, "
    "enumeration behavior, and supported output schema remain material limitations."
)

_WHY_NOT_BENCHMARKED: Final = (
    "F3B measures seven representative detectors only.",
    "F3B contains three documented false negatives.",
    "F4 proves material upstream detector, enumeration, and path-allowlist limitations.",
    "F5 has no complete frozen ground truth and therefore provides no accuracy score.",
    "F5 observed only three rule IDs across the six frozen repositories.",
    "Real-world repeatability proves structural determinism, not accuracy.",
)
_FUTURE_BENCHMARKED_REQUIREMENT: Final = (
    "A future BENCHMARKED state requires a broader frozen capability corpus covering "
    "a representative detector family set with explicit limitation-aware ground "
    "truth and repeatable scoring."
)
_BENCHMARKED_NEVER_MEANS: Final = (
    "exhaustive detection",
    "live credential validity",
    "ecosystem-wide accuracy",
    "zero false negatives",
)


class GitleaksCapabilityClaimState(StrEnum):
    SUPPORTED = "SUPPORTED"
    LIMITED = "LIMITED"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class GitleaksMaturityEvidenceError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Gitleaks final capability evidence is invalid")


def canonical_gitleaks_final_capability(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError):
        raise GitleaksMaturityEvidenceError from None


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_stable_file(path: Path) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_DOCUMENT_BYTES
        ):
            raise OSError
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(
            before
        ):
            raise OSError
        payload = bytearray()
        while len(payload) <= _MAX_DOCUMENT_BYTES:
            chunk = os.read(
                descriptor,
                min(65536, _MAX_DOCUMENT_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        finished = os.fstat(descriptor)
        after = path.lstat()
        if (
            len(payload) > _MAX_DOCUMENT_BYTES
            or len(payload) != before.st_size
            or _stat_identity(finished) != _stat_identity(before)
            or _stat_identity(after) != _stat_identity(before)
        ):
            raise OSError
        return bytes(payload)
    except OSError:
        raise GitleaksMaturityEvidenceError from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _git_text(repository_root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repository_root,
            env={"LC_ALL": "C", "PATH": _CONTROLLED_GIT_PATH},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise GitleaksMaturityEvidenceError from None
    if result.returncode != 0 or not result.stdout:
        raise GitleaksMaturityEvidenceError
    return result.stdout.strip()


def _git_is_ancestor(repository_root: Path, commit: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
            cwd=repository_root,
            env={"LC_ALL": "C", "PATH": _CONTROLLED_GIT_PATH},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise GitleaksMaturityEvidenceError from None
    if result.returncode not in (0, 1):
        raise GitleaksMaturityEvidenceError
    return result.returncode == 0


def verify_f5_baseline(repository_root: Path) -> None:
    if not isinstance(repository_root, Path) or not repository_root.is_absolute():
        raise GitleaksMaturityEvidenceError
    if (
        _git_text(repository_root, "branch", "--show-current") != _BRANCH
        or _git_text(
            repository_root,
            "rev-parse",
            f"{GITLEAKS_F5C_BASELINE_TAG}^{{commit}}",
        )
        != GITLEAKS_F5_BASELINE_COMMIT
        or _git_text(
            repository_root,
            "rev-parse",
            f"{GITLEAKS_F5D_BASELINE_TAG}^{{commit}}",
        )
        != GITLEAKS_F5_BASELINE_COMMIT
        or not _git_is_ancestor(repository_root, GITLEAKS_F5_BASELINE_COMMIT)
    ):
        raise GitleaksMaturityEvidenceError


def _claim(
    claim_id: str,
    state: GitleaksCapabilityClaimState,
    evidence: tuple[str, ...],
    boundary: str,
) -> dict[str, object]:
    return {
        "boundary": boundary,
        "claim_id": claim_id,
        "evidence": list(evidence),
        "state": state.value,
    }


def _claim_matrix() -> list[dict[str, object]]:
    supported = GitleaksCapabilityClaimState.SUPPORTED
    limited = GitleaksCapabilityClaimState.LIMITED
    unsupported = GitleaksCapabilityClaimState.NOT_SUPPORTED
    claims = [
        _claim(
            "current-snapshot-secret-detection",
            supported,
            ("trusted-binding", "F3B", "F5C"),
            "Detection is limited to the exact immutable current-source projection.",
        ),
        _claim(
            "repository-wide-applicability-planning",
            supported,
            ("v0.4D", "F4"),
            "Planning selects the repository-wide Source surface; upstream allowlists "
            "can still exclude selected paths from detector inspection.",
        ),
        _claim(
            "sanitized-content-findings",
            supported,
            ("F3B", "F4", "F5C"),
            "Normalized content observations contain structural fields only.",
        ),
        _claim(
            "validated-path-only-pkcs12-findings",
            supported,
            ("F3B", "F4"),
            "PATH observations identify matching nonempty paths, not validated "
            "credential contents.",
        ),
        _claim(
            "deterministic-structural-finding-identity",
            supported,
            ("v0.4E", "F5D"),
            "Identity uses validated non-secret structural evidence.",
        ),
        _claim(
            "bounded-execution",
            supported,
            ("trusted-binding", "F4"),
            "The frozen process contract bounds time and scanner output.",
        ),
        _claim(
            "execution-failure-semantics",
            supported,
            ("v0.4B", "F4"),
            "Timeout, cancellation, and output-limit outcomes cannot be represented "
            "as clean completed analysis.",
        ),
        _claim(
            "fail-closed-parser",
            supported,
            ("v0.4C", "F4", "F5C"),
            "Malformed, unsupported, or confidentiality-invalid scanner output fails "
            "without normalized findings.",
        ),
        _claim(
            "exact-immutable-source-projection-execution",
            supported,
            ("v0.4B", "F5B3", "F5C"),
            "Execution is bound to a verified immutable Source projection.",
        ),
        _claim(
            "repeatable-structural-observations-on-frozen-f5-snapshots",
            supported,
            ("F5C", "F5D"),
            "Two immediate runs had equal canonical structural sets for every frozen "
            "repository and the aggregate.",
        ),
        _claim(
            "no-raw-secret-persistence",
            supported,
            ("v0.4B", "F3B", "F4", "F5C", "F5D"),
            "Canonical evidence excludes raw scanner streams, Secret, Match, and "
            "secret-derived public identity.",
        ),
        _claim(
            "canonical-evidence-generation",
            supported,
            ("F3B", "F4", "F5B3", "F5C", "F5D"),
            "Frozen JSON evidence is deterministic, canonical, and content-addressed.",
        ),
        _claim(
            "detector-coverage",
            limited,
            ("F3B", "F4", "F5C"),
            "F3B covers seven representative detectors and F5 observed three rule IDs; "
            "neither establishes coverage of every inherited detector.",
        ),
        _claim(
            "generic-api-key-detection",
            limited,
            ("F3B", "F4"),
            "Upstream stopword, allowlist, and entropy behavior can suppress "
            "detector-shaped candidates.",
        ),
        _claim(
            "pkcs12-directory-detection",
            limited,
            ("F3B", "F4"),
            "The upstream directory source skips empty PKCS12 files.",
        ),
        _claim(
            "repository-byte-coverage",
            limited,
            ("F4", "F5C"),
            "Repository-wide selection does not imply inspection of bytes excluded by "
            "inherited Gitleaks path allowlists.",
        ),
        _claim(
            "interpretation-of-real-world-findings",
            limited,
            ("F5C",),
            "The 138 observations are sanitized structural detections without complete "
            "ground truth, credential validation, or exploitability review.",
        ),
        _claim(
            "real-world-generalization",
            limited,
            ("F5B3", "F5C", "F5D"),
            "Evidence covers six frozen repositories and cannot represent all projects "
            "or repository shapes.",
        ),
        _claim(
            "benchmark-accuracy-scope",
            limited,
            ("F3B",),
            "F3B metrics apply only to 48 frozen case/rule relations.",
        ),
        _claim(
            "network-isolation-assurance",
            limited,
            ("trusted-binding", "F5C"),
            "The integration supplies no network-dependent scanner configuration, but "
            "does not claim an operating-system network sandbox.",
        ),
        _claim(
            "link-fragment-output-compatibility",
            limited,
            ("v0.4C", "F5C"),
            "The frozen parser rejects unsupported Link or Fragment fields rather than "
            "silently accepting unmodeled output.",
        ),
        _claim(
            "git-history-scanning",
            unsupported,
            ("trusted-binding",),
            "The frozen binding uses Gitleaks dir mode on the current snapshot only.",
        ),
        _claim(
            "live-credential-validation",
            unsupported,
            ("trusted-binding", "F5C"),
            "No credential is submitted to a provider.",
        ),
        _claim(
            "provider-api-validation",
            unsupported,
            ("trusted-binding", "F5C"),
            "Provider or API validation is outside Source v1.",
        ),
        _claim(
            "exploitability-analysis",
            unsupported,
            ("F3B", "F5C"),
            "A scanner observation is not exploitability evidence.",
        ),
        _claim(
            "credential-reachability-analysis",
            unsupported,
            ("F3B", "F5C"),
            "No control-flow or runtime credential reachability is evaluated.",
        ),
        _claim(
            "universal-secret-detection",
            unsupported,
            ("F3B", "F4"),
            "Representative evidence and documented misses preclude an exhaustive claim.",
        ),
        _claim(
            "zero-false-negatives",
            unsupported,
            ("F3B", "F4"),
            "F3B records three false negatives in its bounded corpus.",
        ),
        _claim(
            "universal-precision-recall",
            unsupported,
            ("F3B", "F5C"),
            "Bounded corpus metrics do not generalize to arbitrary repositories.",
        ),
        _claim(
            "remote-repository-acquisition-as-scanner-feature",
            unsupported,
            ("trusted-binding", "F5B3"),
            "Acquisition is a separate controlled evidence phase, not scanner behavior.",
        ),
        _claim(
            "cross-tool-correlation",
            unsupported,
            ("F3B", "F5C"),
            "This integration does not correlate Gitleaks findings with other tools.",
        ),
        _claim(
            "automatic-lifecycle-deduplication",
            unsupported,
            ("v0.4E", "F5C"),
            "Stable structural identity is not a cross-run lifecycle deduplication policy.",
        ),
        _claim(
            "secret-rotation-tracking",
            unsupported,
            ("F5D",),
            "Two-run repeatability is not credential rotation tracking.",
        ),
        _claim(
            "dynamic-runtime-validation",
            unsupported,
            ("trusted-binding",),
            "Only static current-snapshot source inspection is performed.",
        ),
    ]
    return claims


def _validate_frozen_evidence(
    repository_root: Path,
) -> tuple[object, object, object, object]:
    verify_f5_baseline(repository_root)
    characterization = verify_gitleaks_characterization(repository_root)
    acquisition = verify_gitleaks_realworld_acquisition(repository_root)
    run1, repeatability = verify_gitleaks_realworld_evidence(repository_root)

    categories = {
        row["category"] for row in characterization["characterizations"]  # type: ignore[index]
    }
    repositories = acquisition.get("repository_slots")  # type: ignore[union-attr]
    aggregate = run1.canonical_data()["aggregate"]
    if not isinstance(aggregate, dict):
        raise GitleaksMaturityEvidenceError
    repeatability_aggregate = repeatability.aggregate
    if (
        len(categories) != 6
        or not isinstance(repositories, list)
        or [row.get("repository_id") for row in repositories]
        != list(_F5_REPOSITORY_IDS)
        or [row.get("upstream_url") for row in repositories]
        != [f"https://github.com/{repository}" for repository in _F5_REPOSITORIES]
        or aggregate.get("parsed_finding_count") != 138
        or aggregate.get("content_finding_count") != 138
        or aggregate.get("path_finding_count") != 0
        or aggregate.get("unique_structural_finding_count") != 138
        or aggregate.get("duplicate_structural_finding_count") != 0
        or aggregate.get("observed_rule_ids")
        != ["generic-api-key", "private-key", "square-access-token"]
        or repeatability_aggregate.missing_from_run2 != 0
        or repeatability_aggregate.new_in_run2 != 0
        or not repeatability_aggregate.canonical_set_equal
    ):
        raise GitleaksMaturityEvidenceError
    return characterization, acquisition, run1, repeatability


def build_gitleaks_final_capability(repository_root: Path) -> dict[str, object]:
    try:
        _, acquisition, run1, repeatability = _validate_frozen_evidence(repository_root)
    except GitleaksMaturityEvidenceError:
        raise
    except Exception:
        raise GitleaksMaturityEvidenceError from None
    claims = _claim_matrix()
    states = {state.value: 0 for state in GitleaksCapabilityClaimState}
    for claim in claims:
        states[str(claim["state"])] += 1
    repositories = acquisition["repository_slots"]  # type: ignore[index]
    aggregate = run1.canonical_data()["aggregate"]
    if not isinstance(aggregate, dict):
        raise GitleaksMaturityEvidenceError
    return {
        "baseline": {
            "commit": GITLEAKS_F5_BASELINE_COMMIT,
            "tags": [GITLEAKS_F5C_BASELINE_TAG, GITLEAKS_F5D_BASELINE_TAG],
        },
        "capability": AnalysisCapability.SECRET_DETECTION.value,
        "claim_matrix": claims,
        "claim_state_counts": states,
        "evidence": {
            "F3B": {
                "evidence_type": "CONTROLLED_BENCHMARK",
                "false_negative_cases": [
                    "generic-api-key-positive-01",
                    "pkcs12-file-positive-01",
                    "pkcs12-file-positive-02",
                ],
                "metrics": {"fn": 3, "fp": 0, "tn": 23, "tp": 22},
                "relation_count": 48,
                "representative_detector_count": 7,
                "sha256": GITLEAKS_F3B_REPORT_SHA256,
            },
            "F4": {
                "evidence_type": "ADVERSARIAL_CHARACTERIZATION",
                "expected_outcome_count": 13,
                "passed_outcome_count": 13,
                "sha256": GITLEAKS_CHARACTERIZATION_SHA256,
            },
            "F5B3": {
                "evidence_type": "BOUNDED_ACQUISITION_AND_SNAPSHOT_IDENTITY",
                "manifest_sha256": GITLEAKS_REALWORLD_ACQUIRED_MANIFEST_SHA256,
                "repositories": list(_F5_REPOSITORIES),
                "repository_ids": [row["repository_id"] for row in repositories],
                "repository_count": 6,
            },
            "F5C": {
                "content_finding_count": aggregate["content_finding_count"],
                "duplicate_observation_count": aggregate[
                    "duplicate_structural_finding_count"
                ],
                "evidence_type": "REAL_WORLD_OPERATIONAL_OBSERVATION",
                "observed_rule_ids": aggregate["observed_rule_ids"],
                "parsed_finding_count": aggregate["parsed_finding_count"],
                "path_finding_count": aggregate["path_finding_count"],
                "per_repository_finding_counts": [
                    row.parsed_finding_count for row in run1.repositories
                ],
                "sha256": GITLEAKS_REALWORLD_RESULT_SHA256,
                "unique_structural_identity_count": aggregate[
                    "unique_structural_finding_count"
                ],
            },
            "F5D": {
                "canonical_structural_sets_equal": (
                    repeatability.aggregate.canonical_set_equal
                ),
                "evidence_type": "STRUCTURAL_REPEATABILITY",
                "missing_from_run2": repeatability.aggregate.missing_from_run2,
                "new_in_run2": repeatability.aggregate.new_in_run2,
                "repeatability_sha256": GITLEAKS_REALWORLD_REPEATABILITY_SHA256,
                "run2_sha256": GITLEAKS_REALWORLD_RUN2_SHA256,
            },
            "trusted-binding": {
                "binding_artifact_sha256": GITLEAKS_BINDING_ARTIFACT_SHA256,
                "binding_digest": GITLEAKS_BINDING_DIGEST,
                "config_sha256": GITLEAKS_CONFIG_SHA256,
                "executable_sha256": GITLEAKS_EXECUTABLE_SHA256,
                "ignore_sha256": GITLEAKS_IGNORE_SHA256,
                "scanner_id": GITLEAKS_SCANNER_ID,
                "scanner_version": GITLEAKS_SCANNER_VERSION,
            },
            "v0.4B": {
                "evidence_type": "FROZEN_IMPLEMENTATION_AND_REGRESSION_TESTS",
                "subject": "execution lifecycle and bounded process semantics",
            },
            "v0.4C": {
                "evidence_type": "FROZEN_IMPLEMENTATION_AND_REGRESSION_TESTS",
                "subject": "fail-closed confidential parser",
            },
            "v0.4D": {
                "evidence_type": "FROZEN_IMPLEMENTATION_AND_REGRESSION_TESTS",
                "subject": "repository-wide applicability and planning",
            },
            "v0.4E": {
                "evidence_type": "FROZEN_IMPLEMENTATION_AND_REGRESSION_TESTS",
                "subject": "secret-safe structural finding identity",
            },
        },
        "final_limitation": LIMITATION_STATEMENT,
        "maturity": GITLEAKS_MATURITY,
        "maturity_decision": {
            "benchmarked_never_means": list(_BENCHMARKED_NEVER_MEANS),
            "future_benchmarked_requirement": _FUTURE_BENCHMARKED_REQUIREMENT,
            "why_not_benchmarked": list(_WHY_NOT_BENCHMARKED),
        },
        "schema_version": GITLEAKS_FINAL_CAPABILITY_SCHEMA_VERSION,
        "supported_claim": SUPPORTED_CLAIM,
        "target_1_integration_status": "COMPLETE",
    }


def verify_gitleaks_final_capability(repository_root: Path) -> dict[str, object]:
    expected = build_gitleaks_final_capability(repository_root)
    payload = _read_stable_file(repository_root / GITLEAKS_FINAL_CAPABILITY_PATH)
    if (
        hashlib.sha256(payload).hexdigest() != GITLEAKS_FINAL_CAPABILITY_SHA256
        or payload != canonical_gitleaks_final_capability(expected)
    ):
        raise GitleaksMaturityEvidenceError
    return expected

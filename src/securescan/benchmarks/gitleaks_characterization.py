from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import suppress
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final

GITLEAKS_CHARACTERIZATION_SCHEMA_VERSION: Final = (
    "securescan-gitleaks-characterization-v1"
)
GITLEAKS_CHARACTERIZATION_ID: Final = "securescan-gitleaks-v0.4f4-characterization-v1"
GITLEAKS_CHARACTERIZATION_PATH: Final = (
    "benchmarks/gitleaks/adversarial-v1-characterization.json"
)
GITLEAKS_CHARACTERIZATION_SHA256: Final = (
    "0687a8ec0ea9bdc1cb1d7a5c44dea5872b8a3c86cc3903b0d2e972ccef982404"
)

GITLEAKS_F3B_BASELINE_COMMIT: Final = "d183336c129977c4279cd1058bbe060742de0e54"
GITLEAKS_F3B_BASELINE_TAG: Final = "source-v0.4F3B-gitleaks-initial-baseline"
GITLEAKS_F3B_REPORT_PATH: Final = "benchmarks/gitleaks/initial-v0.4f-baseline.json"
GITLEAKS_F3B_REPORT_SHA256: Final = (
    "62f9c00f79c659d56490a181de231f0aa3cdca6a418f2ca5a9215f7ed1bbbb34"
)

GITLEAKS_F4A_BASELINE_COMMIT: Final = "526ce3192885c6fc04ae8b7ac84346466809ca4e"
GITLEAKS_F4A_BASELINE_TAG: Final = "source-v0.4F4A-gitleaks-adversarial-prescan"
GITLEAKS_F4A_CONTRACT_PATH: Final = "benchmarks/gitleaks/adversarial-contract-v1.json"
GITLEAKS_F4A_CONTRACT_SHA256: Final = (
    "968c672093bb13458c7a677ae8e0f5964b1b3c511090afd1c3bf0c73c3233f43"
)
GITLEAKS_F4A_MANIFEST_PATH: Final = "benchmarks/gitleaks/adversarial-manifest-v1.json"
GITLEAKS_F4A_MANIFEST_SHA256: Final = (
    "9866e77db9ecef20fc49817b89b1f7374cb1fe6cce47d85a90ed18b52f7c4c3a"
)
GITLEAKS_F4A_CORPUS_PATH: Final = "benchmarks/gitleaks/adversarial-corpus"
GITLEAKS_F4A_CORPUS_DIGEST: Final = (
    "dfd3ccbcb6537b7de35cc9bce130e9dabd0f72ef5ff0fc1f10ef7a303bf90c22"
)

GITLEAKS_F4B1_BASELINE_COMMIT: Final = "5f8ef71273b7b7dc7818be006c11c3aa3e91d160"
GITLEAKS_F4B1_BASELINE_TAG: Final = "source-v0.4F4B1-gitleaks-adversarial-harness"
GITLEAKS_F4B2_BASELINE_COMMIT: Final = "52b7b71be1636d5d5cf404174ccec7159f2e777e"
GITLEAKS_F4B2_BASELINE_TAG: Final = "source-v0.4F4B2-gitleaks-adversarial-result"
GITLEAKS_F4B2_RESULT_PATH: Final = "benchmarks/gitleaks/adversarial-v1-result.json"
GITLEAKS_F4B2_RESULT_SHA256: Final = (
    "1fb998220f72b40b6274d2562def3327008ed1cc9fca7471b70dbb750c0b2589"
)

GITLEAKS_SCANNER_ID: Final = "gitleaks"
GITLEAKS_SCANNER_VERSION: Final = "8.30.1"
GITLEAKS_BINDING_DIGEST: Final = (
    "8d9f224e1c5ddabef508a26be2966f51dc2a9c2e5805ea3bffcf444b3cae9561"
)
GITLEAKS_MATURITY: Final = "SCANNABLE"

_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_FIXTURE_BYTES = 16 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_CORPUS_STREAM_VERSION = b"securescan-gitleaks-adversarial-corpus-v1\0"
_F4A_CASE_IDS: Final = (
    "generic-high-entropy-control",
    "generic-low-entropy",
    "generic-stopword-alpha-lower",
    "generic-stopword-alpha-mixed",
    "global-docs-control",
    "global-node-modules",
    "global-vendor-github",
    "pkcs12-one-byte-p12",
    "pkcs12-one-byte-pfx",
    "pkcs12-suffix-boundary",
    "pkcs12-uppercase-extension",
    "pkcs12-zero-p12",
    "pkcs12-zero-pfx",
)
_F3B_REQUIRED_CASES: Final = {
    "generic-api-key-positive-01": ("FN", "generic-api-key", "CONTENT"),
    "pkcs12-file-positive-01": ("FN", "pkcs12-file", "PATH"),
    "pkcs12-file-positive-02": ("FN", "pkcs12-file", "PATH"),
}
_F4B2_REQUIRED_CASES: Final = {
    "generic-high-entropy-control": ("EXPECTED_OBSERVED", "CONTROL", 1),
    "generic-low-entropy": ("EXPECTED_ABSENT", "RULE_ENTROPY", 0),
    "generic-stopword-alpha-lower": ("EXPECTED_ABSENT", "RULE_STOPWORD", 0),
    "generic-stopword-alpha-mixed": ("EXPECTED_ABSENT", "RULE_STOPWORD", 0),
    "global-docs-control": ("EXPECTED_OBSERVED", "CONTROL", 1),
    "global-node-modules": ("EXPECTED_ABSENT", "GLOBAL_PATH_ALLOWLIST", 0),
    "global-vendor-github": ("EXPECTED_ABSENT", "GLOBAL_PATH_ALLOWLIST", 0),
    "pkcs12-one-byte-p12": ("EXPECTED_OBSERVED", "PATH_ONLY_DETECTION", 1),
    "pkcs12-one-byte-pfx": ("EXPECTED_OBSERVED", "PATH_ONLY_DETECTION", 1),
    "pkcs12-suffix-boundary": ("EXPECTED_ABSENT", "PATH_PATTERN_BOUNDARY", 0),
    "pkcs12-uppercase-extension": ("EXPECTED_OBSERVED", "PATH_ONLY_DETECTION", 1),
    "pkcs12-zero-p12": ("EXPECTED_ABSENT", "DIRECTORY_EMPTY_FILE_SKIP", 0),
    "pkcs12-zero-pfx": ("EXPECTED_ABSENT", "DIRECTORY_EMPTY_FILE_SKIP", 0),
}


class GitleaksCharacterizationCategory(StrEnum):
    UPSTREAM_RULE_ALLOWLIST_SUPPRESSION = "UPSTREAM_RULE_ALLOWLIST_SUPPRESSION"
    UPSTREAM_SOURCE_EMPTY_FILE_SKIP = "UPSTREAM_SOURCE_EMPTY_FILE_SKIP"
    UPSTREAM_GLOBAL_PATH_ALLOWLIST = "UPSTREAM_GLOBAL_PATH_ALLOWLIST"
    PATH_ONLY_DETECTION_CONFIRMED = "PATH_ONLY_DETECTION_CONFIRMED"
    FAIL_CLOSED_EXECUTION = "FAIL_CLOSED_EXECUTION"
    CONFIDENTIALITY_GUARANTEE = "CONFIDENTIALITY_GUARANTEE"


class GitleaksCharacterizationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Gitleaks characterization evidence is invalid")


def canonical_gitleaks_characterization(value: object) -> bytes:
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
        raise GitleaksCharacterizationError from None


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> None:
    raise ValueError


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


def _read_stable_file(path: Path, maximum_bytes: int) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_size > maximum_bytes
        ):
            raise OSError
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(before):
            raise OSError
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            chunk = os.read(descriptor, min(65536, maximum_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        finished = os.fstat(descriptor)
        after = path.lstat()
        if (
            len(payload) > maximum_bytes
            or len(payload) != before.st_size
            or _stat_identity(finished) != _stat_identity(before)
            or _stat_identity(after) != _stat_identity(before)
        ):
            raise OSError
        return bytes(payload)
    except OSError:
        raise GitleaksCharacterizationError from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _load_canonical_document(
    path: Path,
    expected_sha256: str,
) -> dict[str, object]:
    payload = _read_stable_file(path, _MAX_DOCUMENT_BYTES)
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, ValueError):
        raise GitleaksCharacterizationError from None
    if (
        not isinstance(document, dict)
        or canonical_gitleaks_characterization(document) != payload
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise GitleaksCharacterizationError
    return document


def _case_map(document: dict[str, object], expected_count: int) -> dict[str, dict[str, object]]:
    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) != expected_count:
        raise GitleaksCharacterizationError
    result: dict[str, dict[str, object]] = {}
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("case_id"), str):
            raise GitleaksCharacterizationError
        case_id = case["case_id"]
        if case_id in result:
            raise GitleaksCharacterizationError
        result[case_id] = case
    return result


def _validate_f3b(document: dict[str, object]) -> None:
    if (
        document.get("schema_version") != "securescan-gitleaks-benchmark-report-v1"
        or document.get("benchmark_id") != "securescan-gitleaks-v0.4f-local-v1"
        or document.get("scanner_id") != GITLEAKS_SCANNER_ID
        or document.get("scanner_version") != GITLEAKS_SCANNER_VERSION
        or document.get("binding_digest") != GITLEAKS_BINDING_DIGEST
        or document.get("case_relation_count") != 48
    ):
        raise GitleaksCharacterizationError
    cases = _case_map(document, 48)
    for case_id, (classification, rule_id, kind) in _F3B_REQUIRED_CASES.items():
        case = cases.get(case_id)
        if (
            case is None
            or case.get("classification") != classification
            or case.get("expectation") != "EXPECTED_MATCH"
            or case.get("expected_rule_id") != rule_id
            or case.get("expected_detection_kind") != kind
            or case.get("same_rule_observation_count") != 0
            or case.get("same_rule_finding_instance_ids") != []
        ):
            raise GitleaksCharacterizationError


def _validate_f4a_corpus(repository_root: Path, cases: list[object]) -> None:
    corpus_root = repository_root / GITLEAKS_F4A_CORPUS_PATH
    try:
        root_metadata = corpus_root.lstat()
        if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
            raise OSError
        entries = tuple(corpus_root.rglob("*"))
        if any(path.is_symlink() for path in entries):
            raise OSError
    except OSError:
        raise GitleaksCharacterizationError from None

    expected_paths: set[str] = set()
    corpus_digest = hashlib.sha256(_CORPUS_STREAM_VERSION)
    for case in cases:
        if not isinstance(case, dict):
            raise GitleaksCharacterizationError
        relative_path = case.get("relative_path")
        expected_sha256 = case.get("sha256")
        if (
            not isinstance(relative_path, str)
            or not relative_path.startswith("adversarial-corpus/")
            or not isinstance(expected_sha256, str)
            or _SHA256.fullmatch(expected_sha256) is None
        ):
            raise GitleaksCharacterizationError
        try:
            relative = PurePosixPath(relative_path).relative_to("adversarial-corpus")
        except ValueError:
            raise GitleaksCharacterizationError from None
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise GitleaksCharacterizationError
        normalized = relative.as_posix()
        expected_paths.add(normalized)
        payload = _read_stable_file(corpus_root / relative, _MAX_FIXTURE_BYTES)
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise GitleaksCharacterizationError
        corpus_digest.update(canonical_gitleaks_characterization(case)[:-1])
        corpus_digest.update(b"\0")

    actual_paths = {
        path.relative_to(corpus_root).as_posix()
        for path in entries
        if path.is_file()
    }
    if actual_paths != expected_paths or corpus_digest.hexdigest() != GITLEAKS_F4A_CORPUS_DIGEST:
        raise GitleaksCharacterizationError


def _validate_f4a(
    repository_root: Path,
    contract: dict[str, object],
    manifest: dict[str, object],
) -> dict[str, dict[str, object]]:
    baseline = contract.get("baseline")
    scanner = contract.get("scanner")
    if (
        contract.get("schema_version") != "securescan-gitleaks-adversarial-contract-v1"
        or contract.get("adversarial_id") != "securescan-gitleaks-v0.4f4-adversarial-v1"
        or contract.get("binding_digest") != GITLEAKS_BINDING_DIGEST
        or contract.get("purpose") != "diagnostic-characterization-not-accuracy-replacement"
        or contract.get("reserved_result_path") != GITLEAKS_F4B2_RESULT_PATH
        or baseline
        != {
            "commit": GITLEAKS_F3B_BASELINE_COMMIT,
            "report_sha256": GITLEAKS_F3B_REPORT_SHA256,
            "tag": GITLEAKS_F3B_BASELINE_TAG,
        }
        or scanner
        != {"id": GITLEAKS_SCANNER_ID, "version": GITLEAKS_SCANNER_VERSION}
        or manifest.get("schema_version")
        != "securescan-gitleaks-adversarial-manifest-v1"
        or manifest.get("adversarial_id") != contract.get("adversarial_id")
        or manifest.get("contract_sha256") != GITLEAKS_F4A_CONTRACT_SHA256
        or manifest.get("corpus_digest") != GITLEAKS_F4A_CORPUS_DIGEST
        or manifest.get("cases") != contract.get("cases")
    ):
        raise GitleaksCharacterizationError
    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise GitleaksCharacterizationError
    by_id = _case_map(manifest, 13)
    if tuple(by_id) != _F4A_CASE_IDS:
        raise GitleaksCharacterizationError
    _validate_f4a_corpus(repository_root, cases)
    return by_id


def _validate_f4b2(
    document: dict[str, object],
    f4a_cases: dict[str, dict[str, object]],
) -> None:
    if (
        document.get("schema_version") != "securescan-gitleaks-adversarial-result-v1"
        or document.get("adversarial_id") != "securescan-gitleaks-v0.4f4-adversarial-v1"
        or document.get("scanner_id") != GITLEAKS_SCANNER_ID
        or document.get("scanner_version") != GITLEAKS_SCANNER_VERSION
        or document.get("binding_digest") != GITLEAKS_BINDING_DIGEST
        or document.get("contract_sha256") != GITLEAKS_F4A_CONTRACT_SHA256
        or document.get("manifest_sha256") != GITLEAKS_F4A_MANIFEST_SHA256
        or document.get("corpus_digest") != GITLEAKS_F4A_CORPUS_DIGEST
        or document.get("f3b_baseline_commit") != GITLEAKS_F3B_BASELINE_COMMIT
        or document.get("f3b_baseline_tag") != GITLEAKS_F3B_BASELINE_TAG
        or document.get("f3b_baseline_sha256") != GITLEAKS_F3B_REPORT_SHA256
        or document.get("f4a_baseline_commit") != GITLEAKS_F4A_BASELINE_COMMIT
        or document.get("f4a_baseline_tag") != GITLEAKS_F4A_BASELINE_TAG
        or document.get("case_count") != 13
        or document.get("pass_count") != 13
        or document.get("fail_count") != 0
        or document.get("unexpected_cross_rule_observations") != []
        or document.get("unexpected_detection_kind_observations") != []
        or document.get("execution")
        != {
            "mode": "production-source-current-snapshot",
            "parsed_finding_count": 5,
            "return_code": 1,
            "status": "completed_with_findings",
        }
        or document.get("confidentiality")
        != {
            "raw_fixture_sentinels_absent_from_scanner_output": True,
            "raw_scanner_output_persisted": False,
        }
    ):
        raise GitleaksCharacterizationError
    cases = _case_map(document, 13)
    if tuple(cases) != _F4A_CASE_IDS:
        raise GitleaksCharacterizationError
    for case_id, (expectation, mechanism, count) in _F4B2_REQUIRED_CASES.items():
        case = cases.get(case_id)
        frozen = f4a_cases.get(case_id)
        if (
            case is None
            or frozen is None
            or case.get("result") != "PASS"
            or case.get("expectation") != expectation
            or case.get("mechanism") != mechanism
            or case.get("matching_observation_count") != count
            or not isinstance(case.get("matching_finding_instance_ids"), list)
            or len(case["matching_finding_instance_ids"]) != count
            or any(
                not isinstance(identity, str) or _SHA256.fullmatch(identity) is None
                for identity in case["matching_finding_instance_ids"]
            )
            or any(
                case.get(key) != frozen.get(key)
                for key in (
                    "relative_path",
                    "expected_rule_id",
                    "expected_detection_kind",
                    "expectation",
                    "mechanism",
                )
            )
        ):
            raise GitleaksCharacterizationError


def _evidence(
    evidence_id: str,
    sha256: str | None,
    case_ids: tuple[str, ...] = (),
    test_ids: tuple[str, ...] = (),
) -> dict[str, object]:
    result: dict[str, object] = {"evidence_id": evidence_id}
    if sha256 is not None:
        result["sha256"] = sha256
    if case_ids:
        result["case_ids"] = list(case_ids)
    if test_ids:
        result["test_ids"] = list(test_ids)
    return result


def _characterizations() -> list[dict[str, object]]:
    return [
        {
            "affected_rule_ids": ["generic-api-key"],
            "category": GitleaksCharacterizationCategory.UPSTREAM_RULE_ALLOWLIST_SUPPRESSION,
            "characterization_id": "generic-api-key-stopword-and-entropy-semantics",
            "claim_boundary": (
                "Do not claim exhaustive generic API-key detection or that every "
                "regex-shaped generic credential is a finding."
            ),
            "evidence": [
                _evidence(
                    "F3B",
                    GITLEAKS_F3B_REPORT_SHA256,
                    ("generic-api-key-positive-01",),
                ),
                _evidence(
                    "F4B2",
                    GITLEAKS_F4B2_RESULT_SHA256,
                    (
                        "generic-high-entropy-control",
                        "generic-low-entropy",
                        "generic-stopword-alpha-lower",
                        "generic-stopword-alpha-mixed",
                    ),
                ),
            ],
            "observation": (
                "The frozen Gitleaks 8.30.1 generic-api-key detector applies stopword "
                "allowlist and entropy semantics in addition to shape matching; "
                "detector-shaped candidates can therefore be suppressed."
            ),
            "product_implication": (
                "SecureScan reports normalized observations delivered by the frozen "
                "scanner and does not reinterpret upstream rule suppression as a parser "
                "failure."
            ),
        },
        {
            "affected_rule_ids": ["pkcs12-file"],
            "category": GitleaksCharacterizationCategory.UPSTREAM_SOURCE_EMPTY_FILE_SKIP,
            "characterization_id": "zero-byte-pkcs12-directory-source-skip",
            "claim_boundary": (
                "Do not synthesize a secret finding solely from an empty .p12 or .pfx "
                "filename."
            ),
            "evidence": [
                _evidence(
                    "F3B",
                    GITLEAKS_F3B_REPORT_SHA256,
                    ("pkcs12-file-positive-01", "pkcs12-file-positive-02"),
                ),
                _evidence(
                    "F4B2",
                    GITLEAKS_F4B2_RESULT_SHA256,
                    (
                        "pkcs12-one-byte-p12",
                        "pkcs12-one-byte-pfx",
                        "pkcs12-uppercase-extension",
                        "pkcs12-zero-p12",
                        "pkcs12-zero-pfx",
                    ),
                ),
            ],
            "observation": (
                "The frozen Gitleaks directory source does not deliver zero-byte files "
                "to path-only detection, while nonempty matching paths are observed."
            ),
            "product_implication": (
                "SecureScan selecting a file does not prove that every Gitleaks detector "
                "inspected that file; later unified coverage reporting may expose this "
                "scanner coverage behavior."
            ),
        },
        {
            "affected_rule_ids": ["pkcs12-file"],
            "category": GitleaksCharacterizationCategory.PATH_ONLY_DETECTION_CONFIRMED,
            "characterization_id": "pkcs12-path-only-detection-boundary",
            "claim_boundary": (
                "A path-only observation does not establish credential content validity."
            ),
            "evidence": [
                _evidence(
                    "F4B2",
                    GITLEAKS_F4B2_RESULT_SHA256,
                    (
                        "pkcs12-one-byte-p12",
                        "pkcs12-one-byte-pfx",
                        "pkcs12-uppercase-extension",
                        "pkcs12-suffix-boundary",
                    ),
                )
            ],
            "observation": (
                "Nonempty .p12, .pfx, and uppercase .P12 paths are observed by the "
                "frozen path-only detector, while the .p12.txt boundary is absent."
            ),
            "product_implication": (
                "SecureScan preserves PATH as the detection kind instead of implying "
                "that file bytes contain a validated credential."
            ),
        },
        {
            "affected_rule_ids": ["github-pat"],
            "category": GitleaksCharacterizationCategory.UPSTREAM_GLOBAL_PATH_ALLOWLIST,
            "characterization_id": "inherited-global-path-allowlist",
            "claim_boundary": (
                "Do not describe inherited node_modules or vendor/github.com exclusions "
                "as SecureScan suppression."
            ),
            "evidence": [
                _evidence(
                    "F4B2",
                    GITLEAKS_F4B2_RESULT_SHA256,
                    (
                        "global-docs-control",
                        "global-node-modules",
                        "global-vendor-github",
                    ),
                )
            ],
            "observation": (
                "The docs control is observed while equivalent detector-shaped values "
                "under inherited node_modules and vendor/github.com allowlists are absent."
            ),
            "product_implication": (
                "SecureScan repository-wide selection does not imply byte-for-byte "
                "Gitleaks inspection when the frozen upstream configuration applies "
                "global path allowlists."
            ),
        },
        {
            "affected_rule_ids": [],
            "category": GitleaksCharacterizationCategory.FAIL_CLOSED_EXECUTION,
            "characterization_id": "incomplete-execution-never-clean",
            "claim_boundary": (
                "Only completed, successfully parsed, confidentiality-valid execution "
                "may produce characterization evidence."
            ),
            "evidence": [
                _evidence(
                    "F4B1",
                    None,
                    test_ids=(
                        "test_fake_failed_or_invalid_execution_cannot_produce_report",
                        "test_raw_projection_sentinel_leak_fails_confidentiality",
                        "test_unknown_path_and_failed_statuses_fail_closed",
                    ),
                )
            ],
            "observation": (
                "FAILED, TIMED_OUT, CANCELLED, OUTPUT_LIMIT_EXCEEDED, invalid exit, "
                "malformed output, parser failure, unknown projection path, and "
                "confidentiality failure cannot produce a clean characterization result."
            ),
            "product_implication": "Incomplete analysis is never represented as clean.",
        },
        {
            "affected_rule_ids": [],
            "category": GitleaksCharacterizationCategory.CONFIDENTIALITY_GUARANTEE,
            "characterization_id": "credential-independent-canonical-evidence",
            "claim_boundary": (
                "Raw Secret, Match, stdout, stderr, Gitleaks Fingerprint, credential "
                "hashes, host paths, projection IDs, context digests, and private parse "
                "digests are not public characterization evidence."
            ),
            "evidence": [
                _evidence(
                    "F4B1",
                    None,
                    test_ids=(
                        "test_canonical_result_is_deterministic_safe_and_has_no_accuracy_metrics",
                        "test_evidence_is_frozen_and_proof_cannot_cross_finding_sets",
                        "test_raw_projection_sentinel_leak_fails_confidentiality",
                    ),
                ),
                _evidence("F4B2", GITLEAKS_F4B2_RESULT_SHA256),
            ],
            "observation": (
                "The frozen result persists sanitized structural finding identities and "
                "confidentiality claims without raw scanner streams or credential-derived "
                "public identity."
            ),
            "product_implication": (
                "Canonical secret-analysis evidence is credential-independent and sanitized."
            ),
        },
    ]


def generate_gitleaks_characterization(repository_root: Path) -> dict[str, object]:
    if not isinstance(repository_root, Path) or not repository_root.is_absolute():
        raise GitleaksCharacterizationError
    f3b = _load_canonical_document(
        repository_root / GITLEAKS_F3B_REPORT_PATH,
        GITLEAKS_F3B_REPORT_SHA256,
    )
    contract = _load_canonical_document(
        repository_root / GITLEAKS_F4A_CONTRACT_PATH,
        GITLEAKS_F4A_CONTRACT_SHA256,
    )
    manifest = _load_canonical_document(
        repository_root / GITLEAKS_F4A_MANIFEST_PATH,
        GITLEAKS_F4A_MANIFEST_SHA256,
    )
    f4b2 = _load_canonical_document(
        repository_root / GITLEAKS_F4B2_RESULT_PATH,
        GITLEAKS_F4B2_RESULT_SHA256,
    )
    _validate_f3b(f3b)
    f4a_cases = _validate_f4a(repository_root, contract, manifest)
    _validate_f4b2(f4b2, f4a_cases)
    return {
        "characterization_id": GITLEAKS_CHARACTERIZATION_ID,
        "characterizations": _characterizations(),
        "evidence_bindings": {
            "f3b": {
                "baseline_commit": GITLEAKS_F3B_BASELINE_COMMIT,
                "baseline_tag": GITLEAKS_F3B_BASELINE_TAG,
                "report_sha256": GITLEAKS_F3B_REPORT_SHA256,
            },
            "f4a": {
                "baseline_commit": GITLEAKS_F4A_BASELINE_COMMIT,
                "baseline_tag": GITLEAKS_F4A_BASELINE_TAG,
                "contract_sha256": GITLEAKS_F4A_CONTRACT_SHA256,
                "corpus_digest": GITLEAKS_F4A_CORPUS_DIGEST,
                "manifest_sha256": GITLEAKS_F4A_MANIFEST_SHA256,
            },
            "f4b1": {
                "baseline_commit": GITLEAKS_F4B1_BASELINE_COMMIT,
                "baseline_tag": GITLEAKS_F4B1_BASELINE_TAG,
            },
            "f4b2": {
                "baseline_commit": GITLEAKS_F4B2_BASELINE_COMMIT,
                "baseline_tag": GITLEAKS_F4B2_BASELINE_TAG,
                "result_sha256": GITLEAKS_F4B2_RESULT_SHA256,
            },
        },
        "maturity": GITLEAKS_MATURITY,
        "schema_version": GITLEAKS_CHARACTERIZATION_SCHEMA_VERSION,
    }


def verify_gitleaks_characterization(repository_root: Path) -> dict[str, object]:
    expected = generate_gitleaks_characterization(repository_root)
    actual = _load_canonical_document(
        repository_root / GITLEAKS_CHARACTERIZATION_PATH,
        GITLEAKS_CHARACTERIZATION_SHA256,
    )
    if actual != expected:
        raise GitleaksCharacterizationError
    return actual

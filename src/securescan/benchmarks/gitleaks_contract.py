from __future__ import annotations

import hashlib
import json
import re
import stat
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final

from securescan.scanners.gitleaks.binding import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
)
from securescan.scanners.gitleaks.parser import GitleaksDetectionKind

GITLEAKS_BENCHMARK_ID: Final = "securescan-gitleaks-v0.4f-local-v1"
GITLEAKS_BENCHMARK_CONTRACT_SCHEMA_VERSION: Final = (
    "securescan-gitleaks-benchmark-contract-v1"
)
GITLEAKS_BENCHMARK_MANIFEST_SCHEMA_VERSION: Final = (
    "securescan-gitleaks-benchmark-manifest-v1"
)

GITLEAKS_V04E_BASELINE_COMMIT: Final = (
    "12fc469a17fc0d118070ad30765c4f5fd0dc749a"
)
GITLEAKS_V04E_BASELINE_TAG: Final = (
    "source-v0.4E-gitleaks-finding-identity"
)

GITLEAKS_BINDING_DIGEST: Final = (
    "8d9f224e1c5ddabef508a26be2966f51dc2a9c2e5805ea3bffcf444b3cae9561"
)
GITLEAKS_BINDING_ARTIFACT_PATH: Final = (
    "benchmarks/gitleaks/gitleaks-binding-v1.json"
)
GITLEAKS_BINDING_ARTIFACT_SHA256: Final = (
    "8d0e06a802158827bbe685b7970ffa075ae07f6393debbb088c3b9bf29f1bd44"
)

GITLEAKS_BENCHMARK_CONTRACT_PATH: Final = (
    "benchmarks/gitleaks/benchmark-contract-v1.json"
)
GITLEAKS_BENCHMARK_CONTRACT_SHA256: Final = (
    "ec5d76590370a979abbdff2170f35c13dda24db7f303c5c4570e6a3e31335b08"
)

_CORPUS_STREAM_VERSION = b"securescan-gitleaks-benchmark-corpus-v1\0"

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_CASE_ID_PATTERN = re.compile(
    r"[a-z0-9][a-z0-9._-]{0,127}\Z",
    re.ASCII,
)
_RULE_ID_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\Z",
    re.ASCII,
)
_URL_SCHEME_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]*:",
    re.ASCII,
)

_MAX_PATH_LENGTH = 4096
_MAX_DESCRIPTION_LENGTH = 512


class GitleaksBenchmarkExpectation(StrEnum):
    EXPECTED_MATCH = "EXPECTED_MATCH"
    EXPECTED_NO_MATCH = "EXPECTED_NO_MATCH"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class GitleaksBenchmarkClassification(StrEnum):
    TP = "TP"
    FP = "FP"
    FN = "FN"
    TN = "TN"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class GitleaksBenchmarkSourceType(StrEnum):
    PROJECT_OWNED_SYNTHETIC = "PROJECT_OWNED_SYNTHETIC"
    PROJECT_OWNED_NEAR_MISS = "PROJECT_OWNED_NEAR_MISS"
    PROJECT_OWNED_SCOPE_SENTINEL = "PROJECT_OWNED_SCOPE_SENTINEL"
    PROJECT_OWNED_BINARY_PATH = "PROJECT_OWNED_BINARY_PATH"


def _has_forbidden_character(value: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        for character in value
    )


def _valid_text(value: object, maximum_length: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= maximum_length
        and not _has_forbidden_character(value)
    )


def _valid_relative_path(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_PATH_LENGTH
        or "\\" in value
        or _has_forbidden_character(value)
        or _URL_SCHEME_PATTERN.match(value) is not None
    ):
        return False

    raw_parts = value.split("/")
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in raw_parts)
        and path.as_posix() == value
    )


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ValueError("Gitleaks benchmark document is invalid") from None


def _pretty_json(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ValueError("Gitleaks benchmark document is invalid") from None


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_non_finite_constant(_value: str) -> None:
    raise ValueError


def _load_json_document(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        ):
            raise ValueError

        payload = path.read_bytes()
        decoded = payload.decode("utf-8")
        document = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except (OSError, UnicodeDecodeError, ValueError):
        raise ValueError("Gitleaks benchmark document is invalid") from None

    if not isinstance(document, dict):
        raise ValueError("Gitleaks benchmark document is invalid")

    return document


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _verified_corpus_case_path(
    benchmark_root: Path,
    relative_path: str,
) -> Path:
    parts = PurePosixPath(relative_path).parts
    current = benchmark_root

    try:
        root_metadata = benchmark_root.lstat()
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_ISLNK(root_metadata.st_mode)
        ):
            raise ValueError

        for part in parts[:-1]:
            current = current / part
            metadata = current.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
            ):
                raise ValueError
    except (OSError, ValueError):
        raise ValueError(
            "Gitleaks benchmark corpus is invalid"
        ) from None

    return benchmark_root / relative_path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        ):
            raise ValueError

        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except (OSError, ValueError):
        raise ValueError("Gitleaks benchmark corpus is invalid") from None

    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class GitleaksBenchmarkCase:
    case_id: str
    description: str
    relative_path: str
    sha256: str
    source_type: GitleaksBenchmarkSourceType
    expectation: GitleaksBenchmarkExpectation
    expected_rule_id: str | None
    expected_detection_kind: GitleaksDetectionKind | None

    def __post_init__(self) -> None:
        scored = self.expectation in {
            GitleaksBenchmarkExpectation.EXPECTED_MATCH,
            GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        }

        if (
            not isinstance(self.case_id, str)
            or _CASE_ID_PATTERN.fullmatch(self.case_id) is None
            or not _valid_text(
                self.description,
                _MAX_DESCRIPTION_LENGTH,
            )
            or not _valid_relative_path(self.relative_path)
            or not self.relative_path.startswith("corpus/")
            or not isinstance(self.sha256, str)
            or _SHA256_PATTERN.fullmatch(self.sha256) is None
            or not isinstance(
                self.source_type,
                GitleaksBenchmarkSourceType,
            )
            or not isinstance(
                self.expectation,
                GitleaksBenchmarkExpectation,
            )
        ):
            raise ValueError("Gitleaks benchmark case is invalid")

        if scored:
            if (
                not isinstance(self.expected_rule_id, str)
                or _RULE_ID_PATTERN.fullmatch(
                    self.expected_rule_id
                )
                is None
                or not isinstance(
                    self.expected_detection_kind,
                    GitleaksDetectionKind,
                )
            ):
                raise ValueError(
                    "Gitleaks benchmark case is invalid"
                )
        elif (
            self.expected_rule_id is not None
            or self.expected_detection_kind is not None
        ):
            raise ValueError("Gitleaks benchmark case is invalid")

    def canonical_data(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "description": self.description,
            "expectation": self.expectation.value,
            "expected_detection_kind": (
                None
                if self.expected_detection_kind is None
                else self.expected_detection_kind.value
            ),
            "expected_rule_id": self.expected_rule_id,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "source_type": self.source_type.value,
        }


def _manifest_material(
    cases: tuple[GitleaksBenchmarkCase, ...],
) -> dict[str, object]:
    return {
        "baseline_commit": GITLEAKS_V04E_BASELINE_COMMIT,
        "baseline_tag": GITLEAKS_V04E_BASELINE_TAG,
        "benchmark_id": GITLEAKS_BENCHMARK_ID,
        "binding_artifact_sha256": (
            GITLEAKS_BINDING_ARTIFACT_SHA256
        ),
        "binding_digest": GITLEAKS_BINDING_DIGEST,
        "cases": [
            case.canonical_data()
            for case in cases
        ],
        "contract_sha256": (
            GITLEAKS_BENCHMARK_CONTRACT_SHA256
        ),
        "scanner_id": GITLEAKS_SCANNER_ID,
        "scanner_version": GITLEAKS_VERSION,
        "schema_version": (
            GITLEAKS_BENCHMARK_MANIFEST_SCHEMA_VERSION
        ),
    }


def calculate_corpus_digest(
    cases: tuple[GitleaksBenchmarkCase, ...],
) -> str:
    if (
        not isinstance(cases, tuple)
        or not cases
        or any(
            not isinstance(case, GitleaksBenchmarkCase)
            for case in cases
        )
    ):
        raise ValueError("Gitleaks benchmark corpus is invalid")

    digest = hashlib.sha256()
    digest.update(_CORPUS_STREAM_VERSION)
    digest.update(_canonical_json(_manifest_material(cases)))
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class GitleaksBenchmarkManifest:
    cases: tuple[GitleaksBenchmarkCase, ...]
    corpus_digest: str
    benchmark_id: str = GITLEAKS_BENCHMARK_ID
    scanner_id: str = GITLEAKS_SCANNER_ID
    scanner_version: str = GITLEAKS_VERSION
    binding_digest: str = GITLEAKS_BINDING_DIGEST
    binding_artifact_sha256: str = (
        GITLEAKS_BINDING_ARTIFACT_SHA256
    )
    contract_sha256: str = (
        GITLEAKS_BENCHMARK_CONTRACT_SHA256
    )
    baseline_commit: str = GITLEAKS_V04E_BASELINE_COMMIT
    baseline_tag: str = GITLEAKS_V04E_BASELINE_TAG
    schema_version: str = (
        GITLEAKS_BENCHMARK_MANIFEST_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != GITLEAKS_BENCHMARK_MANIFEST_SCHEMA_VERSION
            or self.benchmark_id != GITLEAKS_BENCHMARK_ID
            or self.scanner_id != GITLEAKS_SCANNER_ID
            or self.scanner_version != GITLEAKS_VERSION
            or self.binding_digest != GITLEAKS_BINDING_DIGEST
            or self.binding_artifact_sha256
            != GITLEAKS_BINDING_ARTIFACT_SHA256
            or self.contract_sha256
            != GITLEAKS_BENCHMARK_CONTRACT_SHA256
            or self.baseline_commit
            != GITLEAKS_V04E_BASELINE_COMMIT
            or self.baseline_tag
            != GITLEAKS_V04E_BASELINE_TAG
            or not isinstance(self.cases, tuple)
            or not self.cases
            or any(
                not isinstance(case, GitleaksBenchmarkCase)
                for case in self.cases
            )
            or self.cases
            != tuple(
                sorted(
                    self.cases,
                    key=lambda case: case.case_id,
                )
            )
            or len(
                {case.case_id for case in self.cases}
            )
            != len(self.cases)
            or len(
                {case.relative_path for case in self.cases}
            )
            != len(self.cases)
            or not isinstance(self.corpus_digest, str)
            or _SHA256_PATTERN.fullmatch(
                self.corpus_digest
            )
            is None
            or self.corpus_digest
            != calculate_corpus_digest(self.cases)
        ):
            raise ValueError(
                "Gitleaks benchmark manifest is invalid"
            )

    def canonical_data(self) -> dict[str, object]:
        return {
            **_manifest_material(self.cases),
            "corpus_digest": self.corpus_digest,
        }

    def canonical_json(self) -> bytes:
        return _pretty_json(self.canonical_data())


def build_benchmark_manifest(
    cases: tuple[GitleaksBenchmarkCase, ...],
) -> GitleaksBenchmarkManifest:
    if not isinstance(cases, tuple):
        raise ValueError("Gitleaks benchmark manifest is invalid")

    ordered = tuple(
        sorted(
            cases,
            key=lambda case: case.case_id,
        )
    )

    return GitleaksBenchmarkManifest(
        cases=ordered,
        corpus_digest=calculate_corpus_digest(ordered),
    )


def classify_case(
    expectation: GitleaksBenchmarkExpectation,
    observed_same_rule: bool,
) -> GitleaksBenchmarkClassification:
    if (
        not isinstance(
            expectation,
            GitleaksBenchmarkExpectation,
        )
        or type(observed_same_rule) is not bool
    ):
        raise ValueError(
            "Gitleaks benchmark classification is invalid"
        )

    if expectation is GitleaksBenchmarkExpectation.OUT_OF_SCOPE:
        return GitleaksBenchmarkClassification.OUT_OF_SCOPE

    if expectation is GitleaksBenchmarkExpectation.EXPECTED_MATCH:
        return (
            GitleaksBenchmarkClassification.TP
            if observed_same_rule
            else GitleaksBenchmarkClassification.FN
        )

    return (
        GitleaksBenchmarkClassification.FP
        if observed_same_rule
        else GitleaksBenchmarkClassification.TN
    )


def benchmark_contract_document() -> dict[str, object]:
    return {
        "baseline": {
            "commit": GITLEAKS_V04E_BASELINE_COMMIT,
            "tag": GITLEAKS_V04E_BASELINE_TAG,
        },
        "benchmark_id": GITLEAKS_BENCHMARK_ID,
        "binding": {
            "artifact_path": GITLEAKS_BINDING_ARTIFACT_PATH,
            "artifact_sha256": (
                GITLEAKS_BINDING_ARTIFACT_SHA256
            ),
            "binding_digest": GITLEAKS_BINDING_DIGEST,
            "required": True,
        },
        "case_contract": {
            "one_scored_relation_per_file": True,
            "out_of_scope_is_not_scored": True,
            "repeated_same_relation_observations_do_not_increase_tp": True,
            "unexpected_cross_rule_observations_are_reported_separately": True,
        },
        "classification": {
            "EXPECTED_MATCH_observed": "TP",
            "EXPECTED_MATCH_unobserved": "FN",
            "EXPECTED_NO_MATCH_observed": "FP",
            "EXPECTED_NO_MATCH_unobserved": "TN",
            "OUT_OF_SCOPE_observed": "OUT_OF_SCOPE",
            "OUT_OF_SCOPE_unobserved": "OUT_OF_SCOPE",
        },
        "confidentiality": {
            "benchmark_artifacts_may_contain_case_file_sha256": True,
            "benchmark_reports_may_contain_structural_finding_id": True,
            "credential_hash_for_public_identity": False,
            "gitleaks_fingerprint_in_public_report": False,
            "raw_match_in_public_report": False,
            "raw_secret_in_public_report": False,
            "raw_scanner_stdout_persisted": False,
        },
        "execution": {
            "archive_traversal": False,
            "current_snapshot_only": True,
            "history_scanning": False,
            "mode": "dir",
            "network_acquisition": False,
            "recursive_decoding": False,
            "repository_inline_allow_directives": False,
        },
        "manifest_schema_version": (
            GITLEAKS_BENCHMARK_MANIFEST_SCHEMA_VERSION
        ),
        "maturity": {
            "benchmark_result_does_not_auto_promote": True,
            "starting_state": "scannable",
        },
        "scanner": {
            "id": GITLEAKS_SCANNER_ID,
            "version": GITLEAKS_VERSION,
        },
        "schema_version": (
            GITLEAKS_BENCHMARK_CONTRACT_SCHEMA_VERSION
        ),
        "scope_limitations": [
            (
                "Representative bounded evidence does not certify every "
                "inherited Gitleaks detector."
            ),
            (
                "A detected secret-like value is not proof that a credential "
                "is valid, active, exploitable, or reachable."
            ),
            (
                "Git history, provider validation, network requests, archive "
                "traversal, and recursive decoding are outside Source v1."
            ),
            (
                "Perfect bounded-corpus metrics do not imply ecosystem-wide "
                "zero false positives or zero false negatives."
            ),
        ],
    }


def canonical_benchmark_contract() -> bytes:
    return _pretty_json(benchmark_contract_document())


def benchmark_contract_sha256() -> str:
    return _sha256_bytes(canonical_benchmark_contract())


def verify_benchmark_contract(repository_root: Path) -> None:
    if (
        not isinstance(repository_root, Path)
        or not repository_root.is_absolute()
    ):
        raise ValueError(
            "Gitleaks benchmark contract is invalid"
        )

    contract_path = (
        repository_root
        / GITLEAKS_BENCHMARK_CONTRACT_PATH
    )
    binding_path = (
        repository_root
        / GITLEAKS_BINDING_ARTIFACT_PATH
    )

    try:
        contract_sha256 = _sha256_file(contract_path)
        binding_sha256 = _sha256_file(binding_path)
        contract_bytes = contract_path.read_bytes()
    except (OSError, ValueError):
        raise ValueError(
            "Gitleaks benchmark contract is invalid"
        ) from None

    if (
        contract_bytes != canonical_benchmark_contract()
        or contract_sha256
        != GITLEAKS_BENCHMARK_CONTRACT_SHA256
        or binding_sha256
        != GITLEAKS_BINDING_ARTIFACT_SHA256
    ):
        raise ValueError(
            "Gitleaks benchmark contract is invalid"
        )

    binding = _load_json_document(binding_path)
    if binding.get("binding_digest") != GITLEAKS_BINDING_DIGEST:
        raise ValueError(
            "Gitleaks benchmark contract is invalid"
        )


def _case_from_document(
    document: object,
) -> GitleaksBenchmarkCase:
    if not isinstance(document, dict):
        raise ValueError(
            "Gitleaks benchmark manifest is invalid"
        )

    expected_keys = {
        "case_id",
        "description",
        "expectation",
        "expected_detection_kind",
        "expected_rule_id",
        "relative_path",
        "sha256",
        "source_type",
    }
    if set(document) != expected_keys:
        raise ValueError(
            "Gitleaks benchmark manifest is invalid"
        )

    try:
        expectation = GitleaksBenchmarkExpectation(
            document["expectation"]
        )
        source_type = GitleaksBenchmarkSourceType(
            document["source_type"]
        )
        detection_raw = document[
            "expected_detection_kind"
        ]
        detection_kind = (
            None
            if detection_raw is None
            else GitleaksDetectionKind(detection_raw)
        )

        return GitleaksBenchmarkCase(
            case_id=document["case_id"],  # type: ignore[arg-type]
            description=document["description"],  # type: ignore[arg-type]
            relative_path=document["relative_path"],  # type: ignore[arg-type]
            sha256=document["sha256"],  # type: ignore[arg-type]
            source_type=source_type,
            expectation=expectation,
            expected_rule_id=document["expected_rule_id"],  # type: ignore[arg-type]
            expected_detection_kind=detection_kind,
        )
    except (TypeError, ValueError):
        raise ValueError(
            "Gitleaks benchmark manifest is invalid"
        ) from None


def load_benchmark_manifest(
    path: Path,
) -> GitleaksBenchmarkManifest:
    document = _load_json_document(path)

    expected_keys = {
        "baseline_commit",
        "baseline_tag",
        "benchmark_id",
        "binding_artifact_sha256",
        "binding_digest",
        "cases",
        "contract_sha256",
        "corpus_digest",
        "scanner_id",
        "scanner_version",
        "schema_version",
    }
    if set(document) != expected_keys:
        raise ValueError(
            "Gitleaks benchmark manifest is invalid"
        )

    raw_cases = document["cases"]
    if not isinstance(raw_cases, list):
        raise ValueError(
            "Gitleaks benchmark manifest is invalid"
        )

    cases = tuple(
        _case_from_document(case)
        for case in raw_cases
    )

    if cases != tuple(
        sorted(cases, key=lambda case: case.case_id)
    ):
        raise ValueError(
            "Gitleaks benchmark manifest is invalid"
        )

    try:
        manifest = GitleaksBenchmarkManifest(
            cases=cases,
            corpus_digest=document["corpus_digest"],  # type: ignore[arg-type]
            benchmark_id=document["benchmark_id"],  # type: ignore[arg-type]
            scanner_id=document["scanner_id"],  # type: ignore[arg-type]
            scanner_version=document["scanner_version"],  # type: ignore[arg-type]
            binding_digest=document["binding_digest"],  # type: ignore[arg-type]
            binding_artifact_sha256=document[
                "binding_artifact_sha256"
            ],  # type: ignore[arg-type]
            contract_sha256=document["contract_sha256"],  # type: ignore[arg-type]
            baseline_commit=document["baseline_commit"],  # type: ignore[arg-type]
            baseline_tag=document["baseline_tag"],  # type: ignore[arg-type]
            schema_version=document["schema_version"],  # type: ignore[arg-type]
        )
    except (TypeError, ValueError):
        raise ValueError(
            "Gitleaks benchmark manifest is invalid"
        ) from None

    benchmark_root = path.parent
    corpus_root = benchmark_root / "corpus"

    declared_paths = {
        case.relative_path
        for case in manifest.cases
    }

    for case in manifest.cases:
        case_path = _verified_corpus_case_path(
            benchmark_root,
            case.relative_path,
        )
        if _sha256_file(case_path) != case.sha256:
            raise ValueError(
                "Gitleaks benchmark corpus is invalid"
            )

    try:
        actual_paths = {
            path.relative_to(benchmark_root).as_posix()
            for path in corpus_root.rglob("*")
            if path.is_file()
        }
    except OSError:
        raise ValueError(
            "Gitleaks benchmark corpus is invalid"
        ) from None

    if actual_paths != declared_paths:
        raise ValueError(
            "Gitleaks benchmark corpus is invalid"
        )

    return manifest

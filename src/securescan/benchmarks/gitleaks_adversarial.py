from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import unicodedata
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final

from securescan.benchmarks.gitleaks_contract import GITLEAKS_BINDING_DIGEST
from securescan.scanners.gitleaks import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
    GitleaksDetectionKind,
)

GITLEAKS_ADVERSARIAL_SCHEMA_VERSION: Final = "securescan-gitleaks-adversarial-contract-v1"
GITLEAKS_ADVERSARIAL_MANIFEST_SCHEMA_VERSION: Final = "securescan-gitleaks-adversarial-manifest-v1"
GITLEAKS_ADVERSARIAL_ID: Final = "securescan-gitleaks-v0.4f4-adversarial-v1"
GITLEAKS_ADVERSARIAL_CONTRACT_PATH: Final = "benchmarks/gitleaks/adversarial-contract-v1.json"
GITLEAKS_ADVERSARIAL_MANIFEST_PATH: Final = "benchmarks/gitleaks/adversarial-manifest-v1.json"
GITLEAKS_ADVERSARIAL_CORPUS_PATH: Final = "benchmarks/gitleaks/adversarial-corpus"
GITLEAKS_ADVERSARIAL_RESULT_PATH: Final = "benchmarks/gitleaks/adversarial-v1-result.json"
GITLEAKS_F3B_BASELINE_PATH: Final = "benchmarks/gitleaks/initial-v0.4f-baseline.json"
GITLEAKS_ADVERSARIAL_CASE_COUNT: Final = 13
GITLEAKS_F3B_BASELINE_COMMIT: Final = "d183336c129977c4279cd1058bbe060742de0e54"
GITLEAKS_F3B_BASELINE_TAG: Final = "source-v0.4F3B-gitleaks-initial-baseline"
GITLEAKS_F3B_BASELINE_SHA256: Final = (
    "62f9c00f79c659d56490a181de231f0aa3cdca6a418f2ca5a9215f7ed1bbbb34"
)

GITLEAKS_ADVERSARIAL_CONTRACT_SHA256: Final = (
    "968c672093bb13458c7a677ae8e0f5964b1b3c511090afd1c3bf0c73c3233f43"
)
GITLEAKS_ADVERSARIAL_MANIFEST_SHA256: Final = (
    "9866e77db9ecef20fc49817b89b1f7374cb1fe6cce47d85a90ed18b52f7c4c3a"
)
GITLEAKS_ADVERSARIAL_CORPUS_DIGEST: Final = (
    "dfd3ccbcb6537b7de35cc9bce130e9dabd0f72ef5ff0fc1f10ef7a303bf90c22"
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9-]{0,127}\Z", re.ASCII)
_RULE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,127}\Z", re.ASCII)
_URL_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:", re.ASCII)
_GENERIC_ASSIGNMENT = re.compile(
    rb"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*[\"']([A-Za-z0-9]{16,})[\"']"
)
_PKCS12_PATH = re.compile(r"(?i)(?:^|/)[^/]+\.p(?:12|fx)$")
_NODE_MODULES_PATH = re.compile(r"(?:^|/)node_modules(?:/|$)")
_VENDOR_GITHUB_PATH = re.compile(r"(?:^|/)vendor/github\.com/[^/]+/[^/]+(?:/|$)")
_CORPUS_STREAM_VERSION = b"securescan-gitleaks-adversarial-corpus-v1\0"
_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_FIXTURE_BYTES = 16 * 1024
_MAX_BASELINE_BYTES = 1024 * 1024


class GitleaksAdversarialExpectation(StrEnum):
    EXPECTED_OBSERVED = "EXPECTED_OBSERVED"
    EXPECTED_ABSENT = "EXPECTED_ABSENT"


class GitleaksAdversarialMechanism(StrEnum):
    RULE_STOPWORD = "RULE_STOPWORD"
    RULE_ENTROPY = "RULE_ENTROPY"
    DIRECTORY_EMPTY_FILE_SKIP = "DIRECTORY_EMPTY_FILE_SKIP"
    PATH_ONLY_DETECTION = "PATH_ONLY_DETECTION"
    PATH_PATTERN_BOUNDARY = "PATH_PATTERN_BOUNDARY"
    GLOBAL_PATH_ALLOWLIST = "GLOBAL_PATH_ALLOWLIST"
    CONTROL = "CONTROL"


@dataclass(frozen=True, slots=True)
class GitleaksAdversarialCase:
    case_id: str
    description: str
    relative_path: str
    sha256: str
    expected_rule_id: str
    expected_detection_kind: GitleaksDetectionKind
    expectation: GitleaksAdversarialExpectation
    mechanism: GitleaksAdversarialMechanism

    def __post_init__(self) -> None:
        if (
            not isinstance(self.case_id, str)
            or _IDENTIFIER.fullmatch(self.case_id) is None
            or not _valid_text(self.description, 512)
            or not _valid_relative_path(self.relative_path)
            or not self.relative_path.startswith("adversarial-corpus/")
            or not isinstance(self.sha256, str)
            or _SHA256.fullmatch(self.sha256) is None
            or not isinstance(self.expected_rule_id, str)
            or _RULE_ID.fullmatch(self.expected_rule_id) is None
            or not isinstance(self.expected_detection_kind, GitleaksDetectionKind)
            or not isinstance(self.expectation, GitleaksAdversarialExpectation)
            or not isinstance(self.mechanism, GitleaksAdversarialMechanism)
        ):
            raise ValueError("Gitleaks adversarial case is invalid")

    def canonical_data(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "description": self.description,
            "expectation": self.expectation.value,
            "expected_detection_kind": self.expected_detection_kind.value,
            "expected_rule_id": self.expected_rule_id,
            "mechanism": self.mechanism.value,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class GitleaksAdversarialManifest:
    cases: tuple[GitleaksAdversarialCase, ...]
    contract_sha256: str
    corpus_digest: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.cases, tuple)
            or len(self.cases) != GITLEAKS_ADVERSARIAL_CASE_COUNT
            or self.cases != tuple(sorted(self.cases, key=lambda case: case.case_id))
            or len({case.case_id for case in self.cases}) != len(self.cases)
            or len({case.relative_path for case in self.cases}) != len(self.cases)
            or _SHA256.fullmatch(self.contract_sha256) is None
            or _SHA256.fullmatch(self.corpus_digest) is None
        ):
            raise ValueError("Gitleaks adversarial manifest is invalid")

    def canonical_data(self) -> dict[str, object]:
        return {
            "adversarial_id": GITLEAKS_ADVERSARIAL_ID,
            "cases": [case.canonical_data() for case in self.cases],
            "contract_sha256": self.contract_sha256,
            "corpus_digest": self.corpus_digest,
            "schema_version": GITLEAKS_ADVERSARIAL_MANIFEST_SCHEMA_VERSION,
        }

    def canonical_json(self) -> bytes:
        return _canonical_json(self.canonical_data()) + b"\n"


def _valid_text(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= maximum
        and not any(unicodedata.category(char).startswith("C") for char in value)
    )


def _valid_relative_path(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or "\\" in value
        or _URL_SCHEME.match(value) is not None
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ValueError("Gitleaks adversarial document is invalid") from None


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> None:
    raise ValueError


def _load_document(path: Path) -> tuple[dict[str, object], bytes]:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_size > _MAX_DOCUMENT_BYTES
        ):
            raise ValueError
        payload = path.read_bytes()
        after = path.lstat()
        if _stat_identity(before) != _stat_identity(after) or len(payload) != before.st_size:
            raise ValueError
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, UnicodeDecodeError, ValueError):
        raise ValueError("Gitleaks adversarial document is invalid") from None
    if not isinstance(document, dict):
        raise ValueError("Gitleaks adversarial document is invalid")
    return document, payload


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


def _read_frozen_f3b_baseline(path: Path) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_size > _MAX_BASELINE_BYTES
        ):
            raise ValueError
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stat_identity(before) != _stat_identity(opened):
            raise ValueError
        payload = bytearray()
        while len(payload) <= _MAX_BASELINE_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, _MAX_BASELINE_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        after_read = os.fstat(descriptor)
        after_path = path.lstat()
        if (
            len(payload) > _MAX_BASELINE_BYTES
            or len(payload) != before.st_size
            or _stat_identity(before) != _stat_identity(opened)
            or _stat_identity(before) != _stat_identity(after_read)
            or _stat_identity(before) != _stat_identity(after_path)
            or hashlib.sha256(bytes(payload)).hexdigest() != GITLEAKS_F3B_BASELINE_SHA256
        ):
            raise ValueError
    except (OSError, ValueError):
        raise ValueError("Gitleaks F3B baseline is invalid") from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
    return bytes(payload)


def _case_from_data(value: object) -> GitleaksAdversarialCase:
    if not isinstance(value, dict) or set(value) != {
        "case_id",
        "description",
        "expectation",
        "expected_detection_kind",
        "expected_rule_id",
        "mechanism",
        "relative_path",
        "sha256",
    }:
        raise ValueError("Gitleaks adversarial document is invalid")
    try:
        return GitleaksAdversarialCase(
            case_id=value["case_id"],
            description=value["description"],
            expectation=GitleaksAdversarialExpectation(value["expectation"]),
            expected_detection_kind=GitleaksDetectionKind(value["expected_detection_kind"]),
            expected_rule_id=value["expected_rule_id"],
            mechanism=GitleaksAdversarialMechanism(value["mechanism"]),
            relative_path=value["relative_path"],
            sha256=value["sha256"],
        )
    except (TypeError, ValueError):
        raise ValueError("Gitleaks adversarial document is invalid") from None


def _contract_data(cases: tuple[GitleaksAdversarialCase, ...]) -> dict[str, object]:
    return {
        "adversarial_id": GITLEAKS_ADVERSARIAL_ID,
        "baseline": {
            "commit": GITLEAKS_F3B_BASELINE_COMMIT,
            "report_sha256": GITLEAKS_F3B_BASELINE_SHA256,
            "tag": GITLEAKS_F3B_BASELINE_TAG,
        },
        "binding_digest": GITLEAKS_BINDING_DIGEST,
        "cases": [case.canonical_data() for case in cases],
        "purpose": "diagnostic-characterization-not-accuracy-replacement",
        "reserved_result_path": GITLEAKS_ADVERSARIAL_RESULT_PATH,
        "scanner": {"id": GITLEAKS_SCANNER_ID, "version": GITLEAKS_VERSION},
        "schema_version": GITLEAKS_ADVERSARIAL_SCHEMA_VERSION,
    }


def load_gitleaks_adversarial_contract(path: Path) -> tuple[GitleaksAdversarialCase, ...]:
    document, payload = _load_document(path)
    if set(document) != {
        "adversarial_id",
        "baseline",
        "binding_digest",
        "cases",
        "purpose",
        "reserved_result_path",
        "scanner",
        "schema_version",
    }:
        raise ValueError("Gitleaks adversarial document is invalid")
    raw_cases = document.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError("Gitleaks adversarial document is invalid")
    cases = tuple(_case_from_data(case) for case in raw_cases)
    if (
        document != _contract_data(cases)
        or payload != _canonical_json(document) + b"\n"
        or len(cases) != GITLEAKS_ADVERSARIAL_CASE_COUNT
        or cases != tuple(sorted(cases, key=lambda case: case.case_id))
        or len({case.case_id for case in cases}) != len(cases)
        or len({case.relative_path for case in cases}) != len(cases)
    ):
        raise ValueError("Gitleaks adversarial document is invalid")
    return cases


def load_gitleaks_adversarial_manifest(path: Path) -> GitleaksAdversarialManifest:
    document, payload = _load_document(path)
    if set(document) != {
        "adversarial_id",
        "cases",
        "contract_sha256",
        "corpus_digest",
        "schema_version",
    } or not isinstance(document.get("cases"), list):
        raise ValueError("Gitleaks adversarial document is invalid")
    manifest = GitleaksAdversarialManifest(
        cases=tuple(_case_from_data(case) for case in document["cases"]),
        contract_sha256=document["contract_sha256"],
        corpus_digest=document["corpus_digest"],
    )
    if document != manifest.canonical_data() or payload != manifest.canonical_json():
        raise ValueError("Gitleaks adversarial document is invalid")
    return manifest


def shannon_entropy(candidate: bytes) -> float:
    if not isinstance(candidate, bytes) or not candidate:
        raise ValueError("Gitleaks adversarial candidate is invalid")
    return -sum(
        (count / len(candidate)) * math.log2(count / len(candidate))
        for count in Counter(candidate).values()
    )


def _generic_candidate(payload: bytes) -> bytes:
    match = _GENERIC_ASSIGNMENT.search(payload)
    if match is None:
        raise ValueError("Gitleaks adversarial generic fixture is invalid")
    return match.group(1)


def _validate_static_recipes(
    cases: tuple[GitleaksAdversarialCase, ...], payloads: dict[str, bytes]
) -> None:
    by_id = {case.case_id: case for case in cases}
    lower = _generic_candidate(payloads[by_id["generic-stopword-alpha-lower"].relative_path])
    mixed = _generic_candidate(payloads[by_id["generic-stopword-alpha-mixed"].relative_path])
    control = _generic_candidate(payloads[by_id["generic-high-entropy-control"].relative_path])
    low = _generic_candidate(payloads[by_id["generic-low-entropy"].relative_path])
    if not (
        b"alpha" in lower.lower()
        and b"alpha" in mixed.lower()
        and shannon_entropy(lower) >= 3.5
        and shannon_entropy(mixed) >= 3.5
        and b"alpha" not in control.lower()
        and shannon_entropy(control) >= 3.5
        and b"alpha" not in low.lower()
        and shannon_entropy(low) < 3.5
        and not low.isalpha()
    ):
        raise ValueError("Gitleaks adversarial generic fixture is invalid")

    expected_paths = {
        "pkcs12-zero-p12": True,
        "pkcs12-zero-pfx": True,
        "pkcs12-one-byte-p12": True,
        "pkcs12-one-byte-pfx": True,
        "pkcs12-uppercase-extension": True,
        "pkcs12-suffix-boundary": False,
    }
    if any(
        (_PKCS12_PATH.search(case.relative_path) is not None) is not expected
        for case_id, expected in expected_paths.items()
        for case in (by_id[case_id],)
    ):
        raise ValueError("Gitleaks adversarial PKCS12 fixture is invalid")
    if any(
        len(payloads[by_id[case_id].relative_path]) != expected_size
        for case_id, expected_size in {
            "pkcs12-zero-p12": 0,
            "pkcs12-zero-pfx": 0,
            "pkcs12-one-byte-p12": 1,
            "pkcs12-one-byte-pfx": 1,
            "pkcs12-uppercase-extension": 1,
            "pkcs12-suffix-boundary": 1,
        }.items()
    ):
        raise ValueError("Gitleaks adversarial PKCS12 fixture is invalid")

    node = by_id["global-node-modules"].relative_path
    vendor = by_id["global-vendor-github"].relative_path
    docs = by_id["global-docs-control"].relative_path
    if not (
        _NODE_MODULES_PATH.search(node)
        and _VENDOR_GITHUB_PATH.search(vendor)
        and not _NODE_MODULES_PATH.search(docs)
        and not _VENDOR_GITHUB_PATH.search(docs)
    ):
        raise ValueError("Gitleaks adversarial allowlist fixture is invalid")


def _verified_fixture(corpus_root: Path, relative_path: str) -> tuple[bytes, os.stat_result]:
    path = corpus_root / PurePosixPath(relative_path).relative_to("adversarial-corpus")
    current = corpus_root
    try:
        root = current.lstat()
        if not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode):
            raise ValueError
        for part in path.relative_to(corpus_root).parts[:-1]:
            current /= part
            metadata = current.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ValueError
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_size > _MAX_FIXTURE_BYTES
        ):
            raise ValueError
        payload = path.read_bytes()
        after = path.lstat()
        if _stat_identity(before) != _stat_identity(after) or len(payload) != before.st_size:
            raise ValueError
    except (OSError, ValueError):
        raise ValueError("Gitleaks adversarial corpus is invalid") from None
    return payload, after


def adversarial_corpus_digest(cases: tuple[GitleaksAdversarialCase, ...]) -> str:
    digest = hashlib.sha256(_CORPUS_STREAM_VERSION)
    for case in cases:
        digest.update(_canonical_json(case.canonical_data()))
        digest.update(b"\0")
    return digest.hexdigest()


def verify_gitleaks_adversarial(repository_root: Path) -> GitleaksAdversarialManifest:
    if not isinstance(repository_root, Path) or not repository_root.is_absolute():
        raise ValueError("Gitleaks adversarial repository root is invalid")
    contract_path = repository_root / GITLEAKS_ADVERSARIAL_CONTRACT_PATH
    manifest_path = repository_root / GITLEAKS_ADVERSARIAL_MANIFEST_PATH
    corpus_root = repository_root / GITLEAKS_ADVERSARIAL_CORPUS_PATH
    _read_frozen_f3b_baseline(repository_root / GITLEAKS_F3B_BASELINE_PATH)
    cases = load_gitleaks_adversarial_contract(contract_path)
    manifest = load_gitleaks_adversarial_manifest(manifest_path)
    contract_sha = hashlib.sha256(_canonical_json(_contract_data(cases)) + b"\n").hexdigest()
    if (
        cases != manifest.cases
        or contract_sha != manifest.contract_sha256
        or contract_sha != GITLEAKS_ADVERSARIAL_CONTRACT_SHA256
        or hashlib.sha256(manifest.canonical_json()).hexdigest()
        != GITLEAKS_ADVERSARIAL_MANIFEST_SHA256
        or adversarial_corpus_digest(cases) != manifest.corpus_digest
        or manifest.corpus_digest != GITLEAKS_ADVERSARIAL_CORPUS_DIGEST
    ):
        raise ValueError("Gitleaks adversarial evidence is invalid")

    payloads: dict[str, bytes] = {}
    for case in cases:
        payload, _metadata = _verified_fixture(corpus_root, case.relative_path)
        if hashlib.sha256(payload).hexdigest() != case.sha256:
            raise ValueError("Gitleaks adversarial corpus is invalid")
        payloads[case.relative_path] = payload
    expected = {
        PurePosixPath(case.relative_path).relative_to("adversarial-corpus").as_posix()
        for case in cases
    }
    try:
        actual = {
            path.relative_to(corpus_root).as_posix()
            for path in corpus_root.rglob("*")
            if path.is_file() or path.is_symlink()
        }
    except OSError:
        raise ValueError("Gitleaks adversarial corpus is invalid") from None
    if actual != expected:
        raise ValueError("Gitleaks adversarial corpus is invalid")
    _validate_static_recipes(cases, payloads)
    result_path = repository_root / GITLEAKS_ADVERSARIAL_RESULT_PATH
    try:
        result_path.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        raise ValueError("Gitleaks adversarial result path is invalid") from None
    else:
        raise ValueError("Gitleaks adversarial result must not exist during F4A")
    return manifest

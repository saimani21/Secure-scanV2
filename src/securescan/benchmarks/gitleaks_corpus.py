from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import unicodedata
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from securescan.benchmarks.gitleaks_contract import (
    GITLEAKS_BENCHMARK_CONTRACT_SHA256,
    GITLEAKS_BENCHMARK_ID,
    GITLEAKS_BINDING_ARTIFACT_SHA256,
    GITLEAKS_BINDING_DIGEST,
    GitleaksBenchmarkCase,
    GitleaksBenchmarkExpectation,
    GitleaksBenchmarkManifest,
    GitleaksBenchmarkSourceType,
    build_benchmark_manifest,
    load_benchmark_manifest,
)
from securescan.scanners.gitleaks.binding import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
)
from securescan.scanners.gitleaks.parser import GitleaksDetectionKind

GITLEAKS_CORPUS_PLAN_SCHEMA_VERSION: Final = (
    "securescan-gitleaks-corpus-plan-v1"
)
GITLEAKS_CORPUS_PLAN_PATH: Final = "benchmarks/gitleaks/corpus-plan-v1.json"
GITLEAKS_CORPUS_MANIFEST_PATH: Final = "benchmarks/gitleaks/manifest.json"
GITLEAKS_CORPUS_PLAN_SHA256: Final = (
    "0090cd7d140034f715bc9d060465ea69284f63b3a33ab917479b1264fa542a10"
)
GITLEAKS_CORPUS_MANIFEST_SHA256: Final = (
    "2946d1b4093f2195612268d6ec7447f38ae4a7266c80f8da52f98d896db04c8e"
)
GITLEAKS_CORPUS_DIGEST: Final = (
    "8129c41a4f28d1eb323ccc2521b798fd80d25c0f61d1aa9f6323ac985fa19799"
)
GITLEAKS_V04F1_BASELINE_TAG: Final = (
    "source-v0.4F1-gitleaks-benchmark-contract"
)
GITLEAKS_V04F1_BASELINE_COMMIT: Final = (
    "c19e3d0ac78ccc4ab504eeab03c989d1b803acb0"
)

GITLEAKS_CORPUS_CASE_COUNT: Final = 48
GITLEAKS_CORPUS_CORE_CASE_COUNT: Final = 42
GITLEAKS_CORPUS_SCOPE_CASE_COUNT: Final = 6
GITLEAKS_CORPUS_RULE_IDS: Final = (
    "aws-access-token",
    "generic-api-key",
    "github-pat",
    "gitlab-pat",
    "pkcs12-file",
    "private-key",
    "slack-bot-token",
)

_CASE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,127}\Z", re.ASCII)
_RECIPE_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,127}\Z", re.ASCII)
_RULE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,127}\Z", re.ASCII)
_URL_SCHEME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:", re.ASCII)
_AWS_ACCESS_TOKEN_PATTERN = re.compile(
    rb"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\Z"
)
_AWS_WRONG_PREFIX_PATTERN = re.compile(rb"ZZIA[A-Z2-7]{16}\Z")
_AWS_WRONG_LENGTH_PATTERN = re.compile(rb"AKIA[A-Z2-7]{15}\Z")
_MAX_PLAN_BYTES = 1024 * 1024
_MAX_DESCRIPTION_LENGTH = 512
_STAGING_DIRECTORY_NAME = ".gitleaks-corpus-v1.staging"
_MANIFEST_STAGING_NAME = ".gitleaks-manifest-v1.staging"


@dataclass(frozen=True, slots=True)
class _CoreRecipe:
    case_id: str
    rule_id: str
    expectation: GitleaksBenchmarkExpectation
    detection_kind: GitleaksDetectionKind
    relative_path: str
    payload: bytes
    allow_empty: bool = False


def _text(value: str) -> bytes:
    return (
        "# SecureScan project-owned synthetic pre-scan fixture.\n"
        "# This value is non-live and must never be used as a credential.\n"
        f"{value}\n"
    ).encode("ascii")


# These literals are deliberately synthetic and non-live. They encode only
# pre-scan structural intent from the frozen Gitleaks 8.30.1 configuration.
# They must never be submitted to a credential provider or used as credentials.
_CORE_RECIPES: Final = {
    "aws-wrong-prefix": _CoreRecipe(
        "aws-access-token-negative-01",
        "aws-access-token",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/aws-access-token/negative-01.txt",
        _text("aws_access_key_id = ZZIA7Q2W4E6R3T5Y7U2P"),
    ),
    "aws-wrong-length": _CoreRecipe(
        "aws-access-token-negative-02",
        "aws-access-token",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/aws-access-token/negative-02.txt",
        _text("aws_access_key_id = AKIA7Q2W4E6R3T5Y7U2"),
    ),
    "aws-explicit-example-suffix": _CoreRecipe(
        "aws-access-token-negative-03",
        "aws-access-token",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/aws-access-token/negative-03.txt",
        _text("aws_access_key_id = AKIA7Q2W4E6R2EXAMPLE"),
    ),
    "aws-akia-high-entropy": _CoreRecipe(
        "aws-access-token-positive-01",
        "aws-access-token",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/aws-access-token/positive-01.txt",
        _text("aws_access_key_id = AKIA7Q2W4E6R3T5Y7U2P"),
    ),
    "aws-asia-high-entropy": _CoreRecipe(
        "aws-access-token-positive-02",
        "aws-access-token",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/aws-access-token/positive-02.txt",
        _text("aws_access_key_id = ASIA3Z5X7C2V4B6N3M5K"),
    ),
    "aws-abia-high-entropy": _CoreRecipe(
        "aws-access-token-positive-03",
        "aws-access-token",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/aws-access-token/positive-03.txt",
        _text("aws_access_key_id = ABIA2P4O6I7U3Y5T2R4E"),
    ),
    "generic-placeholder": _CoreRecipe(
        "generic-api-key-negative-01",
        "generic-api-key",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/generic-api-key/negative-01.txt",
        _text('api_key = "placeholder"'),
    ),
    "generic-low-entropy-alpha": _CoreRecipe(
        "generic-api-key-negative-02",
        "generic-api-key",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/generic-api-key/negative-02.txt",
        _text('api_key = "aaaaaaaaaaaa"'),
    ),
    "generic-too-short": _CoreRecipe(
        "generic-api-key-negative-03",
        "generic-api-key",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/generic-api-key/negative-03.txt",
        _text('api_key = "A1b2C3d4"'),
    ),
    "generic-api-assignment": _CoreRecipe(
        "generic-api-key-positive-01",
        "generic-api-key",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/generic-api-key/positive-01.txt",
        _text('api_key = "S3cUr3ScanF2Alpha9"'),
    ),
    "generic-secret-assignment": _CoreRecipe(
        "generic-api-key-positive-02",
        "generic-api-key",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/generic-api-key/positive-02.txt",
        _text('client_secret = "V4lueQ8mN2pR7tY5"'),
    ),
    "generic-token-assignment": _CoreRecipe(
        "generic-api-key-positive-03",
        "generic-api-key",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/generic-api-key/positive-03.txt",
        _text('service_token = "Z9xC3vB7nM2qW6eR"'),
    ),
    "github-pat-short": _CoreRecipe(
        "github-pat-negative-01",
        "github-pat",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/github-pat/negative-01.txt",
        _text("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"),
    ),
    "github-pat-wrong-prefix": _CoreRecipe(
        "github-pat-negative-02",
        "github-pat",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/github-pat/negative-02.txt",
        _text("ghx_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
    ),
    "github-pat-low-entropy-placeholder": _CoreRecipe(
        "github-pat-negative-03",
        "github-pat",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/github-pat/negative-03.txt",
        _text("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    ),
    "github-pat-high-entropy-a": _CoreRecipe(
        "github-pat-positive-01",
        "github-pat",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/github-pat/positive-01.txt",
        _text("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
    ),
    "github-pat-high-entropy-b": _CoreRecipe(
        "github-pat-positive-02",
        "github-pat",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/github-pat/positive-02.txt",
        _text("ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"),
    ),
    "github-pat-high-entropy-c": _CoreRecipe(
        "github-pat-positive-03",
        "github-pat",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/github-pat/positive-03.txt",
        _text("ghp_M4n7B2v9C5x1Z8a3S6d0F2g7H9j4K1l5P8q3"),
    ),
    "gitlab-pat-short": _CoreRecipe(
        "gitlab-pat-negative-01",
        "gitlab-pat",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/gitlab-pat/negative-01.txt",
        _text("glpat-A1b2C3d4E5f6G7h8I9j"),
    ),
    "gitlab-pat-wrong-prefix": _CoreRecipe(
        "gitlab-pat-negative-02",
        "gitlab-pat",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/gitlab-pat/negative-02.txt",
        _text("glpax-A1b2C3d4E5f6G7h8I9j0"),
    ),
    "gitlab-pat-low-entropy-placeholder": _CoreRecipe(
        "gitlab-pat-negative-03",
        "gitlab-pat",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/gitlab-pat/negative-03.txt",
        _text("glpat-aaaaaaaaaaaaaaaaaaaa"),
    ),
    "gitlab-pat-high-entropy-a": _CoreRecipe(
        "gitlab-pat-positive-01",
        "gitlab-pat",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/gitlab-pat/positive-01.txt",
        _text("glpat-A1b2C3d4E5f6G7h8I9j0"),
    ),
    "gitlab-pat-high-entropy-b": _CoreRecipe(
        "gitlab-pat-positive-02",
        "gitlab-pat",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/gitlab-pat/positive-02.txt",
        _text("glpat-Z9y8X7w6V5u4T3s2R1q0"),
    ),
    "gitlab-pat-high-entropy-c": _CoreRecipe(
        "gitlab-pat-positive-03",
        "gitlab-pat",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/gitlab-pat/positive-03.txt",
        _text("glpat-M4n7B2v9C5x1Z8a3S6d0"),
    ),
    "ordinary-pem-path": _CoreRecipe(
        "pkcs12-file-negative-01",
        "pkcs12-file",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.PATH,
        "corpus/pkcs12-file/negative-01.pem",
        b"SecureScan synthetic ordinary PEM path near-miss.\n",
    ),
    "p12-double-extension": _CoreRecipe(
        "pkcs12-file-negative-02",
        "pkcs12-file",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.PATH,
        "corpus/pkcs12-file/negative-02.p12.txt",
        b"SecureScan synthetic double-extension path near-miss.\n",
    ),
    "similar-p1-extension": _CoreRecipe(
        "pkcs12-file-negative-03",
        "pkcs12-file",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.PATH,
        "corpus/pkcs12-file/negative-03.p1",
        b"SecureScan synthetic similar-extension path near-miss.\n",
    ),
    "empty-p12-file": _CoreRecipe(
        "pkcs12-file-positive-01",
        "pkcs12-file",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.PATH,
        "corpus/pkcs12-file/positive-01.p12",
        b"",
        True,
    ),
    "empty-pfx-file": _CoreRecipe(
        "pkcs12-file-positive-02",
        "pkcs12-file",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.PATH,
        "corpus/pkcs12-file/positive-02.pfx",
        b"",
        True,
    ),
    "binary-p12-file": _CoreRecipe(
        "pkcs12-file-positive-03",
        "pkcs12-file",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.PATH,
        "corpus/pkcs12-file/positive-03.p12",
        b"\x00SECURESCAN_SYNTHETIC_NOT_A_PKCS12\xff\n",
    ),
    "public-key-block": _CoreRecipe(
        "private-key-negative-01",
        "private-key",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/private-key/negative-01.pem",
        b"-----BEGIN PUBLIC KEY-----\nSYNTHETIC-PUBLIC-DATA\n-----END PUBLIC KEY-----\n",
    ),
    "private-key-short-body": _CoreRecipe(
        "private-key-negative-02",
        "private-key",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/private-key/negative-02.pem",
        b"-----BEGIN PRIVATE KEY-----\nSHORT\n-----END PRIVATE KEY-----\n",
    ),
    "private-key-missing-end": _CoreRecipe(
        "private-key-negative-03",
        "private-key",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/private-key/negative-03.pem",
        b"-----BEGIN PRIVATE KEY-----\n"
        + b"SYNTHETIC-NONCRYPTO-DATA-" * 4
        + b"\nNO-CLOSING-DELIMITER\n",
    ),
    "synthetic-pkcs8-private-key-block": _CoreRecipe(
        "private-key-positive-01",
        "private-key",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/private-key/positive-01.pem",
        b"-----BEGIN PRIVATE KEY-----\n"
        + b"SYNTHETIC-NONCRYPTO-PKCS8-DATA-" * 4
        + b"\n-----END PRIVATE KEY-----\n",
    ),
    "synthetic-rsa-private-key-block": _CoreRecipe(
        "private-key-positive-02",
        "private-key",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/private-key/positive-02.pem",
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        + b"SYNTHETIC-NONCRYPTO-RSA-DATA-" * 4
        + b"\n-----END RSA PRIVATE KEY-----\n",
    ),
    "synthetic-ec-private-key-block": _CoreRecipe(
        "private-key-positive-03",
        "private-key",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/private-key/positive-03.pem",
        b"-----BEGIN EC PRIVATE KEY-----\n"
        + b"SYNTHETIC-NONCRYPTO-EC-DATA-" * 4
        + b"\n-----END EC PRIVATE KEY-----\n",
    ),
    "slack-wrong-prefix": _CoreRecipe(
        "slack-bot-token-negative-01",
        "slack-bot-token",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/slack-bot-token/negative-01.txt",
        _text("zoxb-1029384756-5647382910-Aa9Zz7Yy5Xx3Cc1Vv8Bb6Nn4"),
    ),
    "slack-too-short": _CoreRecipe(
        "slack-bot-token-negative-02",
        "slack-bot-token",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/slack-bot-token/negative-02.txt",
        _text("xoxb-12345-67890"),
    ),
    "slack-placeholder": _CoreRecipe(
        "slack-bot-token-negative-03",
        "slack-bot-token",
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/slack-bot-token/negative-03.txt",
        _text("xoxb-0000000000-0000000000-aaaaaaaaaaaaaaaaaaaaaaaa"),
    ),
    "slack-bot-high-entropy-a": _CoreRecipe(
        "slack-bot-token-positive-01",
        "slack-bot-token",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/slack-bot-token/positive-01.txt",
        _text("xoxb-1029384756-5647382910-Aa9Zz7Yy5Xx3Cc1Vv8Bb6Nn4"),
    ),
    "slack-bot-high-entropy-b": _CoreRecipe(
        "slack-bot-token-positive-02",
        "slack-bot-token",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/slack-bot-token/positive-02.txt",
        _text("xoxb-9182736450-1928374650-Qq2Ww4Ee6Rr8Tt1Yy3Uu5Ii7"),
    ),
    "slack-bot-high-entropy-c": _CoreRecipe(
        "slack-bot-token-positive-03",
        "slack-bot-token",
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        GitleaksDetectionKind.CONTENT,
        "corpus/slack-bot-token/positive-03.txt",
        _text("xoxb-3141592653-2718281828-Mm5Nn7Bb9Vv1Cc3Xx6Zz8Aa2"),
    ),
}

_SCOPE_RECIPE_NAME = "github-pat-high-entropy-scope"
_SCOPE_PAYLOAD = _text("ghp_R8s3T6u1V9w4X7y2Z5a0B3c6D9e4F7g2H5j8")
_ENTROPY_FLOOR_BY_RECIPE: Final = {
    "aws-wrong-prefix": 3.0,
    "aws-wrong-length": 3.0,
    "aws-explicit-example-suffix": 3.0,
    "aws-akia-high-entropy": 3.0,
    "aws-asia-high-entropy": 3.0,
    "aws-abia-high-entropy": 3.0,
    "generic-api-assignment": 3.5,
    "generic-secret-assignment": 3.5,
    "generic-token-assignment": 3.5,
    "github-pat-short": 3.0,
    "github-pat-wrong-prefix": 3.0,
    "github-pat-high-entropy-a": 3.0,
    "github-pat-high-entropy-b": 3.0,
    "github-pat-high-entropy-c": 3.0,
    "gitlab-pat-short": 3.0,
    "gitlab-pat-wrong-prefix": 3.0,
    "gitlab-pat-high-entropy-a": 3.0,
    "gitlab-pat-high-entropy-b": 3.0,
    "gitlab-pat-high-entropy-c": 3.0,
    "slack-wrong-prefix": 3.0,
    "slack-bot-high-entropy-a": 3.0,
    "slack-bot-high-entropy-b": 3.0,
    "slack-bot-high-entropy-c": 3.0,
    _SCOPE_RECIPE_NAME: 3.0,
}
_ENTROPY_CEILING_BY_RECIPE: Final = {
    "generic-placeholder": 3.5,
    "generic-low-entropy-alpha": 3.5,
    "generic-too-short": 3.5,
    "github-pat-low-entropy-placeholder": 3.0,
    "gitlab-pat-low-entropy-placeholder": 3.0,
    "slack-placeholder": 3.0,
}
_SCOPE_CASES: Final = {
    "scope-docs-positive": (
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        "corpus/scope/docs/secret.txt",
    ),
    "scope-generated-positive": (
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        "corpus/scope/generated/secret.txt",
    ),
    "scope-node-modules-allowlisted": (
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        "corpus/scope/node_modules/pkg/secret.js",
    ),
    "scope-tests-positive": (
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        "corpus/scope/tests/secret.txt",
    ),
    "scope-unknown-extension-positive": (
        GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        "corpus/scope/unknown/secret.weird",
    ),
    "scope-vendor-allowlisted": (
        GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        "corpus/scope/vendor/github.com/example/pkg/secret.go",
    ),
}


def _has_forbidden_character(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def _valid_relative_path(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or "\\" in value
        or _has_forbidden_character(value)
        or _URL_SCHEME_PATTERN.match(value) is not None
    ):
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def _description(rule_id: str, recipe: str) -> str:
    return f"Pre-scan {rule_id} relation using recipe {recipe}."


def _expected_source_type(
    *,
    scope: bool,
    rule_id: str,
    expectation: GitleaksBenchmarkExpectation,
) -> GitleaksBenchmarkSourceType:
    if scope:
        return GitleaksBenchmarkSourceType.PROJECT_OWNED_SCOPE_SENTINEL
    if rule_id == "pkcs12-file":
        return GitleaksBenchmarkSourceType.PROJECT_OWNED_BINARY_PATH
    if expectation is GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH:
        return GitleaksBenchmarkSourceType.PROJECT_OWNED_NEAR_MISS
    return GitleaksBenchmarkSourceType.PROJECT_OWNED_SYNTHETIC


@dataclass(frozen=True, slots=True)
class GitleaksCorpusPlanCase:
    case_id: str
    description: str
    detection_kind: GitleaksDetectionKind
    expectation: GitleaksBenchmarkExpectation
    fixture_recipe: str
    relative_path: str
    rule_id: str
    source_type: GitleaksBenchmarkSourceType

    def __post_init__(self) -> None:
        if (
            not isinstance(self.case_id, str)
            or _CASE_ID_PATTERN.fullmatch(self.case_id) is None
            or not isinstance(self.description, str)
            or not self.description
            or len(self.description) > _MAX_DESCRIPTION_LENGTH
            or _has_forbidden_character(self.description)
            or not isinstance(self.detection_kind, GitleaksDetectionKind)
            or not isinstance(self.expectation, GitleaksBenchmarkExpectation)
            or not isinstance(self.fixture_recipe, str)
            or _RECIPE_PATTERN.fullmatch(self.fixture_recipe) is None
            or not _valid_relative_path(self.relative_path)
            or not self.relative_path.startswith("corpus/")
            or not isinstance(self.rule_id, str)
            or _RULE_ID_PATTERN.fullmatch(self.rule_id) is None
            or not isinstance(self.source_type, GitleaksBenchmarkSourceType)
        ):
            raise ValueError("Gitleaks corpus plan is invalid")

    def canonical_data(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "description": self.description,
            "detection_kind": self.detection_kind.value,
            "expectation": self.expectation.value,
            "fixture_recipe": self.fixture_recipe,
            "relative_path": self.relative_path,
            "rule_id": self.rule_id,
            "source_type": self.source_type.value,
        }


@dataclass(frozen=True, slots=True)
class GitleaksCorpusPlan:
    baseline_commit: str
    baseline_tag: str
    benchmark_id: str
    binding_artifact_sha256: str
    binding_digest: str
    case_count: int
    cases: tuple[GitleaksCorpusPlanCase, ...]
    contract_sha256: str
    scanner_id: str
    scanner_version: str
    schema_version: str

    def __post_init__(self) -> None:
        if (
            self.baseline_commit != GITLEAKS_V04F1_BASELINE_COMMIT
            or self.baseline_tag != GITLEAKS_V04F1_BASELINE_TAG
            or self.benchmark_id != GITLEAKS_BENCHMARK_ID
            or self.binding_artifact_sha256 != GITLEAKS_BINDING_ARTIFACT_SHA256
            or self.binding_digest != GITLEAKS_BINDING_DIGEST
            or type(self.case_count) is not int
            or self.case_count != GITLEAKS_CORPUS_CASE_COUNT
            or self.contract_sha256 != GITLEAKS_BENCHMARK_CONTRACT_SHA256
            or self.scanner_id != GITLEAKS_SCANNER_ID
            or self.scanner_version != GITLEAKS_VERSION
            or self.schema_version != GITLEAKS_CORPUS_PLAN_SCHEMA_VERSION
            or not isinstance(self.cases, tuple)
            or len(self.cases) != self.case_count
            or any(not isinstance(case, GitleaksCorpusPlanCase) for case in self.cases)
        ):
            raise ValueError("Gitleaks corpus plan is invalid")
        self._validate_cases()

    def _validate_cases(self) -> None:
        case_ids = tuple(case.case_id for case in self.cases)
        paths = tuple(case.relative_path for case in self.cases)
        core_cases = tuple(case for case in self.cases if not case.case_id.startswith("scope-"))
        scope_cases = tuple(case for case in self.cases if case.case_id.startswith("scope-"))

        if (
            case_ids != tuple(sorted(case_ids))
            or len(set(case_ids)) != len(case_ids)
            or len(set(paths)) != len(paths)
            or len(core_cases) != GITLEAKS_CORPUS_CORE_CASE_COUNT
            or len(scope_cases) != GITLEAKS_CORPUS_SCOPE_CASE_COUNT
            or set(case_ids)
            != {recipe.case_id for recipe in _CORE_RECIPES.values()} | set(_SCOPE_CASES)
            or len({case.fixture_recipe for case in core_cases}) != len(core_cases)
        ):
            raise ValueError("Gitleaks corpus plan is invalid")

        counts: dict[str, dict[GitleaksBenchmarkExpectation, int]] = {
            rule_id: {
                GitleaksBenchmarkExpectation.EXPECTED_MATCH: 0,
                GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH: 0,
            }
            for rule_id in GITLEAKS_CORPUS_RULE_IDS
        }
        for case in core_cases:
            recipe = _CORE_RECIPES.get(case.fixture_recipe)
            if recipe is None or (
                case.case_id,
                case.rule_id,
                case.expectation,
                case.detection_kind,
                case.relative_path,
            ) != (
                recipe.case_id,
                recipe.rule_id,
                recipe.expectation,
                recipe.detection_kind,
                recipe.relative_path,
            ):
                raise ValueError("Gitleaks corpus plan is invalid")
            counts[case.rule_id][case.expectation] += 1

        if any(
            per_rule != {
                GitleaksBenchmarkExpectation.EXPECTED_MATCH: 3,
                GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH: 3,
            }
            for per_rule in counts.values()
        ):
            raise ValueError("Gitleaks corpus plan is invalid")

        for case in scope_cases:
            expected = _SCOPE_CASES.get(case.case_id)
            if expected is None or (
                case.rule_id,
                case.expectation,
                case.detection_kind,
                case.fixture_recipe,
                case.relative_path,
            ) != (
                "github-pat",
                expected[0],
                GitleaksDetectionKind.CONTENT,
                _SCOPE_RECIPE_NAME,
                expected[1],
            ):
                raise ValueError("Gitleaks corpus plan is invalid")

        for case in self.cases:
            scope = case.case_id.startswith("scope-")
            if (
                case.description != _description(case.rule_id, case.fixture_recipe)
                or case.source_type
                is not _expected_source_type(
                    scope=scope,
                    rule_id=case.rule_id,
                    expectation=case.expectation,
                )
            ):
                raise ValueError("Gitleaks corpus plan is invalid")

    def canonical_data(self) -> dict[str, object]:
        return {
            "baseline_commit": self.baseline_commit,
            "baseline_tag": self.baseline_tag,
            "benchmark_id": self.benchmark_id,
            "binding_artifact_sha256": self.binding_artifact_sha256,
            "binding_digest": self.binding_digest,
            "case_count": self.case_count,
            "cases": [case.canonical_data() for case in self.cases],
            "contract_sha256": self.contract_sha256,
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
            "schema_version": self.schema_version,
        }

    def canonical_json(self) -> bytes:
        return (
            json.dumps(
                self.canonical_data(),
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError
        document[key] = value
    return document


def _reject_non_finite(_value: str) -> None:
    raise ValueError


def _case_from_document(document: object) -> GitleaksCorpusPlanCase:
    expected_keys = {
        "case_id",
        "description",
        "detection_kind",
        "expectation",
        "fixture_recipe",
        "relative_path",
        "rule_id",
        "source_type",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise ValueError("Gitleaks corpus plan is invalid")
    try:
        return GitleaksCorpusPlanCase(
            case_id=document["case_id"],  # type: ignore[arg-type]
            description=document["description"],  # type: ignore[arg-type]
            detection_kind=GitleaksDetectionKind(document["detection_kind"]),
            expectation=GitleaksBenchmarkExpectation(document["expectation"]),
            fixture_recipe=document["fixture_recipe"],  # type: ignore[arg-type]
            relative_path=document["relative_path"],  # type: ignore[arg-type]
            rule_id=document["rule_id"],  # type: ignore[arg-type]
            source_type=GitleaksBenchmarkSourceType(document["source_type"]),
        )
    except (TypeError, ValueError):
        raise ValueError("Gitleaks corpus plan is invalid") from None


def load_gitleaks_corpus_plan(path: Path) -> GitleaksCorpusPlan:
    expected_keys = {
        "baseline_commit",
        "baseline_tag",
        "benchmark_id",
        "binding_artifact_sha256",
        "binding_digest",
        "case_count",
        "cases",
        "contract_sha256",
        "scanner_id",
        "scanner_version",
        "schema_version",
    }
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ValueError
        payload = path.read_bytes()
        if len(payload) > _MAX_PLAN_BYTES:
            raise ValueError
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
        if not isinstance(document, dict) or set(document) != expected_keys:
            raise ValueError
        raw_cases = document["cases"]
        if not isinstance(raw_cases, list):
            raise ValueError
        plan = GitleaksCorpusPlan(
            baseline_commit=document["baseline_commit"],  # type: ignore[arg-type]
            baseline_tag=document["baseline_tag"],  # type: ignore[arg-type]
            benchmark_id=document["benchmark_id"],  # type: ignore[arg-type]
            binding_artifact_sha256=document["binding_artifact_sha256"],  # type: ignore[arg-type]
            binding_digest=document["binding_digest"],  # type: ignore[arg-type]
            case_count=document["case_count"],  # type: ignore[arg-type]
            cases=tuple(_case_from_document(case) for case in raw_cases),
            contract_sha256=document["contract_sha256"],  # type: ignore[arg-type]
            scanner_id=document["scanner_id"],  # type: ignore[arg-type]
            scanner_version=document["scanner_version"],  # type: ignore[arg-type]
            schema_version=document["schema_version"],  # type: ignore[arg-type]
        )
        if payload != plan.canonical_json():
            raise ValueError
        return plan
    except (OSError, UnicodeDecodeError, TypeError, ValueError):
        raise ValueError("Gitleaks corpus plan is invalid") from None


def corpus_plan_sha256(plan: GitleaksCorpusPlan) -> str:
    if not isinstance(plan, GitleaksCorpusPlan):
        raise ValueError("Gitleaks corpus plan is invalid")
    return hashlib.sha256(plan.canonical_json()).hexdigest()


def _recipe_payload(case: GitleaksCorpusPlanCase) -> bytes:
    if case.fixture_recipe == _SCOPE_RECIPE_NAME:
        payload = _SCOPE_PAYLOAD
        allow_empty = False
    else:
        recipe = _CORE_RECIPES.get(case.fixture_recipe)
        if recipe is None:
            raise ValueError("Gitleaks corpus recipe is invalid")
        payload = recipe.payload
        allow_empty = recipe.allow_empty
    if not payload and not allow_empty:
        raise ValueError("Gitleaks corpus recipe is invalid")
    _validate_recipe_payload(case, payload)
    return payload


def _last_fixture_line(payload: bytes) -> bytes:
    lines = payload.rstrip(b"\n").splitlines()
    if not lines:
        raise ValueError("Gitleaks corpus recipe is invalid")
    return lines[-1]


def _shannon_entropy(value: bytes) -> float:
    if not isinstance(value, bytes):
        raise ValueError("Gitleaks corpus recipe is invalid")
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _entropy_subject(recipe: str, value: bytes) -> bytes:
    if recipe.startswith("aws-"):
        return value.rsplit(b" ", 1)[-1]
    if recipe.startswith("generic-"):
        match = re.fullmatch(rb'[a-z_]+ = "([^"]+)"', value)
        if match is None:
            raise ValueError("Gitleaks corpus recipe is invalid")
        return match.group(1)
    return value


def _validate_recipe_payload(
    case: GitleaksCorpusPlanCase,
    payload: bytes,
) -> None:
    if not isinstance(payload, bytes) or len(payload) > 4096:
        raise ValueError("Gitleaks corpus recipe is invalid")

    recipe = case.fixture_recipe
    value = _last_fixture_line(payload) if payload else b""
    structurally_valid = True

    if recipe.startswith("aws-"):
        candidate = value.rsplit(b" ", 1)[-1]
        if recipe == "aws-wrong-prefix":
            structurally_valid = (
                _AWS_WRONG_PREFIX_PATTERN.fullmatch(candidate) is not None
                and _AWS_ACCESS_TOKEN_PATTERN.fullmatch(candidate) is None
            )
        elif recipe == "aws-wrong-length":
            structurally_valid = (
                _AWS_WRONG_LENGTH_PATTERN.fullmatch(candidate) is not None
                and _AWS_ACCESS_TOKEN_PATTERN.fullmatch(candidate) is None
            )
        elif recipe == "aws-explicit-example-suffix":
            structurally_valid = (
                _AWS_ACCESS_TOKEN_PATTERN.fullmatch(candidate) is not None
                and candidate.endswith(b"EXAMPLE")
            )
        else:
            structurally_valid = (
                recipe
                in {
                    "aws-akia-high-entropy",
                    "aws-asia-high-entropy",
                    "aws-abia-high-entropy",
                }
                and _AWS_ACCESS_TOKEN_PATTERN.fullmatch(candidate) is not None
            )
    elif recipe.startswith("github-pat-"):
        prefix, candidate = value[:4], value[4:]
        structurally_valid = (
            len(candidate) == 35
            if recipe == "github-pat-short"
            else len(candidate) == 36
        ) and prefix in {b"ghp_", b"ghx_"}
    elif recipe.startswith("gitlab-pat-"):
        prefix, candidate = value[:6], value[6:]
        structurally_valid = (
            len(candidate) == 19
            if recipe == "gitlab-pat-short"
            else len(candidate) == 20
        ) and prefix in {b"glpat-", b"glpax-"}
    elif recipe.startswith("generic-"):
        structurally_valid = b" = \"" in value and value.endswith(b'"')
    elif recipe.startswith("slack-"):
        parts = value.split(b"-")
        if recipe == "slack-too-short":
            structurally_valid = (
                len(parts) == 3
                and parts[0] == b"xoxb"
                and all(part.isdigit() for part in parts[1:])
                and all(len(part) < 10 for part in parts[1:])
            )
        else:
            structurally_valid = (
                len(parts) == 4
                and parts[0] in {b"xoxb", b"zoxb"}
                and parts[1].isdigit()
                and parts[2].isdigit()
                and len(parts[1]) == 10
                and len(parts[2]) == 10
                and len(parts[3]) == 24
                and parts[3].isalnum()
            )
    elif case.rule_id == "pkcs12-file":
        structurally_valid = b"-----BEGIN PRIVATE KEY-----" not in payload and (
            b"-----BEGIN CERTIFICATE-----" not in payload
        )
    elif case.rule_id == "private-key":
        is_positive = (
            case.expectation is GitleaksBenchmarkExpectation.EXPECTED_MATCH
        )
        if recipe == "public-key-block":
            structurally_valid = (
                b"-----BEGIN PUBLIC KEY-----" in payload
                and b"PRIVATE KEY" not in payload
            )
        elif recipe == "private-key-short-body":
            structurally_valid = (
                b"\nSHORT\n" in payload
                and payload.count(b"-----BEGIN") == 1
                and payload.count(b"-----END") == 1
            )
        else:
            structurally_valid = (
                b"SYNTHETIC-NONCRYPTO" in payload
                and payload.count(b"-----BEGIN") == 1
                and payload.count(b"-----END") == (1 if is_positive else 0)
            )

    if recipe == _SCOPE_RECIPE_NAME:
        structurally_valid = (
            value.startswith(b"ghp_")
            and len(value.removeprefix(b"ghp_")) == 36
        )

    entropy_subject = _entropy_subject(recipe, value)
    minimum_entropy = _ENTROPY_FLOOR_BY_RECIPE.get(recipe)
    maximum_entropy = _ENTROPY_CEILING_BY_RECIPE.get(recipe)
    if minimum_entropy is not None:
        structurally_valid = structurally_valid and (
            _shannon_entropy(entropy_subject) >= minimum_entropy
        )
    if maximum_entropy is not None:
        structurally_valid = structurally_valid and (
            _shannon_entropy(entropy_subject) < maximum_entropy
        )

    if not structurally_valid:
        raise ValueError("Gitleaks corpus recipe is invalid")


def _safe_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise ValueError("Gitleaks benchmark corpus generation is invalid") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError("Gitleaks benchmark corpus generation is invalid")


def _inventory_corpus(corpus_root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    try:
        _safe_directory(corpus_root)
        for root, directory_names, file_names in os.walk(
            corpus_root,
            topdown=True,
            followlinks=False,
        ):
            root_path = Path(root)
            for name in directory_names:
                directory = root_path / name
                metadata = directory.lstat()
                if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    raise ValueError
                directories.add(directory.relative_to(corpus_root).as_posix())
            for name in file_names:
                file_path = root_path / name
                metadata = file_path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    raise ValueError
                files.add(file_path.relative_to(corpus_root).as_posix())
    except (OSError, ValueError):
        raise ValueError("Gitleaks benchmark corpus generation is invalid") from None
    return files, directories


def _expected_corpus_layout(
    plan: GitleaksCorpusPlan,
) -> tuple[set[str], set[str]]:
    files = {
        PurePosixPath(case.relative_path).relative_to("corpus").as_posix()
        for case in plan.cases
    }
    directories: set[str] = set()
    for relative_path in files:
        parent = PurePosixPath(relative_path).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return files, directories


def _verify_existing_corpus(
    plan: GitleaksCorpusPlan,
    corpus_root: Path,
) -> dict[str, str]:
    expected_files, expected_directories = _expected_corpus_layout(plan)
    actual_files, actual_directories = _inventory_corpus(corpus_root)
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ValueError("Gitleaks benchmark corpus generation is invalid")
    sha256_by_path: dict[str, str] = {}
    for case in plan.cases:
        payload = _recipe_payload(case)
        path = corpus_root.joinpath(
            *PurePosixPath(case.relative_path).relative_to("corpus").parts
        )
        try:
            if path.read_bytes() != payload:
                raise ValueError
        except (OSError, ValueError):
            raise ValueError(
                "Gitleaks benchmark corpus generation is invalid"
            ) from None
        sha256_by_path[case.relative_path] = hashlib.sha256(payload).hexdigest()
    return sha256_by_path


def generate_gitleaks_corpus(
    plan: GitleaksCorpusPlan,
    benchmark_root: Path,
) -> dict[str, str]:
    if not isinstance(plan, GitleaksCorpusPlan) or not isinstance(benchmark_root, Path):
        raise ValueError("Gitleaks benchmark corpus generation is invalid")
    if not benchmark_root.is_absolute():
        raise ValueError("Gitleaks benchmark corpus generation is invalid")
    _safe_directory(benchmark_root)
    corpus_root = benchmark_root / "corpus"
    staging_root = benchmark_root / _STAGING_DIRECTORY_NAME

    if corpus_root.exists() or corpus_root.is_symlink():
        return _verify_existing_corpus(plan, corpus_root)
    if staging_root.exists() or staging_root.is_symlink():
        raise ValueError("Gitleaks benchmark corpus generation is invalid")

    try:
        staging_root.mkdir(mode=0o755)
        for case in plan.cases:
            relative = PurePosixPath(case.relative_path).relative_to("corpus")
            current = staging_root
            for part in relative.parts[:-1]:
                current = current / part
                if current.exists():
                    _safe_directory(current)
                else:
                    current.mkdir(mode=0o755)
            output = staging_root.joinpath(*relative.parts)
            with output.open("xb") as handle:
                handle.write(_recipe_payload(case))
        sha256_by_path = _verify_existing_corpus(plan, staging_root)
        os.replace(staging_root, corpus_root)
        return sha256_by_path
    except (OSError, ValueError):
        if staging_root.exists() and not staging_root.is_symlink():
            shutil.rmtree(staging_root)
        raise ValueError("Gitleaks benchmark corpus generation is invalid") from None


def build_gitleaks_corpus_manifest(
    plan: GitleaksCorpusPlan,
    sha256_by_path: dict[str, str],
) -> GitleaksBenchmarkManifest:
    if set(sha256_by_path) != {case.relative_path for case in plan.cases}:
        raise ValueError("Gitleaks benchmark corpus generation is invalid")
    cases = tuple(
        GitleaksBenchmarkCase(
            case_id=case.case_id,
            description=case.description,
            relative_path=case.relative_path,
            sha256=sha256_by_path[case.relative_path],
            source_type=case.source_type,
            expectation=case.expectation,
            expected_rule_id=case.rule_id,
            expected_detection_kind=case.detection_kind,
        )
        for case in plan.cases
    )
    return build_benchmark_manifest(cases)


def materialize_gitleaks_benchmark(
    repository_root: Path,
) -> GitleaksBenchmarkManifest:
    if not isinstance(repository_root, Path) or not repository_root.is_absolute():
        raise ValueError("Gitleaks benchmark corpus generation is invalid")
    plan_path = repository_root / GITLEAKS_CORPUS_PLAN_PATH
    manifest_path = repository_root / GITLEAKS_CORPUS_MANIFEST_PATH
    benchmark_root = plan_path.parent
    plan = load_gitleaks_corpus_plan(plan_path)
    if corpus_plan_sha256(plan) != GITLEAKS_CORPUS_PLAN_SHA256:
        raise ValueError("Gitleaks benchmark corpus generation is invalid")
    sha256_by_path = generate_gitleaks_corpus(plan, benchmark_root)
    manifest = build_gitleaks_corpus_manifest(plan, sha256_by_path)
    payload = manifest.canonical_json()
    if (
        manifest.corpus_digest != GITLEAKS_CORPUS_DIGEST
        or hashlib.sha256(payload).hexdigest()
        != GITLEAKS_CORPUS_MANIFEST_SHA256
    ):
        raise ValueError("Gitleaks benchmark corpus generation is invalid")

    if manifest_path.exists() or manifest_path.is_symlink():
        try:
            metadata = manifest_path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or manifest_path.read_bytes() != payload
            ):
                raise ValueError
        except (OSError, ValueError):
            raise ValueError("Gitleaks benchmark corpus generation is invalid") from None
        return manifest

    staging_path = benchmark_root / _MANIFEST_STAGING_NAME
    if staging_path.exists() or staging_path.is_symlink():
        raise ValueError("Gitleaks benchmark corpus generation is invalid")
    try:
        with staging_path.open("xb") as handle:
            handle.write(payload)
        os.replace(staging_path, manifest_path)
    except OSError:
        with suppress(OSError):
            staging_path.unlink(missing_ok=True)
        raise ValueError("Gitleaks benchmark corpus generation is invalid") from None
    return manifest


def verify_gitleaks_benchmark(
    repository_root: Path,
) -> GitleaksBenchmarkManifest:
    if not isinstance(repository_root, Path) or not repository_root.is_absolute():
        raise ValueError("Gitleaks benchmark corpus is invalid")

    plan_path = repository_root / GITLEAKS_CORPUS_PLAN_PATH
    manifest_path = repository_root / GITLEAKS_CORPUS_MANIFEST_PATH
    plan = load_gitleaks_corpus_plan(plan_path)
    if corpus_plan_sha256(plan) != GITLEAKS_CORPUS_PLAN_SHA256:
        raise ValueError("Gitleaks benchmark corpus is invalid")

    try:
        sha256_by_path = _verify_existing_corpus(
            plan,
            plan_path.parent / "corpus",
        )
    except ValueError:
        raise ValueError("Gitleaks benchmark corpus is invalid") from None
    expected = build_gitleaks_corpus_manifest(plan, sha256_by_path)
    try:
        actual = load_benchmark_manifest(manifest_path)
        manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    except (OSError, ValueError):
        raise ValueError("Gitleaks benchmark corpus is invalid") from None

    if (
        actual != expected
        or actual.corpus_digest != GITLEAKS_CORPUS_DIGEST
        or manifest_sha256 != GITLEAKS_CORPUS_MANIFEST_SHA256
    ):
        raise ValueError("Gitleaks benchmark corpus is invalid")
    return actual

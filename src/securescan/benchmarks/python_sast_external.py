from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unicodedata
import urllib.request
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

SOURCE_LOCK_SCHEMA_VERSION: Final = "securescan-python-sast-external-source-lock-v1"
INVENTORY_SCHEMA_VERSION: Final = "securescan-python-sast-external-candidates-v2"
SUMMARY_SCHEMA_VERSION: Final = "securescan-python-sast-external-summary-v2"
CANDIDATE_CWES: Final = frozenset({78, 79, 89, 94, 95, 295, 347, 377, 489, 502, 611})
SAMPLE_LIMIT_PER_LABEL: Final = 20
OWASP_SOURCE_ID: Final = "owasp-benchmark-python"
BENCHPROCTOR_SOURCE_ID: Final = "benchproctor-python-quicktest"
EXPECTED_SOURCE_IDS: Final = frozenset({OWASP_SOURCE_ID, BENCHPROCTOR_SOURCE_ID})
OWASP_REPOSITORY_URL: Final = "https://github.com/OWASP-Benchmark/BenchmarkPython.git"
BENCHPROCTOR_REPOSITORY_URL: Final = "https://github.com/TheAuditorTool/BenchProctor.git"
BENCHPROCTOR_RELEASE: Final = "2026.07.22"
OWASP_RELEASE: Final = "preliminary-v0.1"
OWASP_EXPECTED_RESULTS_METADATA: Final = (
    "# test name, category, real vulnerability, cwe, Benchmark version: 0.1, 2026-01-9"
)
OWASP_KNOWN_ISSUE_URL: Final = (
    "https://github.com/OWASP-Benchmark/BenchmarkPython/pull/6"
)
OWASP_CROSS_CATEGORY_XSS_CASE_IDS: Final = frozenset(
    {
        "BenchmarkTest00079",
        "BenchmarkTest00081",
        "BenchmarkTest00269",
        "BenchmarkTest00270",
        "BenchmarkTest00271",
        "BenchmarkTest00433",
        "BenchmarkTest00434",
        "BenchmarkTest00435",
        "BenchmarkTest00513",
        "BenchmarkTest00514",
        "BenchmarkTest00608",
        "BenchmarkTest00609",
        "BenchmarkTest00658",
        "BenchmarkTest00659",
        "BenchmarkTest00660",
        "BenchmarkTest00827",
        "BenchmarkTest00828",
        "BenchmarkTest00901",
        "BenchmarkTest00902",
        "BenchmarkTest00903",
        "BenchmarkTest00904",
        "BenchmarkTest00994",
        "BenchmarkTest00995",
        "BenchmarkTest00996",
        "BenchmarkTest00997",
        "BenchmarkTest00998",
        "BenchmarkTest00999",
        "BenchmarkTest01099",
        "BenchmarkTest01100",
        "BenchmarkTest01101",
        "BenchmarkTest01102",
        "BenchmarkTest01174",
        "BenchmarkTest01228",
    }
)

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_CASE_ID_PATTERN = re.compile(r"BenchmarkTest[0-9]{5}\Z", re.ASCII)
_CATEGORY_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)
_SOURCE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z", re.ASCII)
_LOCK_FIELDS = frozenset({"schema_version", "sources"})
_SOURCE_FIELDS = frozenset(
    {
        "artifact",
        "cache_path",
        "expected_results",
        "frameworks",
        "immutable_identity",
        "license",
        "release",
        "source_id",
        "source_type",
        "upstream_url",
        "verification_artifacts",
    }
)
_ARTIFACT_FIELDS = frozenset({"identity", "kind", "relative_path", "sha256", "url"})
_IMMUTABLE_FIELDS = frozenset({"kind", "value"})
_EXPECTED_RESULTS_FIELDS = frozenset(
    {"framework", "identity", "metadata", "relative_path", "sha256"}
)
_VERIFICATION_FIELDS = frozenset({"identity", "relative_path", "sha256", "url"})
_CANDIDATE_FIELDS = frozenset(
    {
        "candidate_id",
        "category",
        "cwe",
        "external_case_id",
        "external_source_id",
        "framework",
        "ground_truth_status",
        "known_issue",
        "license",
        "provenance",
        "relative_source_path",
        "scoring_status",
        "source_sha256",
        "upstream_label",
        "upstream_version_id",
    }
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_document(value: object) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _load_json(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("external benchmark JSON is invalid") from exc


def _bounded_text(value: object, maximum: int = 512) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 1 <= len(value) <= maximum
        and not any(unicodedata.category(character).startswith("C") for character in value)
    )


def _valid_relative_path(value: object, *, allow_dot: bool = False) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    if allow_dot and value == ".":
        return True
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
        and not any(unicodedata.category(character).startswith("C") for character in value)
    )


def _require_sha256(value: object) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError("external benchmark SHA-256 is invalid")
    return value


@dataclass(frozen=True, slots=True, order=True)
class ArtifactIdentity:
    identity: str
    kind: str
    relative_path: str
    sha256: str
    url: str

    def canonical_data(self) -> dict[str, str]:
        return {
            "identity": self.identity,
            "kind": self.kind,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "url": self.url,
        }


@dataclass(frozen=True, slots=True, order=True)
class ExpectedResultsIdentity:
    framework: str
    identity: str
    metadata: str
    relative_path: str
    sha256: str

    def canonical_data(self) -> dict[str, str]:
        return {
            "framework": self.framework,
            "identity": self.identity,
            "metadata": self.metadata,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True, order=True)
class VerificationIdentity:
    identity: str
    relative_path: str
    sha256: str
    url: str

    def canonical_data(self) -> dict[str, str]:
        return {
            "identity": self.identity,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "url": self.url,
        }


@dataclass(frozen=True, slots=True, order=True)
class LockedSource:
    source_id: str
    source_type: str
    upstream_url: str
    cache_path: str
    immutable_kind: str
    immutable_value: str
    release: str
    license: str
    frameworks: tuple[str, ...]
    artifact: ArtifactIdentity
    expected_results: tuple[ExpectedResultsIdentity, ...]
    verification_artifacts: tuple[VerificationIdentity, ...]

    def canonical_data(self) -> dict[str, object]:
        return {
            "artifact": self.artifact.canonical_data(),
            "cache_path": self.cache_path,
            "expected_results": [item.canonical_data() for item in self.expected_results],
            "frameworks": list(self.frameworks),
            "immutable_identity": {
                "kind": self.immutable_kind,
                "value": self.immutable_value,
            },
            "license": self.license,
            "release": self.release,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "upstream_url": self.upstream_url,
            "verification_artifacts": [
                item.canonical_data() for item in self.verification_artifacts
            ],
        }


@dataclass(frozen=True, slots=True)
class SourceLock:
    schema_version: str
    sources: tuple[LockedSource, ...]

    def canonical_data(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sources": [source.canonical_data() for source in self.sources],
        }

    def source(self, source_id: str) -> LockedSource:
        try:
            return next(source for source in self.sources if source.source_id == source_id)
        except StopIteration as exc:
            raise ValueError("external benchmark source is unrecognized") from exc


def source_lock_digest(source_lock: SourceLock) -> str:
    if not isinstance(source_lock, SourceLock):
        raise ValueError("external benchmark source lock is invalid")
    return hashlib.sha256(_canonical_json(source_lock.canonical_data())).hexdigest()


def _parse_artifact(raw: object) -> ArtifactIdentity:
    if not isinstance(raw, dict) or set(raw) != _ARTIFACT_FIELDS:
        raise ValueError
    artifact = ArtifactIdentity(**raw)
    if (
        not _bounded_text(artifact.identity, 160)
        or artifact.kind not in {"git-tree", "zip"}
        or not _valid_relative_path(artifact.relative_path, allow_dot=True)
        or _SHA256_PATTERN.fullmatch(artifact.sha256) is None
        or not artifact.url.startswith("https://")
    ):
        raise ValueError
    return artifact


def _parse_expected_results(raw: object) -> ExpectedResultsIdentity:
    if not isinstance(raw, dict) or set(raw) != _EXPECTED_RESULTS_FIELDS:
        raise ValueError
    identity = ExpectedResultsIdentity(**raw)
    if (
        not _CATEGORY_PATTERN.fullmatch(identity.framework)
        or not _bounded_text(identity.identity, 160)
        or not _bounded_text(identity.metadata, 240)
        or not _valid_relative_path(identity.relative_path)
        or _SHA256_PATTERN.fullmatch(identity.sha256) is None
    ):
        raise ValueError
    return identity


def _parse_verification(raw: object) -> VerificationIdentity:
    if not isinstance(raw, dict) or set(raw) != _VERIFICATION_FIELDS:
        raise ValueError
    identity = VerificationIdentity(**raw)
    if (
        not _bounded_text(identity.identity, 160)
        or not _valid_relative_path(identity.relative_path)
        or _SHA256_PATTERN.fullmatch(identity.sha256) is None
        or not identity.url.startswith("https://")
    ):
        raise ValueError
    return identity


def _parse_source(raw: object) -> LockedSource:
    if not isinstance(raw, dict) or set(raw) != _SOURCE_FIELDS:
        raise ValueError
    immutable = raw["immutable_identity"]
    raw_expected_results = raw["expected_results"]
    raw_verification = raw["verification_artifacts"]
    raw_frameworks = raw["frameworks"]
    if (
        not isinstance(immutable, dict)
        or set(immutable) != _IMMUTABLE_FIELDS
        or not isinstance(raw_expected_results, list)
        or not isinstance(raw_verification, list)
        or not isinstance(raw_frameworks, list)
    ):
        raise ValueError
    source = LockedSource(
        source_id=raw["source_id"],
        source_type=raw["source_type"],
        upstream_url=raw["upstream_url"],
        cache_path=raw["cache_path"],
        immutable_kind=immutable["kind"],
        immutable_value=immutable["value"],
        release=raw["release"],
        license=raw["license"],
        frameworks=tuple(raw_frameworks),
        artifact=_parse_artifact(raw["artifact"]),
        expected_results=tuple(_parse_expected_results(item) for item in raw_expected_results),
        verification_artifacts=tuple(_parse_verification(item) for item in raw_verification),
    )
    moving_reference_markers = ("/main/", "/master/", "/heads/", "?ref=main", "?ref=master")
    if (
        not isinstance(source.source_id, str)
        or _SOURCE_ID_PATTERN.fullmatch(source.source_id) is None
        or source.source_type not in {"git-commit", "release-bundle"}
        or not source.upstream_url.startswith("https://")
        or not _valid_relative_path(source.cache_path)
        or source.immutable_kind != "git-commit"
        or not isinstance(source.immutable_value, str)
        or _COMMIT_PATTERN.fullmatch(source.immutable_value) is None
        or not _bounded_text(source.release, 64)
        or source.license not in {"GPL-3.0", "Apache-2.0"}
        or not source.frameworks
        or any(_CATEGORY_PATTERN.fullmatch(item) is None for item in source.frameworks)
        or source.frameworks != tuple(sorted(set(source.frameworks)))
        or not source.expected_results
        or source.expected_results
        != tuple(sorted(set(source.expected_results), key=lambda item: item.framework))
        or source.verification_artifacts
        != tuple(sorted(set(source.verification_artifacts), key=lambda item: item.identity))
        or source.immutable_value not in source.artifact.url
        or any(marker in source.artifact.url for marker in moving_reference_markers)
        or any(
            source.immutable_value not in item.url
            or any(marker in item.url for marker in moving_reference_markers)
            for item in source.verification_artifacts
        )
    ):
        raise ValueError
    return source


def _validate_known_sources(source_lock: SourceLock) -> None:
    if {source.source_id for source in source_lock.sources} != EXPECTED_SOURCE_IDS:
        raise ValueError
    owasp = source_lock.source(OWASP_SOURCE_ID)
    benchproctor = source_lock.source(BENCHPROCTOR_SOURCE_ID)
    if (
        owasp.source_type != "git-commit"
        or owasp.upstream_url != OWASP_REPOSITORY_URL
        or owasp.release != OWASP_RELEASE
        or owasp.license != "GPL-3.0"
        or owasp.frameworks != ("flask",)
        or owasp.artifact.kind != "git-tree"
        or len(owasp.expected_results) != 1
        or owasp.expected_results[0].metadata != OWASP_EXPECTED_RESULTS_METADATA
        or benchproctor.source_type != "release-bundle"
        or benchproctor.upstream_url != BENCHPROCTOR_REPOSITORY_URL
        or benchproctor.release != BENCHPROCTOR_RELEASE
        or benchproctor.license != "Apache-2.0"
        or benchproctor.frameworks != ("django", "fastapi", "flask")
        or benchproctor.artifact.kind != "zip"
        or tuple(item.framework for item in benchproctor.expected_results)
        != benchproctor.frameworks
    ):
        raise ValueError


def load_source_lock(path: Path) -> SourceLock:
    try:
        raw = _load_json(path)
        if not isinstance(raw, dict) or set(raw) != _LOCK_FIELDS:
            raise ValueError
        raw_sources = raw["sources"]
        if not isinstance(raw_sources, list):
            raise ValueError
        sources = tuple(_parse_source(item) for item in raw_sources)
        source_lock = SourceLock(schema_version=raw["schema_version"], sources=sources)
        if (
            source_lock.schema_version != SOURCE_LOCK_SCHEMA_VERSION
            or sources != tuple(sorted(set(sources), key=lambda item: item.source_id))
            or len({source.source_id for source in sources}) != len(sources)
        ):
            raise ValueError
        _validate_known_sources(source_lock)
        if path.read_bytes() != canonical_document(source_lock.canonical_data()):
            raise ValueError
        return source_lock
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("external benchmark source lock is invalid") from exc


def _regular_file(root: Path, relative_path: str, expected_sha256: str | None = None) -> Path:
    if not _valid_relative_path(relative_path):
        raise ValueError("external benchmark path is invalid")
    try:
        resolved_root = root.resolve(strict=True)
        candidate = root.joinpath(*PurePosixPath(relative_path).parts)
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("external benchmark file is invalid") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved != candidate.absolute()
    ):
        raise ValueError("external benchmark file is invalid")
    if expected_sha256 is not None and _sha256_file(candidate) != expected_sha256:
        raise ValueError("external benchmark checksum mismatch")
    return candidate


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ValueError("external benchmark file is invalid") from exc
    return digest.hexdigest()


def owasp_relevant_tree_digest(root: Path) -> str:
    paths = [Path("expectedresults-0.1.csv")]
    try:
        paths.extend(
            path.relative_to(root)
            for path in sorted(
                (root / "testcode").glob("BenchmarkTest[0-9][0-9][0-9][0-9][0-9].py")
            )
        )
    except (OSError, ValueError) as exc:
        raise ValueError("OWASP BenchmarkPython source tree is invalid") from exc
    entries = []
    for path in paths:
        relative_path = path.as_posix()
        file = _regular_file(root, relative_path)
        entries.append({"relative_path": relative_path, "sha256": _sha256_file(file)})
    return hashlib.sha256(_canonical_json(entries)).hexdigest()


@dataclass(frozen=True, slots=True, order=True)
class ExternalGroundTruth:
    source_id: str
    external_case_id: str
    cwe: int
    upstream_label: str
    category: str
    framework: str
    relative_source_path: str
    upstream_version_id: str
    license: str
    ground_truth_status: str = "accepted"
    known_issue: str | None = None
    scoring_status: str = "pending-applicability-review"

    @property
    def immutable_case_id(self) -> str:
        return (
            f"{self.source_id}:{self.upstream_version_id}:"
            f"{self.framework}:{self.external_case_id}"
        )


def _read_csv_rows(path: Path) -> list[list[str]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as source:
            return list(csv.reader(source))
    except (OSError, UnicodeError, csv.Error) as exc:
        raise ValueError("external benchmark expected results are invalid") from exc


def _parse_ground_truth_row(
    row: list[str],
    *,
    source_id: str,
    framework: str,
    version: str,
    license_identifier: str,
    relative_source_path: str,
    known_issue: str | None,
) -> ExternalGroundTruth:
    if len(row) != 4:
        raise ValueError("external benchmark ground truth row is invalid")
    case_id, category, raw_label, raw_cwe = row
    if (
        _CASE_ID_PATTERN.fullmatch(case_id) is None
        or _CATEGORY_PATTERN.fullmatch(category) is None
        or raw_label not in {"true", "false"}
        or not raw_cwe.isascii()
        or not raw_cwe.isdecimal()
        or raw_cwe.startswith("0")
    ):
        raise ValueError("external benchmark ground truth row is invalid")
    cwe = int(raw_cwe)
    if not 1 <= cwe <= 9999:
        raise ValueError("external benchmark ground truth row is invalid")
    return ExternalGroundTruth(
        source_id=source_id,
        external_case_id=case_id,
        cwe=cwe,
        upstream_label="vulnerable" if raw_label == "true" else "safe",
        category=category,
        framework=framework,
        relative_source_path=relative_source_path,
        upstream_version_id=version,
        license=license_identifier,
        ground_truth_status="accepted",
        known_issue=known_issue,
        scoring_status=(
            "excluded-known-benchmark-contamination"
            if known_issue is not None
            else "pending-applicability-review"
        ),
    )


def parse_owasp_expected_results(
    root: Path,
    identity: ExpectedResultsIdentity,
    *,
    required_known_contaminated_case_ids: frozenset[str] = (
        OWASP_CROSS_CATEGORY_XSS_CASE_IDS
    ),
) -> tuple[ExternalGroundTruth, ...]:
    path = _regular_file(root, identity.relative_path, identity.sha256)
    rows = _read_csv_rows(path)
    if not rows or ",".join(rows[0]) != identity.metadata:
        raise ValueError("OWASP BenchmarkPython expected-results metadata is invalid")
    parsed: list[ExternalGroundTruth] = []
    seen: set[str] = set()
    for row in rows[1:]:
        if not row or row == []:
            raise ValueError("OWASP BenchmarkPython expected results contain an empty row")
        case_id = row[0] if row else ""
        relative_path = f"testcode/{case_id}.py"
        item = _parse_ground_truth_row(
            row,
            source_id=OWASP_SOURCE_ID,
            framework=identity.framework,
            version=OWASP_RELEASE,
            license_identifier="GPL-3.0",
            relative_source_path=relative_path,
            known_issue=(
                "cross-category-xss-contamination"
                if case_id in required_known_contaminated_case_ids
                else None
            ),
        )
        if item.immutable_case_id in seen:
            raise ValueError("duplicate external benchmark case identity")
        seen.add(item.immutable_case_id)
        _regular_file(root, relative_path)
        parsed.append(item)
    if seen.intersection(
        f"{OWASP_SOURCE_ID}:{OWASP_RELEASE}:flask:{case_id}"
        for case_id in required_known_contaminated_case_ids
    ) != {
        f"{OWASP_SOURCE_ID}:{OWASP_RELEASE}:flask:{case_id}"
        for case_id in required_known_contaminated_case_ids
    }:
        raise ValueError("OWASP BenchmarkPython known-issue evidence is incomplete")
    return tuple(parsed)


def parse_benchproctor_expected_results(
    root: Path,
    identity: ExpectedResultsIdentity,
    *,
    release: str,
    expected_case_count: int = 6100,
) -> tuple[ExternalGroundTruth, ...]:
    if (
        not isinstance(expected_case_count, int)
        or isinstance(expected_case_count, bool)
        or expected_case_count < 1
    ):
        raise ValueError("BenchProctor expected case count is invalid")
    path = _regular_file(root, identity.relative_path, identity.sha256)
    rows = _read_csv_rows(path)
    expected_comments = [
        ["# test name", "category", "real vulnerability", "CWE"],
        [identity.metadata],
        [f"# {expected_case_count} test cases generated 2026-07-22"],
        [f"# language=python framework={identity.framework} shape=standalone"],
    ]
    if rows[:4] != expected_comments:
        raise ValueError("BenchProctor expected-results metadata is invalid")
    parsed: list[ExternalGroundTruth] = []
    seen: set[str] = set()
    for row in rows[4:]:
        case_id = row[0] if row else ""
        filename = case_id.removeprefix("BenchmarkTest")
        relative_path = f"{identity.framework}/testcode/benchmark_test_{filename}.py"
        item = _parse_ground_truth_row(
            row,
            source_id=BENCHPROCTOR_SOURCE_ID,
            framework=identity.framework,
            version=release,
            license_identifier="Apache-2.0",
            relative_source_path=relative_path,
            known_issue=None,
        )
        if item.immutable_case_id in seen:
            raise ValueError("duplicate external benchmark case identity")
        seen.add(item.immutable_case_id)
        _regular_file(root, relative_path)
        parsed.append(item)
    if len(parsed) != expected_case_count:
        raise ValueError("BenchProctor expected-results case count is invalid")
    return tuple(parsed)


def _verify_benchproctor_manifest(root: Path, source: LockedSource) -> None:
    manifest_identity = next(
        (
            identity
            for identity in source.verification_artifacts
            if identity.identity == "benchproctor-manifest.json"
        ),
        None,
    )
    if manifest_identity is None:
        raise ValueError("BenchProctor manifest identity is missing")
    manifest_path = _regular_file(
        root, manifest_identity.relative_path, manifest_identity.sha256
    )
    raw = _load_json(manifest_path)
    manifest_fields = frozenset(
        {
            "benchmark",
            "frameworks",
            "generator_version",
            "language",
            "scorer",
            "suites",
            "tier",
            "version",
        }
    )
    scorer_fields = frozenset({"file", "sha256"})
    suite_fields = frozenset(
        {
            "categories",
            "csv_sha256",
            "expectedresults_csv",
            "safe",
            "testcode_files",
            "total",
            "vulnerable",
        }
    )
    if not isinstance(raw, dict) or set(raw) != manifest_fields:
        raise ValueError("BenchProctor manifest is invalid")
    scorer = raw["scorer"]
    suites = raw["suites"]
    if (
        raw["benchmark"] != "benchproctor"
        or raw["frameworks"] != list(source.frameworks)
        or raw["generator_version"] != "0.13.3"
        or raw["language"] != "python"
        or raw["tier"] != "quicktest"
        or raw["version"] != source.release
        or not isinstance(scorer, dict)
        or set(scorer) != scorer_fields
        or scorer.get("file") != "score_sarif.py"
        or _SHA256_PATTERN.fullmatch(str(scorer.get("sha256"))) is None
        or not isinstance(suites, dict)
        or set(suites) != set(source.frameworks)
    ):
        raise ValueError("BenchProctor manifest is invalid")
    expected_by_framework = {item.framework: item for item in source.expected_results}
    for framework in source.frameworks:
        suite = suites[framework]
        if (
            not isinstance(suite, dict)
            or set(suite) != suite_fields
            or suite["categories"] != 61
            or suite["csv_sha256"] != expected_by_framework[framework].sha256
            or suite["expectedresults_csv"] != f"expectedresults-{source.release}.csv"
            or suite["safe"] != 3050
            or suite["total"] != 6100
            or suite["vulnerable"] != 3050
            or suite["testcode_files"] not in {6101, 6102}
        ):
            raise ValueError("BenchProctor manifest suite is invalid")
    _regular_file(root, "score_sarif.py", str(scorer["sha256"]))


def _git_output(repository: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(repository), *arguments],
            check=True,
            capture_output=True,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("external benchmark Git identity is invalid") from exc
    return result.stdout.strip()


def _verify_owasp_source(source_root: Path, source: LockedSource) -> None:
    if (
        _git_output(source_root, "rev-parse", "HEAD^{commit}")
        != source.immutable_value
        or _git_output(source_root, "remote", "get-url", "origin")
        != source.upstream_url
        or _git_output(source_root, "rev-parse", "--abbrev-ref", "HEAD") != "HEAD"
    ):
        raise ValueError("OWASP BenchmarkPython immutable identity is invalid")
    if owasp_relevant_tree_digest(source_root) != source.artifact.sha256:
        raise ValueError("OWASP BenchmarkPython relevant tree checksum mismatch")


def _verify_published_file(
    source_root: Path, identity: VerificationIdentity
) -> None:
    _regular_file(source_root, identity.relative_path, identity.sha256)


def _verify_benchproctor_checksum_contents(root: Path, source: LockedSource) -> None:
    identities = {item.identity: item for item in source.verification_artifacts}
    try:
        sidecar_identity = identities["python-quicktest-sha256-sidecar"]
        aggregate_identity = identities["release-shasums256"]
        sidecar = _regular_file(
            root, sidecar_identity.relative_path, sidecar_identity.sha256
        ).read_text(encoding="ascii")
        aggregate = _regular_file(
            root, aggregate_identity.relative_path, aggregate_identity.sha256
        ).read_text(encoding="ascii")
    except (KeyError, OSError, UnicodeError) as exc:
        raise ValueError("BenchProctor checksum evidence is invalid") from exc
    expected_sidecar = f"{source.artifact.sha256}  {source.artifact.identity}"
    expected_aggregate = (
        f"{source.artifact.sha256}  quicktest/python/{source.artifact.identity}"
    )
    if (
        sidecar.splitlines() != [expected_sidecar]
        or expected_aggregate not in aggregate.splitlines()
    ):
        raise ValueError("BenchProctor checksum evidence is invalid")


def verify_external_sources(cache_root: Path, source_lock: SourceLock) -> None:
    if not isinstance(cache_root, Path) or not isinstance(source_lock, SourceLock):
        raise ValueError("external benchmark source verification is invalid")
    owasp = source_lock.source(OWASP_SOURCE_ID)
    benchproctor = source_lock.source(BENCHPROCTOR_SOURCE_ID)
    owasp_root = cache_root / owasp.cache_path
    benchproctor_root = cache_root / benchproctor.cache_path
    _verify_owasp_source(owasp_root, owasp)
    for identity in owasp.verification_artifacts:
        _verify_published_file(owasp_root, identity)
    _regular_file(
        cache_root,
        f"{benchproctor.cache_path}/{benchproctor.artifact.relative_path}",
        benchproctor.artifact.sha256,
    )
    for identity in benchproctor.verification_artifacts:
        _verify_published_file(benchproctor_root, identity)
    _verify_benchproctor_checksum_contents(benchproctor_root, benchproctor)
    _verify_benchproctor_manifest(benchproctor_root, benchproctor)


@dataclass(frozen=True, slots=True, order=True)
class Candidate:
    candidate_id: str
    category: str
    cwe: int
    external_case_id: str
    external_source_id: str
    framework: str
    ground_truth_status: str
    known_issue: str | None
    license: str
    provenance: str
    relative_source_path: str
    scoring_status: str
    source_sha256: str
    upstream_label: str
    upstream_version_id: str

    def __post_init__(self) -> None:
        if (
            not _bounded_text(self.candidate_id, 240)
            or _CATEGORY_PATTERN.fullmatch(self.category) is None
            or self.cwe not in CANDIDATE_CWES
            or _CASE_ID_PATTERN.fullmatch(self.external_case_id) is None
            or self.external_source_id not in EXPECTED_SOURCE_IDS
            or _CATEGORY_PATTERN.fullmatch(self.framework) is None
            or self.ground_truth_status != "accepted"
            or self.known_issue not in {None, "cross-category-xss-contamination"}
            or self.license not in {"GPL-3.0", "Apache-2.0"}
            or self.provenance
            != f"sources.lock.json#{self.external_source_id}"
            or not _valid_relative_path(self.relative_source_path)
            or self.scoring_status
            not in {
                "excluded-known-benchmark-contamination",
                "pending-applicability-review",
            }
            or (
                (self.known_issue is None)
                != (self.scoring_status == "pending-applicability-review")
            )
            or _SHA256_PATTERN.fullmatch(self.source_sha256) is None
            or self.upstream_label not in {"safe", "vulnerable"}
            or not _bounded_text(self.upstream_version_id, 64)
        ):
            raise ValueError("external benchmark candidate is invalid")

    def canonical_data(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "category": self.category,
            "cwe": self.cwe,
            "external_case_id": self.external_case_id,
            "external_source_id": self.external_source_id,
            "framework": self.framework,
            "ground_truth_status": self.ground_truth_status,
            "known_issue": self.known_issue,
            "license": self.license,
            "provenance": self.provenance,
            "relative_source_path": self.relative_source_path,
            "scoring_status": self.scoring_status,
            "source_sha256": self.source_sha256,
            "upstream_label": self.upstream_label,
            "upstream_version_id": self.upstream_version_id,
        }


def filter_candidate_ground_truth(
    ground_truth: tuple[ExternalGroundTruth, ...],
) -> tuple[ExternalGroundTruth, ...]:
    if not isinstance(ground_truth, tuple) or any(
        not isinstance(item, ExternalGroundTruth) for item in ground_truth
    ):
        raise ValueError("external benchmark ground truth is invalid")
    return tuple(item for item in ground_truth if item.cwe in CANDIDATE_CWES)


def deterministic_review_sample(
    ground_truth: tuple[ExternalGroundTruth, ...],
    *,
    limit_per_label: int = SAMPLE_LIMIT_PER_LABEL,
) -> tuple[ExternalGroundTruth, ...]:
    if (
        not isinstance(limit_per_label, int)
        or isinstance(limit_per_label, bool)
        or limit_per_label < 1
    ):
        raise ValueError("external benchmark sample limit is invalid")
    groups: dict[tuple[str, str, int, str], list[ExternalGroundTruth]] = defaultdict(list)
    for item in ground_truth:
        if not isinstance(item, ExternalGroundTruth):
            raise ValueError("external benchmark ground truth is invalid")
        groups[(item.source_id, item.framework, item.cwe, item.upstream_label)].append(item)
    selected: list[ExternalGroundTruth] = []
    for key in sorted(groups):
        ranked = sorted(
            groups[key],
            key=lambda item: (
                hashlib.sha256(item.immutable_case_id.encode("utf-8")).hexdigest(),
                item.immutable_case_id,
            ),
        )
        selected.extend(ranked[:limit_per_label])
    return tuple(sorted(selected, key=lambda item: item.immutable_case_id))


def _candidate_from_ground_truth(root: Path, item: ExternalGroundTruth) -> Candidate:
    source_path = _regular_file(root, item.relative_source_path)
    candidate_id = f"{item.source_id}/{item.framework}/{item.external_case_id}"
    return Candidate(
        candidate_id=candidate_id,
        category=item.category,
        cwe=item.cwe,
        external_case_id=item.external_case_id,
        external_source_id=item.source_id,
        framework=item.framework,
        ground_truth_status=item.ground_truth_status,
        known_issue=item.known_issue,
        license=item.license,
        provenance=f"sources.lock.json#{item.source_id}",
        relative_source_path=item.relative_source_path,
        scoring_status=item.scoring_status,
        source_sha256=_sha256_file(source_path),
        upstream_label=item.upstream_label,
        upstream_version_id=item.upstream_version_id,
    )


def candidate_inventory_data(
    candidates: tuple[Candidate, ...], source_digest: str
) -> dict[str, object]:
    _require_sha256(source_digest)
    if (
        not isinstance(candidates, tuple)
        or any(not isinstance(candidate, Candidate) for candidate in candidates)
        or candidates != tuple(sorted(candidates, key=lambda item: item.candidate_id))
        or len({candidate.candidate_id for candidate in candidates}) != len(candidates)
    ):
        raise ValueError("external benchmark candidate inventory is invalid")
    return {
        "candidates": [candidate.canonical_data() for candidate in candidates],
        "sampling": {
            "benchproctor": (
                "first 20 per source/framework/CWE/label by SHA-256 ordering "
                "of immutable external case identity"
            ),
            "owasp": "all matching-CWE candidates",
        },
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "source_lock_digest": source_digest,
    }


def candidate_inventory_digest(inventory: dict[str, object]) -> str:
    if (
        not isinstance(inventory, dict)
        or set(inventory) != {"candidates", "sampling", "schema_version", "source_lock_digest"}
        or inventory.get("schema_version") != INVENTORY_SCHEMA_VERSION
    ):
        raise ValueError("external benchmark candidate inventory is invalid")
    return hashlib.sha256(_canonical_json(inventory)).hexdigest()


def _counts(
    items: tuple[ExternalGroundTruth, ...], attribute: str
) -> dict[str, int]:
    values = Counter(str(getattr(item, attribute)) for item in items)
    return dict(sorted(values.items()))


def _dimension_counts(
    full: tuple[ExternalGroundTruth, ...], sampled: tuple[ExternalGroundTruth, ...], attribute: str
) -> dict[str, dict[str, int]]:
    full_counts = _counts(full, attribute)
    sampled_counts = _counts(sampled, attribute)
    keys = sorted(set(full_counts) | set(sampled_counts))
    return {
        key: {"full": full_counts.get(key, 0), "review_sample": sampled_counts.get(key, 0)}
        for key in keys
    }


def candidate_summary_data(
    source_lock: SourceLock,
    full: tuple[ExternalGroundTruth, ...],
    sampled: tuple[ExternalGroundTruth, ...],
    inventory_digest: str,
) -> dict[str, object]:
    digest = source_lock_digest(source_lock)
    _require_sha256(inventory_digest)
    cwe_counts = _dimension_counts(full, sampled, "cwe")
    for cwe in CANDIDATE_CWES:
        cwe_counts.setdefault(str(cwe), {"full": 0, "review_sample": 0})
    selection_ids = sorted(
        f"{item.source_id}/{item.framework}/{item.external_case_id}" for item in sampled
    )
    return {
        "candidate_counts_by_cwe": dict(sorted(cwe_counts.items())),
        "candidate_counts_by_framework": _dimension_counts(full, sampled, "framework"),
        "candidate_counts_by_label": _dimension_counts(full, sampled, "upstream_label"),
        "candidate_counts_by_source": _dimension_counts(full, sampled, "source_id"),
        "candidate_inventory_digest": inventory_digest,
        "known_contaminated_excluded_case_count": {
            "full": sum(
                item.scoring_status == "excluded-known-benchmark-contamination"
                for item in full
            ),
            "review_sample": sum(
                item.scoring_status == "excluded-known-benchmark-contamination"
                for item in sampled
            ),
        },
        "full_candidate_count": len(full),
        "review_sample_count": len(sampled),
        "review_selection_digest": hashlib.sha256(
            _canonical_json(selection_ids)
        ).hexdigest(),
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "source_identities": [
            {
                "immutable_identity": source.immutable_value,
                "release": source.release,
                "source_id": source.source_id,
            }
            for source in source_lock.sources
        ],
        "source_lock_digest": digest,
    }


def build_candidate_evidence(
    cache_root: Path, source_lock: SourceLock
) -> tuple[dict[str, object], dict[str, object]]:
    verify_external_sources(cache_root, source_lock)
    owasp = source_lock.source(OWASP_SOURCE_ID)
    benchproctor = source_lock.source(BENCHPROCTOR_SOURCE_ID)
    owasp_root = cache_root / owasp.cache_path
    benchproctor_root = cache_root / benchproctor.cache_path
    owasp_all = parse_owasp_expected_results(owasp_root, owasp.expected_results[0])
    benchproctor_all = tuple(
        item
        for identity in benchproctor.expected_results
        for item in parse_benchproctor_expected_results(
            benchproctor_root, identity, release=benchproctor.release
        )
    )
    full_owasp = filter_candidate_ground_truth(owasp_all)
    full_benchproctor = filter_candidate_ground_truth(benchproctor_all)
    full = tuple(
        sorted(full_owasp + full_benchproctor, key=lambda item: item.immutable_case_id)
    )
    sampled_benchproctor = deterministic_review_sample(full_benchproctor)
    sampled = tuple(
        sorted(full_owasp + sampled_benchproctor, key=lambda item: item.immutable_case_id)
    )
    if len({item.immutable_case_id for item in full}) != len(full):
        raise ValueError("duplicate external benchmark case identity")
    candidates = tuple(
        sorted(
            (
                _candidate_from_ground_truth(
                    owasp_root if item.source_id == OWASP_SOURCE_ID else benchproctor_root,
                    item,
                )
                for item in sampled
            ),
            key=lambda item: item.candidate_id,
        )
    )
    digest = source_lock_digest(source_lock)
    inventory = candidate_inventory_data(candidates, digest)
    summary = candidate_summary_data(
        source_lock, full, sampled, candidate_inventory_digest(inventory)
    )
    return inventory, summary


def load_candidate_inventory(path: Path, expected_source_lock_digest: str) -> tuple[Candidate, ...]:
    try:
        raw = _load_json(path)
        if (
            not isinstance(raw, dict)
            or set(raw) != {"candidates", "sampling", "schema_version", "source_lock_digest"}
            or raw["schema_version"] != INVENTORY_SCHEMA_VERSION
            or raw["source_lock_digest"] != _require_sha256(expected_source_lock_digest)
            or not isinstance(raw["candidates"], list)
            or not isinstance(raw["sampling"], dict)
            or set(raw["sampling"]) != {"benchproctor", "owasp"}
        ):
            raise ValueError
        candidates: list[Candidate] = []
        for item in raw["candidates"]:
            if not isinstance(item, dict) or set(item) != _CANDIDATE_FIELDS:
                raise ValueError
            candidates.append(Candidate(**item))
        candidate_tuple = tuple(candidates)
        if (
            candidate_tuple != tuple(sorted(candidate_tuple, key=lambda item: item.candidate_id))
            or len({item.candidate_id for item in candidate_tuple}) != len(candidate_tuple)
            or path.read_bytes() != canonical_document(raw)
        ):
            raise ValueError
        return candidate_tuple
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("external benchmark candidate inventory is invalid") from exc


def _run_command(arguments: list[str], *, timeout: int = 300) -> None:
    try:
        subprocess.run(
            arguments,
            check=True,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("external benchmark acquisition failed") from exc


def _download_if_missing(url: str, destination: Path, expected_sha256: str) -> None:
    if destination.exists():
        if destination.is_symlink() or not destination.is_file():
            raise ValueError("external benchmark download target is invalid")
        if _sha256_file(destination) != expected_sha256:
            raise ValueError("external benchmark checksum mismatch")
        return
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".external-download-", dir=destination.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as target:
            with urllib.request.urlopen(url, timeout=120) as response:
                shutil.copyfileobj(response, target)
            target.flush()
            os.fsync(target.fileno())
        if _sha256_file(temporary_path) != expected_sha256:
            raise ValueError("external benchmark checksum mismatch")
        os.chmod(temporary_path, 0o600)
        os.link(temporary_path, destination, follow_symlinks=False)
    finally:
        temporary_path.unlink(missing_ok=True)


def _safe_extract_bundle(bundle: Path, destination: Path) -> None:
    if (destination / "benchproctor-manifest.json").exists():
        return
    temporary_root = Path(
        tempfile.mkdtemp(prefix=".benchproctor-extract-", dir=destination.parent)
    )
    try:
        with zipfile.ZipFile(bundle) as archive:
            normalized: set[str] = set()
            for info in archive.infolist():
                name = info.filename.replace("\\", "/")
                path = PurePosixPath(name)
                mode = info.external_attr >> 16
                if (
                    not name
                    or path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or name in normalized
                    or stat.S_ISLNK(mode)
                ):
                    raise ValueError("BenchProctor ZIP member is invalid")
                normalized.add(name)
                target = temporary_root.joinpath(*path.parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.open(info) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                os.chmod(target, 0o600)
        for child in temporary_root.iterdir():
            target = destination / child.name
            if target.exists():
                raise ValueError("BenchProctor extraction target already exists")
            child.rename(target)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("BenchProctor ZIP artifact is invalid") from exc
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)


def acquire_external_sources(cache_root: Path, source_lock: SourceLock) -> None:
    cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if cache_root.is_symlink() or not cache_root.is_dir():
        raise ValueError("external benchmark cache is invalid")
    owasp = source_lock.source(OWASP_SOURCE_ID)
    owasp_root = cache_root / owasp.cache_path
    if not owasp_root.exists():
        _run_command(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "--no-tags",
                owasp.upstream_url,
                os.fspath(owasp_root),
            ]
        )
        _run_command(
            [
                "git",
                "-C",
                os.fspath(owasp_root),
                "checkout",
                "--detach",
                owasp.immutable_value,
            ]
        )
    benchproctor = source_lock.source(BENCHPROCTOR_SOURCE_ID)
    benchproctor_root = cache_root / benchproctor.cache_path
    benchproctor_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    _download_if_missing(
        benchproctor.artifact.url,
        benchproctor_root / benchproctor.artifact.relative_path,
        benchproctor.artifact.sha256,
    )
    for identity in benchproctor.verification_artifacts:
        if identity.identity == "benchproctor-manifest.json":
            continue
        _download_if_missing(
            identity.url,
            benchproctor_root / identity.relative_path,
            identity.sha256,
        )
    _safe_extract_bundle(
        benchproctor_root / benchproctor.artifact.relative_path, benchproctor_root
    )
    verify_external_sources(cache_root, source_lock)


def write_candidate_evidence(
    inventory_path: Path,
    summary_path: Path,
    inventory: dict[str, object],
    summary: dict[str, object],
) -> None:
    for path, payload in (
        (inventory_path, canonical_document(inventory)),
        (summary_path, canonical_document(summary)),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary_path, 0o644)
            os.replace(temporary_path, path)
        finally:
            temporary_path.unlink(missing_ok=True)

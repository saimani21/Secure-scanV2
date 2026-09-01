from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path, PurePosixPath
from typing import Final

from securescan.scanners.semgrep import (
    DECLARED_SEMGREP_TOOL_VERSION,
    SEMGREP_ADAPTER_ID,
    load_baseline_ruleset,
    parse_semgrep_output,
)
from securescan.workspaces.models import (
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)

BENCHMARK_ID: Final = "securescan-python-sast-v0.3f-local-v1"
MANIFEST_SCHEMA_VERSION: Final = "securescan-python-sast-benchmark-manifest-v1"
REPORT_SCHEMA_VERSION: Final = "securescan-python-sast-benchmark-report-v1"
SOURCE_TYPE: Final = "independent-local"
SCANNER_ID: Final = SEMGREP_ADAPTER_ID
EXPECTED_SCANNER_VERSION: Final = DECLARED_SEMGREP_TOOL_VERSION
FROZEN_RULESET_ID: Final = "securescan-python-baseline-v2"
FROZEN_RULESET_VERSION: Final = "2"
FROZEN_RULESET_DIGEST: Final = (
    "e10fb04e6b5abb35e0b83bdd718c2e973a8026e3630e420dc398db95e59d01a5"
)
FROZEN_CORPUS_DIGEST: Final = (
    "2a3b3a3b001ce251a5fceafc82cfd1a1599cd9d8d3d6a81de424ae393113adec"
)
PRODUCTION_RULE_IDS: Final = frozenset(
    {
        "securescan.python.dangerous-eval",
        "securescan.python.dangerous-exec",
        "securescan.python.flask-debug-enabled",
        "securescan.python.insecure-tempfile-mktemp",
        "securescan.python.jinja-autoescape-disabled",
        "securescan.python.jwt-signature-verification-disabled",
        "securescan.python.lxml-resolve-entities",
        "securescan.python.os-popen",
        "securescan.python.os-system",
        "securescan.python.paramiko-autoaddpolicy",
        "securescan.python.requests-session-verify-false",
        "securescan.python.requests-verify-false",
        "securescan.python.sql-fstring-execute",
        "securescan.python.ssl-unverified-context",
        "securescan.python.subprocess-shell-true",
        "securescan.python.unsafe-pickle-load",
        "securescan.python.unsafe-yaml-load",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "benchmark_id",
        "cases",
        "corpus_digest",
        "ruleset",
        "schema_version",
    }
)
_RULESET_FIELDS = frozenset({"digest", "id", "version"})
_CASE_FIELDS = frozenset(
    {
        "case_id",
        "category",
        "description",
        "expected_match",
        "relative_path",
        "rule_id",
        "sha256",
        "source_type",
    }
)
_CASE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,95}\Z", re.ASCII)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_METRIC_QUANTUM = Decimal("0.0001")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _bounded_text(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 1 <= len(value) <= maximum
        and not any(
            unicodedata.category(character).startswith("C") for character in value
        )
    )


def _valid_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and path.suffix == ".py"
        and path.parts[0] == "corpus"
        and all(part not in {"", ".", ".."} for part in path.parts)
        and not any(
            unicodedata.category(character).startswith("C") for character in value
        )
    )


@dataclass(frozen=True, slots=True, order=True)
class BenchmarkCase:
    case_id: str
    rule_id: str
    expected_match: bool
    relative_path: str
    description: str
    category: str
    source_type: str
    sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.case_id, str)
            or _CASE_ID_PATTERN.fullmatch(self.case_id) is None
            or self.rule_id not in PRODUCTION_RULE_IDS
            or not isinstance(self.expected_match, bool)
            or not _valid_relative_path(self.relative_path)
            or not _bounded_text(self.description, 240)
            or self.category
            != ("positive" if self.expected_match else "negative")
            or self.source_type != SOURCE_TYPE
            or not isinstance(self.sha256, str)
            or _SHA256_PATTERN.fullmatch(self.sha256) is None
        ):
            raise ValueError("Python SAST benchmark case is invalid")

    def canonical_data(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "description": self.description,
            "expected_match": self.expected_match,
            "relative_path": self.relative_path,
            "rule_id": self.rule_id,
            "sha256": self.sha256,
            "source_type": self.source_type,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkManifest:
    benchmark_id: str
    schema_version: str
    ruleset_id: str
    ruleset_version: str
    ruleset_digest: str
    corpus_digest: str
    cases: tuple[BenchmarkCase, ...]
    root: Path

    def __post_init__(self) -> None:
        if (
            self.benchmark_id != BENCHMARK_ID
            or self.schema_version != MANIFEST_SCHEMA_VERSION
            or not _bounded_text(self.ruleset_id, 64)
            or not _bounded_text(self.ruleset_version, 64)
            or not isinstance(self.ruleset_digest, str)
            or _SHA256_PATTERN.fullmatch(self.ruleset_digest) is None
            or not isinstance(self.corpus_digest, str)
            or _SHA256_PATTERN.fullmatch(self.corpus_digest) is None
            or not isinstance(self.cases, tuple)
            or any(not isinstance(case, BenchmarkCase) for case in self.cases)
            or not isinstance(self.root, Path)
        ):
            raise ValueError("Python SAST benchmark manifest is invalid")

    def digest_data(self) -> dict[str, object]:
        return {
            "benchmark_id": self.benchmark_id,
            "cases": [case.canonical_data() for case in self.cases],
            "ruleset": {
                "digest": self.ruleset_digest,
                "id": self.ruleset_id,
                "version": self.ruleset_version,
            },
            "schema_version": self.schema_version,
        }


def calculate_corpus_digest(manifest: BenchmarkManifest) -> str:
    if not isinstance(manifest, BenchmarkManifest):
        raise ValueError("Python SAST benchmark manifest is invalid")
    return hashlib.sha256(_canonical_json(manifest.digest_data())).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _case_file(root: Path, case: BenchmarkCase) -> Path:
    candidate = root.joinpath(*PurePosixPath(case.relative_path).parts)
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("Python SAST benchmark corpus is invalid") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or resolved != candidate
    ):
        raise ValueError("Python SAST benchmark corpus is invalid")
    try:
        content = candidate.read_bytes()
    except OSError as exc:
        raise ValueError("Python SAST benchmark corpus is invalid") from exc
    if hashlib.sha256(content).hexdigest() != case.sha256:
        raise ValueError("Python SAST benchmark corpus is invalid")
    return candidate


def load_benchmark_manifest(path: Path) -> BenchmarkManifest:
    ruleset = load_baseline_ruleset()
    try:
        manifest_path = path.resolve(strict=True)
        root = manifest_path.parent
        raw = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
        if not isinstance(raw, dict) or set(raw) != _MANIFEST_FIELDS:
            raise ValueError
        raw_ruleset = raw["ruleset"]
        raw_cases = raw["cases"]
        if (
            not isinstance(raw_ruleset, dict)
            or set(raw_ruleset) != _RULESET_FIELDS
            or not isinstance(raw_cases, list)
        ):
            raise ValueError
        cases: list[BenchmarkCase] = []
        for item in raw_cases:
            if not isinstance(item, dict) or set(item) != _CASE_FIELDS:
                raise ValueError
            cases.append(BenchmarkCase(**item))
        case_tuple = tuple(cases)
        if (
            case_tuple != tuple(sorted(case_tuple, key=lambda case: case.case_id))
            or len({case.case_id for case in case_tuple}) != len(case_tuple)
            or len({case.relative_path for case in case_tuple}) != len(case_tuple)
            or set(case.rule_id for case in case_tuple) != PRODUCTION_RULE_IDS
        ):
            raise ValueError
        counts = Counter((case.rule_id, case.expected_match) for case in case_tuple)
        if any(
            counts[(rule_id, expected)] < 3
            for rule_id in PRODUCTION_RULE_IDS
            for expected in (False, True)
        ):
            raise ValueError
        manifest = BenchmarkManifest(
            benchmark_id=raw["benchmark_id"],
            schema_version=raw["schema_version"],
            ruleset_id=raw_ruleset["id"],
            ruleset_version=raw_ruleset["version"],
            ruleset_digest=raw_ruleset["digest"],
            corpus_digest=raw["corpus_digest"],
            cases=case_tuple,
            root=root,
        )
        if (
            (manifest.ruleset_id, manifest.ruleset_version, manifest.ruleset_digest)
            != (
                FROZEN_RULESET_ID,
                FROZEN_RULESET_VERSION,
                FROZEN_RULESET_DIGEST,
            )
            or (ruleset.ruleset_id, ruleset.version, ruleset.sha256)
            != (
                FROZEN_RULESET_ID,
                FROZEN_RULESET_VERSION,
                FROZEN_RULESET_DIGEST,
            )
            or calculate_corpus_digest(manifest) != manifest.corpus_digest
            or manifest.corpus_digest != FROZEN_CORPUS_DIGEST
        ):
            raise ValueError
        expected_paths = {case.relative_path for case in case_tuple}
        actual_paths = {
            candidate.relative_to(root).as_posix()
            for candidate in (root / "corpus").rglob("*.py")
            if candidate.is_file()
        }
        if actual_paths != expected_paths:
            raise ValueError
        for case in case_tuple:
            _case_file(root, case)
    except (
        AttributeError,
        KeyError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise ValueError("Python SAST benchmark manifest is invalid") from exc
    return manifest


@dataclass(frozen=True, slots=True, order=True)
class CaseEvaluation:
    case_id: str
    rule_id: str
    expected_match: bool
    observed_match: bool
    classification: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.case_id, str)
            or _CASE_ID_PATTERN.fullmatch(self.case_id) is None
            or self.rule_id not in PRODUCTION_RULE_IDS
            or not isinstance(self.expected_match, bool)
            or not isinstance(self.observed_match, bool)
            or self.classification
            != classify_case(self.expected_match, self.observed_match)
        ):
            raise ValueError("Python SAST benchmark case evaluation is invalid")


def classify_case(expected_match: bool, observed_match: bool) -> str:
    if not isinstance(expected_match, bool) or not isinstance(observed_match, bool):
        raise ValueError("Python SAST benchmark classification is invalid")
    return {
        (True, True): "TP",
        (True, False): "FN",
        (False, True): "FP",
        (False, False): "TN",
    }[(expected_match, observed_match)]


def _rounded_ratio(numerator: int, denominator: int) -> str | None:
    if denominator == 0:
        return None
    return str(
        (Decimal(numerator) / Decimal(denominator)).quantize(
            _METRIC_QUANTUM,
            rounding=ROUND_HALF_UP,
        )
    )


@dataclass(frozen=True, slots=True)
class BenchmarkMetrics:
    tp: int
    fp: int
    fn: int
    tn: int
    precision: str | None
    recall: str | None
    f1: str | None

    def __post_init__(self) -> None:
        counts = (self.tp, self.fp, self.fn, self.tn)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in counts
        ):
            raise ValueError("Python SAST benchmark metrics are invalid")
        if (
            self.precision != _rounded_ratio(self.tp, self.tp + self.fp)
            or self.recall != _rounded_ratio(self.tp, self.tp + self.fn)
            or self.f1 != _rounded_ratio(2 * self.tp, 2 * self.tp + self.fp + self.fn)
        ):
            raise ValueError("Python SAST benchmark metrics are invalid")

    def canonical_data(self) -> dict[str, object]:
        return {
            "f1": self.f1,
            "fn": self.fn,
            "fp": self.fp,
            "precision": self.precision,
            "recall": self.recall,
            "tn": self.tn,
            "tp": self.tp,
        }


def calculate_metrics(classifications: Iterable[str]) -> BenchmarkMetrics:
    counts = Counter(classifications)
    if set(counts) - {"TP", "FP", "FN", "TN"}:
        raise ValueError("Python SAST benchmark classification is invalid")
    tp, fp, fn, tn = (counts[key] for key in ("TP", "FP", "FN", "TN"))
    return BenchmarkMetrics(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision=_rounded_ratio(tp, tp + fp),
        recall=_rounded_ratio(tp, tp + fn),
        f1=_rounded_ratio(2 * tp, 2 * tp + fp + fn),
    )


@dataclass(frozen=True, slots=True)
class BenchmarkEvaluation:
    manifest: BenchmarkManifest
    scanner_id: str
    scanner_version: str
    cases: tuple[CaseEvaluation, ...]
    overall: BenchmarkMetrics
    per_rule: tuple[tuple[str, BenchmarkMetrics], ...]
    unexpected_matches: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if (
            self.scanner_id != SCANNER_ID
            or self.scanner_version != EXPECTED_SCANNER_VERSION
        ):
            raise ValueError("Python SAST benchmark scanner identity is invalid")


def evaluate_benchmark(
    manifest: BenchmarkManifest,
    observed: Iterable[tuple[str, str]],
    *,
    scanner_id: str = SCANNER_ID,
    scanner_version: str = EXPECTED_SCANNER_VERSION,
) -> BenchmarkEvaluation:
    if not isinstance(manifest, BenchmarkManifest):
        raise ValueError("Python SAST benchmark manifest is invalid")
    cases_by_path = {case.relative_path: case for case in manifest.cases}
    observed_by_path: defaultdict[str, set[str]] = defaultdict(set)
    for relative_path, rule_id in observed:
        if relative_path not in cases_by_path or rule_id not in PRODUCTION_RULE_IDS:
            raise ValueError("Python SAST benchmark observation is invalid")
        observed_by_path[relative_path].add(rule_id)
    evaluations: list[CaseEvaluation] = []
    unexpected: list[tuple[str, str]] = []
    for case in manifest.cases:
        observed_rules = observed_by_path[case.relative_path]
        observed_match = case.rule_id in observed_rules
        evaluations.append(
            CaseEvaluation(
                case_id=case.case_id,
                rule_id=case.rule_id,
                expected_match=case.expected_match,
                observed_match=observed_match,
                classification=classify_case(case.expected_match, observed_match),
            )
        )
        unexpected.extend(
            (case.case_id, rule_id)
            for rule_id in sorted(observed_rules - {case.rule_id})
        )
    case_tuple = tuple(evaluations)
    per_rule = tuple(
        (
            rule_id,
            calculate_metrics(
                item.classification for item in case_tuple if item.rule_id == rule_id
            ),
        )
        for rule_id in sorted(PRODUCTION_RULE_IDS)
    )
    return BenchmarkEvaluation(
        manifest=manifest,
        scanner_id=scanner_id,
        scanner_version=scanner_version,
        cases=case_tuple,
        overall=calculate_metrics(item.classification for item in case_tuple),
        per_rule=per_rule,
        unexpected_matches=tuple(sorted(unexpected)),
    )


def _report_data(evaluation: BenchmarkEvaluation) -> dict[str, object]:
    failures = [
        {
            "case_id": case.case_id,
            "classification": case.classification,
            "expected": case.expected_match,
            "observed": case.observed_match,
            "rule_id": case.rule_id,
        }
        for case in evaluation.cases
        if case.classification in {"FP", "FN"}
    ]
    return {
        "benchmark_corpus_digest": evaluation.manifest.corpus_digest,
        "benchmark_id": evaluation.manifest.benchmark_id,
        "case_count": len(evaluation.cases),
        "failures": failures,
        "overall": evaluation.overall.canonical_data(),
        "per_rule": [
            {"rule_id": rule_id, **metrics.canonical_data()}
            for rule_id, metrics in evaluation.per_rule
        ],
        "ruleset_digest": evaluation.manifest.ruleset_digest,
        "ruleset_id": evaluation.manifest.ruleset_id,
        "ruleset_version": evaluation.manifest.ruleset_version,
        "scanner_id": evaluation.scanner_id,
        "scanner_version": evaluation.scanner_version,
        "schema_version": REPORT_SCHEMA_VERSION,
        "unexpected_matches": [
            {"case_id": case_id, "rule_id": rule_id}
            for case_id, rule_id in evaluation.unexpected_matches
        ],
    }


def canonical_benchmark_report(evaluation: BenchmarkEvaluation) -> bytes:
    if not isinstance(evaluation, BenchmarkEvaluation):
        raise ValueError("Python SAST benchmark evaluation is invalid")
    return _canonical_json(_report_data(evaluation)) + b"\n"


def _repository_manifest(
    manifest: BenchmarkManifest,
    benchmark_prefix: str,
) -> RepositoryManifest:
    entries = tuple(
        RepositoryManifestEntry(
            relative_path=(benchmark_prefix + "/" + case.relative_path),
            size_bytes=_case_file(manifest.root, case).stat().st_size,
            sha256=case.sha256,
        )
        for case in manifest.cases
    )
    return RepositoryManifest(
        entries=entries,
        file_count=len(entries),
        total_bytes=sum(entry.size_bytes for entry in entries),
        content_digest=repository_content_digest(entries),
    )


def run_frozen_semgrep_benchmark(
    repository_root: Path,
    manifest: BenchmarkManifest,
) -> BenchmarkEvaluation:
    executable = shutil.which("semgrep")
    if executable is None:
        raise RuntimeError("Local Semgrep CLI is unavailable")
    root = repository_root.resolve(strict=True)
    if manifest.root.parent != root / "benchmarks":
        raise ValueError("Python SAST benchmark root is invalid")
    benchmark_prefix = manifest.root.relative_to(root).as_posix()
    ruleset_path = (
        root
        / "src/securescan/scanners/semgrep/rules/securescan-python-baseline-v2.yml"
    )
    if hashlib.sha256(ruleset_path.read_bytes()).hexdigest() != manifest.ruleset_digest:
        raise ValueError("Frozen Python SAST ruleset identity is invalid")
    paths = [
        (benchmark_prefix + "/" + case.relative_path) for case in manifest.cases
    ]
    with tempfile.TemporaryDirectory(prefix="securescan-python-sast-benchmark-") as temp:
        environment = {
            "HOME": temp,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.pathsep.join((str(Path(executable).parent), os.defpath)),
            "SEMGREP_LOG_FILE": str(Path(temp) / "semgrep.log"),
            "SEMGREP_SETTINGS_FILE": str(Path(temp) / "settings.yml"),
        }
        result = subprocess.run(
            [
                executable,
                "scan",
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--quiet",
                "--no-git-ignore",
                "--jobs=1",
                "--no-rewrite-rule-ids",
                f"--config={ruleset_path.relative_to(root).as_posix()}",
                *paths,
            ],
            cwd=root,
            env=environment,
            capture_output=True,
            check=False,
            timeout=120,
        )
    if result.returncode != 0:
        raise RuntimeError("Frozen Python SAST benchmark execution failed")
    try:
        raw = json.loads(result.stdout)
        scanner_version = raw["version"]
        if not isinstance(scanner_version, str) or not scanner_version:
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Frozen Python SAST benchmark output is invalid") from exc
    if scanner_version != EXPECTED_SCANNER_VERSION:
        raise ValueError("Frozen Python SAST benchmark scanner identity is invalid")
    try:
        parsed = parse_semgrep_output(
            result.stdout,
            _repository_manifest(manifest, benchmark_prefix),
            scanner_id=SCANNER_ID,
            scanner_version=scanner_version,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Frozen Python SAST benchmark output is invalid") from exc
    if parsed.analysis_gaps:
        raise ValueError("Frozen Python SAST benchmark output contains analysis gaps")
    return evaluate_benchmark(
        manifest,
        (
            (
                finding.path.removeprefix(benchmark_prefix + "/"),
                finding.rule_id,
            )
            for finding in parsed.findings
        ),
        scanner_id=SCANNER_ID,
        scanner_version=scanner_version,
    )

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_RULE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,511}\Z", re.ASCII)
_MAX_LIMITATIONS = 32
_MAX_LIMITATION_LENGTH = 512


def _bounded_text(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 1 <= len(value) <= maximum
        and not any(unicodedata.category(character).startswith("C") for character in value)
    )


def _valid_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(component not in {"", ".", ".."} for component in path.parts)
        and not any(unicodedata.category(character).startswith("C") for character in value)
    )


def _nonnegative_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _metric(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0.0 <= value <= 1.0
    )


@dataclass(frozen=True, slots=True, order=True)
class BenchmarkExpectation:
    rule_id: str
    relative_path: str
    start_line: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.rule_id, str)
            or _RULE_ID_PATTERN.fullmatch(self.rule_id) is None
            or not _valid_relative_path(self.relative_path)
            or not isinstance(self.start_line, int)
            or isinstance(self.start_line, bool)
            or self.start_line < 1
        ):
            raise ValueError("Benchmark expectation is invalid")


@dataclass(frozen=True, slots=True, order=True)
class BenchmarkObservation:
    fingerprint: str
    rule_id: str
    relative_path: str
    start_line: int
    severity: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.fingerprint, str)
            or _SHA256_PATTERN.fullmatch(self.fingerprint) is None
            or not isinstance(self.rule_id, str)
            or _RULE_ID_PATTERN.fullmatch(self.rule_id) is None
            or not _valid_relative_path(self.relative_path)
            or not isinstance(self.start_line, int)
            or isinstance(self.start_line, bool)
            or self.start_line < 1
            or not _bounded_text(self.severity, 64)
        ):
            raise ValueError("Benchmark observation is invalid")


@dataclass(frozen=True, slots=True)
class BenchmarkMetrics:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float

    def __post_init__(self) -> None:
        if (
            not all(
                _nonnegative_integer(value)
                for value in (
                    self.true_positives,
                    self.false_positives,
                    self.false_negatives,
                )
            )
            or not all(_metric(value) for value in (self.precision, self.recall, self.f1_score))
        ):
            raise ValueError("Benchmark metrics are invalid")
        object.__setattr__(self, "precision", float(self.precision))
        object.__setattr__(self, "recall", float(self.recall))
        object.__setattr__(self, "f1_score", float(self.f1_score))


@dataclass(frozen=True, slots=True)
class BenchmarkCaseResult:
    case_id: str
    corpus_digest: str
    expected_findings: tuple[BenchmarkExpectation, ...]
    observed_findings: tuple[BenchmarkObservation, ...]
    metrics: BenchmarkMetrics
    analysis_gap_count: int
    raw_artifact_count: int
    deterministic: bool

    def __post_init__(self) -> None:
        expected = tuple(sorted(self.expected_findings))
        observed = tuple(sorted(self.observed_findings))
        if (
            not _bounded_text(self.case_id, 128)
            or not isinstance(self.corpus_digest, str)
            or _SHA256_PATTERN.fullmatch(self.corpus_digest) is None
            or any(not isinstance(item, BenchmarkExpectation) for item in expected)
            or any(not isinstance(item, BenchmarkObservation) for item in observed)
            or not isinstance(self.metrics, BenchmarkMetrics)
            or not _nonnegative_integer(self.analysis_gap_count)
            or not _nonnegative_integer(self.raw_artifact_count)
            or not isinstance(self.deterministic, bool)
        ):
            raise ValueError("Benchmark case result is invalid")
        if (
            self.metrics.true_positives + self.metrics.false_negatives != len(expected)
            or self.metrics.true_positives + self.metrics.false_positives != len(observed)
        ):
            raise ValueError("Benchmark case result metrics are inconsistent")
        true_positives = self.metrics.true_positives
        false_positives = self.metrics.false_positives
        false_negatives = self.metrics.false_negatives
        precision = (
            true_positives / (true_positives + false_positives)
            if true_positives + false_positives
            else 1.0
        )
        recall = (
            true_positives / (true_positives + false_negatives)
            if true_positives + false_negatives
            else 1.0
        )
        f1_score = (
            2 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )
        if (self.metrics.precision, self.metrics.recall, self.metrics.f1_score) != (
            precision,
            recall,
            f1_score,
        ):
            raise ValueError("Benchmark case result metrics are inconsistent")
        object.__setattr__(self, "expected_findings", expected)
        object.__setattr__(self, "observed_findings", observed)


@dataclass(frozen=True, slots=True)
class CoreReleaseEvaluation:
    release_version: str
    benchmark_id: str
    vulnerable_case: BenchmarkCaseResult
    clean_case: BenchmarkCaseResult
    repeatability_verified: bool
    acceptance_passed: bool
    limitations: tuple[str, ...]
    release_evidence_digest: str

    def __post_init__(self) -> None:
        limitations = tuple(sorted(self.limitations))
        if (
            not _bounded_text(self.release_version, 32)
            or not _bounded_text(self.benchmark_id, 128)
            or not isinstance(self.vulnerable_case, BenchmarkCaseResult)
            or not isinstance(self.clean_case, BenchmarkCaseResult)
            or not isinstance(self.repeatability_verified, bool)
            or not isinstance(self.acceptance_passed, bool)
            or not 1 <= len(limitations) <= _MAX_LIMITATIONS
            or any(
                not _bounded_text(limitation, _MAX_LIMITATION_LENGTH)
                for limitation in limitations
            )
            or len(set(limitations)) != len(limitations)
            or not isinstance(self.release_evidence_digest, str)
            or _SHA256_PATTERN.fullmatch(self.release_evidence_digest) is None
        ):
            raise ValueError("Core release evaluation is invalid")
        object.__setattr__(self, "limitations", limitations)
        from securescan.release.report import release_evidence_digest

        expected_digest = release_evidence_digest(
            release_version=self.release_version,
            benchmark_id=self.benchmark_id,
            vulnerable_case=self.vulnerable_case,
            clean_case=self.clean_case,
            repeatability_verified=self.repeatability_verified,
            acceptance_passed=self.acceptance_passed,
            limitations=limitations,
        )
        if self.release_evidence_digest != expected_digest:
            raise ValueError("Core release evidence digest is inconsistent")

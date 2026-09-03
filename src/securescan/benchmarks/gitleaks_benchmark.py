from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import unicodedata
from collections import Counter
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path, PurePosixPath
from typing import Final
from uuid import UUID

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.benchmarks.gitleaks_contract import (
    GITLEAKS_BENCHMARK_CONTRACT_SHA256,
    GITLEAKS_BENCHMARK_ID,
    GITLEAKS_BINDING_ARTIFACT_SHA256,
    GITLEAKS_BINDING_DIGEST,
    GitleaksBenchmarkCase,
    GitleaksBenchmarkClassification,
    GitleaksBenchmarkExpectation,
    GitleaksBenchmarkManifest,
    classify_case,
)
from securescan.benchmarks.gitleaks_corpus import (
    GITLEAKS_CORPUS_CASE_COUNT,
    GITLEAKS_CORPUS_CORE_CASE_COUNT,
    GITLEAKS_CORPUS_DIGEST,
    GITLEAKS_CORPUS_MANIFEST_SHA256,
    GITLEAKS_CORPUS_PLAN_SHA256,
    GITLEAKS_CORPUS_SCOPE_CASE_COUNT,
    verify_gitleaks_benchmark,
)
from securescan.domain.enums import ArtifactKind, JobStatus
from securescan.jobs.models import JobRecord
from securescan.scanners.gitleaks import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_SOURCE_ANALYZER_ID,
    GITLEAKS_VERSION,
    GitleaksDetectionKind,
    GitleaksExecutionResultEnvelope,
    GitleaksExecutionStatus,
    GitleaksParseResult,
    GitleaksSourceExecutionBridge,
    GitleaksSourceExecutionContextResolver,
    GitleaksSourceExecutionResolver,
    NormalizedGitleaksFinding,
    TrustedGitleaksBinding,
    build_gitleaks_finding_identities,
    create_default_gitleaks_binding,
    parse_gitleaks_execution_result,
)
from securescan.scanners.semgrep import (
    SourceExecutionEnvelope,
    SourceProjectionExecutionReference,
)
from securescan.source import (
    AnalysisCapability,
    PreparedSourceProjection,
    SourceExecutionContext,
    SourceExecutionSelectedFile,
    SourceProjectionManager,
)
from securescan.workspaces import RepositoryWorkspaceManager
from securescan.workspaces.models import RepositoryManifestEntry

GITLEAKS_BENCHMARK_REPORT_SCHEMA_VERSION: Final = "securescan-gitleaks-benchmark-report-v1"
GITLEAKS_V04F2_BASELINE_COMMIT: Final = "98034c4e124e935e2bb5a893c45013ed5090f6e3"
GITLEAKS_V04F2_BASELINE_TAG: Final = "source-v0.4F2-gitleaks-prescan-corpus"
GITLEAKS_BENCHMARK_BASELINE_PATH: Final = "benchmarks/gitleaks/initial-v0.4f-baseline.json"

_EXECUTION_MODE = "production-source-current-snapshot"
_FIXED_SOURCE_RUN_ID = str(UUID("00000000-0000-4000-8000-00000000f3a1"))
_FIXED_JOB_ID = str(UUID("00000000-0000-4000-8000-00000000f3a2"))
_FIXED_LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-00000000f3a3"))
_FIXED_TIME = datetime(2065, 3, 10, 3, 10, 3, tzinfo=UTC)
_WORKSPACE_SUFFIX = "f3a0" * 8
_PROJECTION_SUFFIX = "f3a4" * 8
_MIN_SENTINEL_BYTES = 16
_METRIC_QUANTUM = Decimal("0.0001")
_METRIC_PATTERN = re.compile(r"(?:0\.\d{4}|1\.0000)\Z", re.ASCII)
_CASE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
_RULE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\Z", re.ASCII)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_URL_SCHEME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:", re.ASCII)
_PROJECTION_ID_PATTERN = re.compile(
    r"securescan-source-projection-[0-9a-f]{16,48}\Z",
    re.ASCII,
)
_CONFIDENTIALITY_PROOF_TOKEN = object()
_LIMITATIONS = (
    "Metrics apply only to the 48 frozen F2 case/rule relations.",
    "Seven representative detectors do not certify all inherited Gitleaks detectors.",
    "Unexpected cross-rule observations are reported separately from intended relations.",
    "A finding is not proof that a credential is valid, active, or exploitable.",
    (
        "Git history, provider validation, network acquisition, archive traversal, "
        "and recursive decoding are outside Source v1."
    ),
    "Benchmark results do not automatically promote SECRET_DETECTION maturity.",
)


class GitleaksBenchmarkError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Gitleaks benchmark execution failed")


class GitleaksBenchmarkConfidentialityError(GitleaksBenchmarkError):
    def __init__(self) -> None:
        RuntimeError.__init__(
            self,
            "Gitleaks benchmark confidentiality validation failed",
        )


def _has_forbidden_character(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def _valid_case_id(value: object) -> bool:
    return isinstance(value, str) and _CASE_ID_PATTERN.fullmatch(value) is not None


def _valid_rule_id(value: object) -> bool:
    return isinstance(value, str) and _RULE_ID_PATTERN.fullmatch(value) is not None


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_PATTERN.fullmatch(value) is not None


def _valid_projection_id(value: object) -> bool:
    return isinstance(value, str) and _PROJECTION_ID_PATTERN.fullmatch(value) is not None


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
    parts = value.split("/")
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in parts)
        and path.as_posix() == value
    )


@dataclass(frozen=True, slots=True)
class GitleaksObservationLocation:
    start_line: int
    end_line: int
    start_column: int | None
    end_column: int | None

    def __post_init__(self) -> None:
        values = (self.start_line, self.end_line)
        columns = (self.start_column, self.end_column)
        if (
            any(type(value) is not int or not 1 <= value <= 2_147_483_647 for value in values)
            or self.end_line < self.start_line
            or (self.start_column is None) is not (self.end_column is None)
            or any(
                value is not None and (type(value) is not int or not 1 <= value <= 2_147_483_647)
                for value in columns
            )
            or (
                self.start_column is not None
                and self.end_column is not None
                and self.end_column < self.start_column
            )
        ):
            raise GitleaksBenchmarkError

    def canonical_data(self) -> dict[str, int | None]:
        return {
            "end_column": self.end_column,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "start_line": self.start_line,
        }


@dataclass(frozen=True, slots=True)
class GitleaksBenchmarkCaseResult:
    case_id: str
    relative_path: str
    expected_rule_id: str | None
    expected_detection_kind: GitleaksDetectionKind | None
    expectation: GitleaksBenchmarkExpectation
    classification: GitleaksBenchmarkClassification
    same_rule_observation_count: int
    same_rule_finding_instance_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        scored = self.expectation in {
            GitleaksBenchmarkExpectation.EXPECTED_MATCH,
            GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        }
        if (
            not _valid_case_id(self.case_id)
            or not _valid_relative_path(self.relative_path)
            or not self.relative_path.startswith("corpus/")
            or not isinstance(self.expectation, GitleaksBenchmarkExpectation)
            or not isinstance(self.classification, GitleaksBenchmarkClassification)
            or type(self.same_rule_observation_count) is not int
            or self.same_rule_observation_count < 0
            or not isinstance(self.same_rule_finding_instance_ids, tuple)
            or self.same_rule_observation_count != len(self.same_rule_finding_instance_ids)
            or any(not _valid_sha256(value) for value in self.same_rule_finding_instance_ids)
            or (
                scored
                and (
                    not _valid_rule_id(self.expected_rule_id)
                    or not isinstance(
                        self.expected_detection_kind,
                        GitleaksDetectionKind,
                    )
                )
            )
            or (
                not scored
                and (
                    self.expected_rule_id is not None
                    or self.expected_detection_kind is not None
                    or self.same_rule_observation_count != 0
                )
            )
        ):
            raise GitleaksBenchmarkError
        try:
            expected_classification = classify_case(
                self.expectation,
                self.same_rule_observation_count > 0,
            )
        except ValueError:
            raise GitleaksBenchmarkError from None
        if self.classification is not expected_classification:
            raise GitleaksBenchmarkError

    def canonical_data(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "classification": self.classification.value,
            "expectation": self.expectation.value,
            "expected_detection_kind": (
                None if self.expected_detection_kind is None else self.expected_detection_kind.value
            ),
            "expected_rule_id": self.expected_rule_id,
            "relative_path": self.relative_path,
            "same_rule_finding_instance_ids": list(self.same_rule_finding_instance_ids),
            "same_rule_observation_count": self.same_rule_observation_count,
        }


@dataclass(frozen=True, slots=True)
class GitleaksUnexpectedObservation:
    case_id: str
    rule_id: str
    file_path: str
    detection_kind: GitleaksDetectionKind
    location: GitleaksObservationLocation | None
    finding_instance_id: str

    def __post_init__(self) -> None:
        if (
            not _valid_case_id(self.case_id)
            or not _valid_rule_id(self.rule_id)
            or not _valid_relative_path(self.file_path)
            or not self.file_path.startswith("corpus/")
            or not isinstance(self.detection_kind, GitleaksDetectionKind)
            or not _valid_sha256(self.finding_instance_id)
            or (self.detection_kind is GitleaksDetectionKind.PATH and self.location is not None)
            or (
                self.detection_kind is GitleaksDetectionKind.CONTENT
                and not isinstance(self.location, GitleaksObservationLocation)
            )
        ):
            raise GitleaksBenchmarkError

    def canonical_data(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "detection_kind": self.detection_kind.value,
            "file_path": self.file_path,
            "finding_instance_id": self.finding_instance_id,
            "location": None if self.location is None else self.location.canonical_data(),
            "rule_id": self.rule_id,
        }


@dataclass(frozen=True, slots=True)
class GitleaksBenchmarkMetrics:
    tp: int
    fp: int
    fn: int
    tn: int
    out_of_scope: int
    precision: str | None
    recall: str | None
    f1: str | None

    def __post_init__(self) -> None:
        metric_values = (self.tp, self.fp, self.fn, self.tn, self.out_of_scope)
        ratio_values = (self.precision, self.recall, self.f1)
        if any(type(value) is not int or value < 0 for value in metric_values) or any(
            value is not None
            and (not isinstance(value, str) or _METRIC_PATTERN.fullmatch(value) is None)
            for value in ratio_values
        ):
            raise GitleaksBenchmarkError
        precision = _ratio(self.tp, self.tp + self.fp)
        recall = _ratio(self.tp, self.tp + self.fn)
        f1 = (
            None
            if precision is None or recall is None or precision + recall == 0
            else Decimal(2) * precision * recall / (precision + recall)
        )
        if (self.precision, self.recall, self.f1) != tuple(
            _metric_text(value) for value in (precision, recall, f1)
        ):
            raise GitleaksBenchmarkError

    @property
    def relation_count(self) -> int:
        return self.tp + self.fp + self.fn + self.tn + self.out_of_scope

    def canonical_data(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "f1": self.f1,
            "fn": self.fn,
            "fp": self.fp,
            "out_of_scope": self.out_of_scope,
            "precision": self.precision,
            "recall": self.recall,
            "relation_count": self.relation_count,
            "tn": self.tn,
            "tp": self.tp,
        }


@dataclass(frozen=True, slots=True)
class GitleaksPerRuleResult:
    rule_id: str
    metrics: GitleaksBenchmarkMetrics

    def __post_init__(self) -> None:
        if not _valid_rule_id(self.rule_id) or not isinstance(
            self.metrics,
            GitleaksBenchmarkMetrics,
        ):
            raise GitleaksBenchmarkError

    def canonical_data(self) -> dict[str, object]:
        return {"rule_id": self.rule_id, **self.metrics.canonical_data()}


@dataclass(frozen=True, slots=True)
class GitleaksBenchmarkEvaluation:
    execution_status: GitleaksExecutionStatus
    return_code: int
    finding_observation_count: int
    parsed_finding_count: int
    overall: GitleaksBenchmarkMetrics
    core: GitleaksBenchmarkMetrics
    scope: GitleaksBenchmarkMetrics
    per_rule: tuple[GitleaksPerRuleResult, ...]
    cases: tuple[GitleaksBenchmarkCaseResult, ...]
    unexpected_cross_rule_observations: tuple[GitleaksUnexpectedObservation, ...]
    projection_id: str = field(repr=False)
    context_digest: str = field(repr=False)
    projection_digest: str = field(repr=False)
    parse_result_digest: str = field(repr=False)

    def __post_init__(self) -> None:
        _validate_evaluation_state(self)


@dataclass(frozen=True, slots=True)
class _GitleaksConfidentialityProof:
    projection_id: str
    context_digest: str
    projection_digest: str
    execution_status: GitleaksExecutionStatus
    return_code: int
    corpus_digest: str
    parse_result_digest: str = field(repr=False)
    _token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        expected_return_code = (
            0 if self.execution_status is GitleaksExecutionStatus.COMPLETED_NO_FINDINGS else 1
        )
        if (
            self._token is not _CONFIDENTIALITY_PROOF_TOKEN
            or not _valid_projection_id(self.projection_id)
            or not _valid_sha256(self.context_digest)
            or not _valid_sha256(self.projection_digest)
            or self.execution_status
            not in {
                GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
                GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS,
            }
            or type(self.return_code) is not int
            or self.return_code != expected_return_code
            or self.corpus_digest != GITLEAKS_CORPUS_DIGEST
            or not _valid_sha256(self.parse_result_digest)
        ):
            raise GitleaksBenchmarkConfidentialityError


@dataclass(frozen=True, slots=True)
class GitleaksBenchmarkReport:
    evaluation: GitleaksBenchmarkEvaluation
    _confidentiality_proof: _GitleaksConfidentialityProof = field(
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.evaluation, GitleaksBenchmarkEvaluation) or not isinstance(
            self._confidentiality_proof,
            _GitleaksConfidentialityProof,
        ):
            raise GitleaksBenchmarkError
        proof = self._confidentiality_proof
        evaluation = self.evaluation
        _validate_evaluation_state(evaluation)
        if (
            proof._token is not _CONFIDENTIALITY_PROOF_TOKEN
            or proof.projection_id != evaluation.projection_id
            or proof.context_digest != evaluation.context_digest
            or proof.projection_digest != evaluation.projection_digest
            or proof.execution_status is not evaluation.execution_status
            or proof.return_code != evaluation.return_code
            or proof.corpus_digest != GITLEAKS_CORPUS_DIGEST
            or proof.parse_result_digest != evaluation.parse_result_digest
        ):
            raise GitleaksBenchmarkError

    @property
    def execution_status(self) -> GitleaksExecutionStatus:
        return self.evaluation.execution_status

    @property
    def return_code(self) -> int:
        return self.evaluation.return_code

    @property
    def finding_observation_count(self) -> int:
        return self.evaluation.finding_observation_count

    @property
    def parsed_finding_count(self) -> int:
        return self.evaluation.parsed_finding_count

    @property
    def overall(self) -> GitleaksBenchmarkMetrics:
        return self.evaluation.overall

    @property
    def core(self) -> GitleaksBenchmarkMetrics:
        return self.evaluation.core

    @property
    def scope(self) -> GitleaksBenchmarkMetrics:
        return self.evaluation.scope

    @property
    def per_rule(self) -> tuple[GitleaksPerRuleResult, ...]:
        return self.evaluation.per_rule

    @property
    def cases(self) -> tuple[GitleaksBenchmarkCaseResult, ...]:
        return self.evaluation.cases

    @property
    def unexpected_cross_rule_observations(
        self,
    ) -> tuple[GitleaksUnexpectedObservation, ...]:
        return self.evaluation.unexpected_cross_rule_observations

    def canonical_data(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "benchmark_baseline_commit": GITLEAKS_V04F2_BASELINE_COMMIT,
            "benchmark_baseline_tag": GITLEAKS_V04F2_BASELINE_TAG,
            "benchmark_id": GITLEAKS_BENCHMARK_ID,
            "binding_artifact_sha256": GITLEAKS_BINDING_ARTIFACT_SHA256,
            "binding_digest": GITLEAKS_BINDING_DIGEST,
            "case_relation_count": GITLEAKS_CORPUS_CASE_COUNT,
            "cases": [row.canonical_data() for row in self.cases],
            "confidentiality": {
                "raw_fixture_sentinels_absent_from_scanner_output": True,
                "raw_scanner_output_persisted": False,
            },
            "contract_sha256": GITLEAKS_BENCHMARK_CONTRACT_SHA256,
            "core": self.core.canonical_data(),
            "core_relation_count": GITLEAKS_CORPUS_CORE_CASE_COUNT,
            "corpus_digest": GITLEAKS_CORPUS_DIGEST,
            "execution": {
                "mode": _EXECUTION_MODE,
                "parsed_finding_count": self.parsed_finding_count,
                "return_code": self.return_code,
                "status": self.execution_status.value,
            },
            "finding_observation_count": self.finding_observation_count,
            "limitations": list(_LIMITATIONS),
            "manifest_sha256": GITLEAKS_CORPUS_MANIFEST_SHA256,
            "overall": self.overall.canonical_data(),
            "per_rule": [row.canonical_data() for row in self.per_rule],
            "plan_sha256": GITLEAKS_CORPUS_PLAN_SHA256,
            "scanner_id": GITLEAKS_SCANNER_ID,
            "scanner_version": GITLEAKS_VERSION,
            "schema_version": GITLEAKS_BENCHMARK_REPORT_SCHEMA_VERSION,
            "scope": self.scope.canonical_data(),
            "scope_relation_count": GITLEAKS_CORPUS_SCOPE_CASE_COUNT,
            "unexpected_cross_rule_observations": list(
                row.canonical_data() for row in self.unexpected_cross_rule_observations
            ),
        }

    def canonical_json(self) -> bytes:
        try:
            return (
                json.dumps(
                    self.canonical_data(),
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                + b"\n"
            )
        except (TypeError, ValueError, UnicodeEncodeError):
            raise GitleaksBenchmarkError from None


def _ratio(numerator: int, denominator: int) -> Decimal | None:
    if denominator == 0:
        return None
    return Decimal(numerator) / Decimal(denominator)


def _metric_text(value: Decimal | None) -> str | None:
    if value is None:
        return None
    return format(value.quantize(_METRIC_QUANTUM, rounding=ROUND_HALF_UP), ".4f")


def calculate_gitleaks_benchmark_metrics(
    classifications: Iterable[GitleaksBenchmarkClassification],
) -> GitleaksBenchmarkMetrics:
    try:
        values = tuple(classifications)
    except TypeError:
        raise GitleaksBenchmarkError from None
    if any(not isinstance(value, GitleaksBenchmarkClassification) for value in values):
        raise GitleaksBenchmarkError
    counts = Counter(values)
    tp = counts[GitleaksBenchmarkClassification.TP]
    fp = counts[GitleaksBenchmarkClassification.FP]
    fn = counts[GitleaksBenchmarkClassification.FN]
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (
        None
        if precision is None or recall is None or precision + recall == 0
        else Decimal(2) * precision * recall / (precision + recall)
    )
    return GitleaksBenchmarkMetrics(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=counts[GitleaksBenchmarkClassification.TN],
        out_of_scope=counts[GitleaksBenchmarkClassification.OUT_OF_SCOPE],
        precision=_metric_text(precision),
        recall=_metric_text(recall),
        f1=_metric_text(f1),
    )


def _unexpected_sort_key(
    observation: GitleaksUnexpectedObservation,
) -> tuple[object, ...]:
    location = observation.location
    return (
        observation.case_id,
        observation.rule_id,
        observation.detection_kind.value,
        0 if location is None else location.start_line,
        0 if location is None else location.end_line,
        0 if location is None or location.start_column is None else location.start_column,
        0 if location is None or location.end_column is None else location.end_column,
        observation.finding_instance_id,
    )


def _per_rule_results(
    cases: tuple[GitleaksBenchmarkCaseResult, ...],
) -> tuple[GitleaksPerRuleResult, ...]:
    rule_ids = sorted(
        {case.expected_rule_id for case in cases if case.expected_rule_id is not None}
    )
    return tuple(
        GitleaksPerRuleResult(
            rule_id=rule_id,
            metrics=calculate_gitleaks_benchmark_metrics(
                case.classification for case in cases if case.expected_rule_id == rule_id
            ),
        )
        for rule_id in rule_ids
    )


def _validate_evaluation_state(evaluation: GitleaksBenchmarkEvaluation) -> None:
    expected_return_code = (
        0 if evaluation.execution_status is GitleaksExecutionStatus.COMPLETED_NO_FINDINGS else 1
    )
    if (
        evaluation.execution_status
        not in {
            GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
            GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS,
        }
        or type(evaluation.return_code) is not int
        or evaluation.return_code != expected_return_code
        or type(evaluation.finding_observation_count) is not int
        or evaluation.finding_observation_count < 0
        or type(evaluation.parsed_finding_count) is not int
        or evaluation.parsed_finding_count != evaluation.finding_observation_count
        or not _valid_sha256(evaluation.parse_result_digest)
        or (
            evaluation.execution_status is GitleaksExecutionStatus.COMPLETED_NO_FINDINGS
            and evaluation.finding_observation_count != 0
        )
        or (
            evaluation.execution_status is GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
            and evaluation.finding_observation_count == 0
        )
        or any(
            not isinstance(metrics, GitleaksBenchmarkMetrics)
            for metrics in (evaluation.overall, evaluation.core, evaluation.scope)
        )
        or not isinstance(evaluation.cases, tuple)
        or len(evaluation.cases) != GITLEAKS_CORPUS_CASE_COUNT
        or any(not isinstance(case, GitleaksBenchmarkCaseResult) for case in evaluation.cases)
        or evaluation.cases != tuple(sorted(evaluation.cases, key=lambda case: case.case_id))
        or len({case.case_id for case in evaluation.cases}) != GITLEAKS_CORPUS_CASE_COUNT
        or not isinstance(evaluation.per_rule, tuple)
        or any(not isinstance(row, GitleaksPerRuleResult) for row in evaluation.per_rule)
        or evaluation.per_rule != tuple(sorted(evaluation.per_rule, key=lambda row: row.rule_id))
        or len({row.rule_id for row in evaluation.per_rule}) != len(evaluation.per_rule)
        or not isinstance(evaluation.unexpected_cross_rule_observations, tuple)
        or any(
            not isinstance(row, GitleaksUnexpectedObservation)
            for row in evaluation.unexpected_cross_rule_observations
        )
        or evaluation.unexpected_cross_rule_observations
        != tuple(
            sorted(
                evaluation.unexpected_cross_rule_observations,
                key=_unexpected_sort_key,
            )
        )
        or not _valid_projection_id(evaluation.projection_id)
        or not _valid_sha256(evaluation.context_digest)
        or not _valid_sha256(evaluation.projection_digest)
    ):
        raise GitleaksBenchmarkError

    for metrics in (evaluation.overall, evaluation.core, evaluation.scope):
        metrics.__post_init__()
    for case in evaluation.cases:
        case.__post_init__()
    for row in evaluation.per_rule:
        row.__post_init__()
        row.metrics.__post_init__()
    for observation in evaluation.unexpected_cross_rule_observations:
        observation.__post_init__()

    cases_by_id = {case.case_id: case for case in evaluation.cases}
    if any(
        observation.case_id not in cases_by_id
        or observation.file_path != cases_by_id[observation.case_id].relative_path
        for observation in evaluation.unexpected_cross_rule_observations
    ):
        raise GitleaksBenchmarkError

    core_cases = tuple(case for case in evaluation.cases if not case.case_id.startswith("scope-"))
    scope_cases = tuple(case for case in evaluation.cases if case.case_id.startswith("scope-"))
    expected_overall = calculate_gitleaks_benchmark_metrics(
        case.classification for case in evaluation.cases
    )
    expected_core = calculate_gitleaks_benchmark_metrics(case.classification for case in core_cases)
    expected_scope = calculate_gitleaks_benchmark_metrics(
        case.classification for case in scope_cases
    )
    intended_observations = sum(case.same_rule_observation_count for case in evaluation.cases)
    if (
        len(core_cases) != GITLEAKS_CORPUS_CORE_CASE_COUNT
        or len(scope_cases) != GITLEAKS_CORPUS_SCOPE_CASE_COUNT
        or evaluation.overall != expected_overall
        or evaluation.core != expected_core
        or evaluation.scope != expected_scope
        or evaluation.per_rule != _per_rule_results(evaluation.cases)
        or evaluation.finding_observation_count
        != intended_observations + len(evaluation.unexpected_cross_rule_observations)
    ):
        raise GitleaksBenchmarkError


def _validate_evaluation_against_manifest(
    evaluation: GitleaksBenchmarkEvaluation,
    manifest: GitleaksBenchmarkManifest,
) -> None:
    trusted_manifest = _validate_manifest(manifest)
    _validate_evaluation_state(evaluation)
    if tuple(case.case_id for case in evaluation.cases) != tuple(
        case.case_id for case in trusted_manifest.cases
    ):
        raise GitleaksBenchmarkError
    for result, case in zip(evaluation.cases, trusted_manifest.cases, strict=True):
        if (
            result.case_id != case.case_id
            or result.relative_path != case.relative_path
            or result.expectation is not case.expectation
            or result.expected_rule_id != case.expected_rule_id
            or result.expected_detection_kind is not case.expected_detection_kind
        ):
            raise GitleaksBenchmarkError


def _validate_manifest(manifest: object) -> GitleaksBenchmarkManifest:
    if (
        not isinstance(manifest, GitleaksBenchmarkManifest)
        or manifest.benchmark_id != GITLEAKS_BENCHMARK_ID
        or manifest.binding_digest != GITLEAKS_BINDING_DIGEST
        or manifest.binding_artifact_sha256 != GITLEAKS_BINDING_ARTIFACT_SHA256
        or manifest.contract_sha256 != GITLEAKS_BENCHMARK_CONTRACT_SHA256
        or manifest.corpus_digest != GITLEAKS_CORPUS_DIGEST
        or len(manifest.cases) != GITLEAKS_CORPUS_CASE_COUNT
    ):
        raise GitleaksBenchmarkError
    return manifest


def _validate_parse_result(result: object) -> GitleaksParseResult:
    if (
        not isinstance(result, GitleaksParseResult)
        or result.scanner_id != GITLEAKS_SCANNER_ID
        or result.scanner_version != GITLEAKS_VERSION
        or result.binding_digest != GITLEAKS_BINDING_DIGEST
        or result.finding_count != len(result.findings)
    ):
        raise GitleaksBenchmarkError
    return result


def _benchmark_path(file_path: str) -> str:
    return f"corpus/{file_path}"


def _location(
    finding: NormalizedGitleaksFinding,
) -> GitleaksObservationLocation | None:
    if finding.detection_kind is GitleaksDetectionKind.PATH:
        return None
    if finding.start_line is None or finding.end_line is None:
        raise GitleaksBenchmarkError
    return GitleaksObservationLocation(
        start_line=finding.start_line,
        end_line=finding.end_line,
        start_column=finding.start_column,
        end_column=finding.end_column,
    )


def _observation_sort_key(
    item: tuple[NormalizedGitleaksFinding, str],
) -> tuple[object, ...]:
    finding, finding_id = item
    return (
        _benchmark_path(finding.file_path),
        finding.rule_id,
        finding.detection_kind.value,
        finding.start_line or 0,
        finding.end_line or 0,
        finding.start_column or 0,
        finding.end_column or 0,
        finding_id,
    )


def _evaluate_gitleaks_benchmark(
    manifest: GitleaksBenchmarkManifest,
    parse_result: GitleaksParseResult,
    *,
    execution_status: GitleaksExecutionStatus,
    return_code: int,
) -> GitleaksBenchmarkEvaluation:
    trusted_manifest = _validate_manifest(manifest)
    trusted_result = _validate_parse_result(parse_result)
    expected_return_code = (
        0 if execution_status is GitleaksExecutionStatus.COMPLETED_NO_FINDINGS else 1
    )
    if (
        execution_status
        not in {
            GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
            GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS,
        }
        or type(return_code) is not int
        or return_code != expected_return_code
    ):
        raise GitleaksBenchmarkError

    identities = build_gitleaks_finding_identities(trusted_result.findings)
    observations = tuple(
        sorted(
            zip(
                trusted_result.findings,
                (identity.finding_instance_id for identity in identities),
                strict=True,
            ),
            key=_observation_sort_key,
        )
    )
    case_by_path = {case.relative_path: case for case in trusted_manifest.cases}
    if any(_benchmark_path(finding.file_path) not in case_by_path for finding, _ in observations):
        raise GitleaksBenchmarkError

    case_rows: list[GitleaksBenchmarkCaseResult] = []
    unexpected_rows: list[GitleaksUnexpectedObservation] = []
    for case in trusted_manifest.cases:
        same_path = tuple(
            item
            for item in observations
            if _benchmark_path(item[0].file_path) == case.relative_path
        )
        intended = tuple(
            item
            for item in same_path
            if item[0].rule_id == case.expected_rule_id
            and item[0].detection_kind is case.expected_detection_kind
        )
        classification = classify_case(case.expectation, bool(intended))
        case_rows.append(
            GitleaksBenchmarkCaseResult(
                case_id=case.case_id,
                classification=classification,
                expectation=case.expectation,
                expected_detection_kind=case.expected_detection_kind,
                expected_rule_id=case.expected_rule_id,
                relative_path=case.relative_path,
                same_rule_finding_instance_ids=tuple(item[1] for item in intended),
                same_rule_observation_count=len(intended),
            )
        )
        for finding, finding_id in same_path:
            if (finding, finding_id) in intended:
                continue
            unexpected_rows.append(
                GitleaksUnexpectedObservation(
                    case_id=case.case_id,
                    detection_kind=finding.detection_kind,
                    file_path=case.relative_path,
                    finding_instance_id=finding_id,
                    location=_location(finding),
                    rule_id=finding.rule_id,
                )
            )

    def metrics_for(
        cases: Iterable[GitleaksBenchmarkCase],
    ) -> GitleaksBenchmarkMetrics:
        return calculate_gitleaks_benchmark_metrics(
            next(row.classification for row in case_rows if row.case_id == case.case_id)
            for case in cases
        )

    core_cases = tuple(
        case for case in trusted_manifest.cases if not case.case_id.startswith("scope-")
    )
    scope_cases = tuple(
        case for case in trusted_manifest.cases if case.case_id.startswith("scope-")
    )
    frozen_case_rows = tuple(case_rows)
    return GitleaksBenchmarkEvaluation(
        execution_status=execution_status,
        return_code=return_code,
        finding_observation_count=len(observations),
        parsed_finding_count=trusted_result.finding_count,
        overall=metrics_for(trusted_manifest.cases),
        core=metrics_for(core_cases),
        scope=metrics_for(scope_cases),
        per_rule=_per_rule_results(frozen_case_rows),
        cases=frozen_case_rows,
        unexpected_cross_rule_observations=tuple(sorted(unexpected_rows, key=_unexpected_sort_key)),
        projection_id=trusted_result.projection_id,
        context_digest=trusted_result.context_digest,
        projection_digest=trusted_result.projection_digest,
        parse_result_digest=hashlib.sha256(trusted_result.canonical_json()).hexdigest(),
    )


def evaluate_gitleaks_benchmark(
    manifest: GitleaksBenchmarkManifest,
    parse_result: GitleaksParseResult,
    *,
    execution_status: GitleaksExecutionStatus,
    return_code: int,
) -> GitleaksBenchmarkEvaluation:
    try:
        return _evaluate_gitleaks_benchmark(
            manifest,
            parse_result,
            execution_status=execution_status,
            return_code=return_code,
        )
    except GitleaksBenchmarkError:
        raise
    except Exception:
        raise GitleaksBenchmarkError from None


def build_gitleaks_benchmark_report(
    manifest: GitleaksBenchmarkManifest,
    evaluation: GitleaksBenchmarkEvaluation,
    confidentiality_proof: _GitleaksConfidentialityProof,
) -> GitleaksBenchmarkReport:
    try:
        if not isinstance(confidentiality_proof, _GitleaksConfidentialityProof):
            raise GitleaksBenchmarkError
        _validate_evaluation_against_manifest(evaluation, manifest)
        return GitleaksBenchmarkReport(
            evaluation=evaluation,
            _confidentiality_proof=confidentiality_proof,
        )
    except GitleaksBenchmarkError:
        raise
    except Exception:
        raise GitleaksBenchmarkError from None


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_verified_projection_fixture(
    projection_root: Path,
    case: GitleaksBenchmarkCase,
) -> bytes:
    relative = PurePosixPath(case.relative_path).relative_to("corpus")
    target = projection_root.joinpath(*relative.parts)
    descriptor = -1
    try:
        root_metadata = projection_root.lstat()
        if (
            not projection_root.is_absolute()
            or not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_ISLNK(root_metadata.st_mode)
        ):
            raise OSError
        current = projection_root
        for part in relative.parts[:-1]:
            current /= part
            metadata = current.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise OSError

        before = target.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise OSError
        descriptor = os.open(
            target,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(before):
            raise OSError
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read()
            after_read = os.fstat(handle.fileno())
        after_path = target.lstat()
        if (
            _stat_identity(opened) != _stat_identity(after_read)
            or _stat_identity(opened) != _stat_identity(after_path)
            or hashlib.sha256(payload).hexdigest() != case.sha256
        ):
            raise OSError
        return payload
    except (OSError, TypeError, ValueError):
        raise GitleaksBenchmarkConfidentialityError from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _extract_fixture_sentinels(
    manifest: GitleaksBenchmarkManifest,
    projection_root: Path,
) -> tuple[bytes, ...]:
    sentinels: set[bytes] = set()
    try:
        for case in manifest.cases:
            if case.expected_detection_kind is GitleaksDetectionKind.PATH:
                continue
            payload = _read_verified_projection_fixture(
                projection_root,
                case,
            )
            lines = tuple(line for line in payload.splitlines() if line)
            if case.relative_path.endswith(".pem"):
                candidates = tuple(
                    line
                    for line in lines
                    if not line.startswith(b"-----BEGIN")
                    and not line.startswith(b"-----END")
                    and b"SYNTHETIC" in line
                )
            else:
                value = lines[-1]
                if b" = " in value:
                    value = value.split(b" = ", 1)[1]
                    if value.startswith(b'"') and value.endswith(b'"'):
                        value = value[1:-1]
                candidates = (value,)
            sentinels.update(value for value in candidates if len(value) >= _MIN_SENTINEL_BYTES)
    except (OSError, ValueError):
        raise GitleaksBenchmarkConfidentialityError from None
    if not sentinels:
        raise GitleaksBenchmarkConfidentialityError
    return tuple(sorted(sentinels))


def _validate_raw_output_confidentiality(
    manifest: GitleaksBenchmarkManifest,
    projection_root: Path,
    result: GitleaksExecutionResultEnvelope,
) -> None:
    trusted_manifest = _validate_manifest(manifest)
    if (
        not isinstance(result, GitleaksExecutionResultEnvelope)
        or result.scanner_id != GITLEAKS_SCANNER_ID
        or result.scanner_version != GITLEAKS_VERSION
        or result.binding_digest != GITLEAKS_BINDING_DIGEST
    ):
        raise GitleaksBenchmarkConfidentialityError
    sentinels = _extract_fixture_sentinels(trusted_manifest, projection_root)
    if any(
        sentinel in stream
        for sentinel in sentinels
        for stream in (result.stdout_bytes, result.stderr_bytes)
    ):
        raise GitleaksBenchmarkConfidentialityError


def _validate_and_parse_controlled_execution(
    manifest: GitleaksBenchmarkManifest,
    projection: PreparedSourceProjection,
    result: GitleaksExecutionResultEnvelope,
) -> tuple[GitleaksParseResult, _GitleaksConfidentialityProof]:
    _validate_raw_output_confidentiality(
        manifest,
        projection.source_directory,
        result,
    )
    parse_result = parse_gitleaks_execution_result(result, projection)
    return parse_result, _GitleaksConfidentialityProof(
        projection_id=result.projection_id,
        context_digest=result.context_digest,
        projection_digest=result.projection_digest,
        execution_status=result.execution_status,
        return_code=result.return_code,
        corpus_digest=manifest.corpus_digest,
        parse_result_digest=hashlib.sha256(parse_result.canonical_json()).hexdigest(),
        _token=_CONFIDENTIALITY_PROOF_TOKEN,
    )


def _workspace_matches_manifest(
    manifest: GitleaksBenchmarkManifest,
    entries: tuple[RepositoryManifestEntry, ...],
) -> bool:
    expected = tuple(
        (
            PurePosixPath(case.relative_path).relative_to("corpus").as_posix(),
            case.sha256,
        )
        for case in manifest.cases
    )
    actual = tuple((entry.relative_path, entry.sha256) for entry in entries)
    return actual == expected


def _build_job(
    context: SourceExecutionContext,
    envelope: SourceExecutionEnvelope,
) -> JobRecord:
    return JobRecord(
        id=_FIXED_JOB_ID,
        run_id=_FIXED_SOURCE_RUN_ID,
        adapter_id=GITLEAKS_SCANNER_ID,
        status=JobStatus.RUNNING,
        priority=100,
        attempt_count=1,
        max_attempts=1,
        available_at=_FIXED_TIME,
        leased_by="gitleaks-benchmark",
        lease_expires_at=_FIXED_TIME,
        heartbeat_at=_FIXED_TIME,
        cancel_requested=False,
        idempotency_key=hashlib.sha256(b"securescan-gitleaks-f3a").hexdigest(),
        payload_json=envelope.payload_json(),
        last_error=None,
        created_at=_FIXED_TIME,
        updated_at=_FIXED_TIME,
        started_at=_FIXED_TIME,
        finished_at=None,
        lease_token=_FIXED_LEASE_TOKEN,
    )


def _run_with_dependencies(
    repository_root: Path,
    binding: TrustedGitleaksBinding,
    process_executor: object | None,
) -> GitleaksBenchmarkReport:
    manifest = verify_gitleaks_benchmark(repository_root)
    if binding.binding_digest() != GITLEAKS_BINDING_DIGEST:
        raise GitleaksBenchmarkError
    corpus_root = repository_root / "benchmarks/gitleaks/corpus"

    try:
        with tempfile.TemporaryDirectory(prefix="securescan-gitleaks-benchmark-") as temporary_name:
            temporary_root = Path(temporary_name).resolve()
            if temporary_root.is_relative_to(repository_root):
                raise GitleaksBenchmarkError
            workspace_manager = RepositoryWorkspaceManager(
                temporary_root / "workspaces",
                workspace_id_factory=lambda: _WORKSPACE_SUFFIX,
            )
            workspace = workspace_manager.prepare_repository(corpus_root)
            projection_manager = SourceProjectionManager(temporary_root / "projections")
            projection = None
            try:
                if not _workspace_matches_manifest(
                    manifest,
                    workspace.manifest.entries,
                ):
                    raise GitleaksBenchmarkError
                context = SourceExecutionContext(
                    source_run_id=_FIXED_SOURCE_RUN_ID,
                    job_id=_FIXED_JOB_ID,
                    repository_digest=workspace.manifest.content_digest,
                    profile_digest=GITLEAKS_CORPUS_MANIFEST_SHA256,
                    plan_digest=GITLEAKS_CORPUS_PLAN_SHA256,
                    source_analyzer_id=GITLEAKS_SOURCE_ANALYZER_ID,
                    capability=AnalysisCapability.SECRET_DETECTION,
                    component_id=None,
                    selected_files=tuple(
                        SourceExecutionSelectedFile(
                            entry=replace(entry),
                            component_id=None,
                        )
                        for entry in workspace.manifest.entries
                    ),
                    binding_digest=binding.binding_digest(),
                    core_adapter_id=GITLEAKS_SCANNER_ID,
                )
                projection = projection_manager.build_projection(
                    workspace,
                    context,
                    projection_suffix=_PROJECTION_SUFFIX,
                )
                store = ContentAddressedArtifactStore(temporary_root / "artifacts")
                artifact = store.put(
                    context.canonical_json(),
                    kind=ArtifactKind.SOURCE_EXECUTION_CONTEXT,
                    media_type="application/json",
                    sanitized=False,
                )
                execution_envelope = SourceExecutionEnvelope(
                    artifact_sha256=artifact.sha256,
                    artifact_size_bytes=artifact.size_bytes,
                    context_digest=context.context_digest(),
                    projection_reference=SourceProjectionExecutionReference(
                        projection_id=projection.projection_id,
                        context_digest=projection.context_digest,
                        projection_digest=projection.projection_digest,
                    ),
                )
                job = _build_job(context, execution_envelope)
                context_resolver = GitleaksSourceExecutionContextResolver(
                    store,
                    binding,
                )
                execution_resolver = GitleaksSourceExecutionResolver(
                    context_resolver,
                    projection_manager,
                )
                bridge = GitleaksSourceExecutionBridge(
                    execution_resolver,
                    binding,
                    process_executor,
                )
                with bridge.start(job) as handle:
                    result = handle.wait()
                    if result is None:
                        result = handle.poll()
                if result is None:
                    raise GitleaksBenchmarkError
                if result.execution_status not in {
                    GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
                    GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS,
                }:
                    raise GitleaksBenchmarkError
                parsed, confidentiality_proof = _validate_and_parse_controlled_execution(
                    manifest,
                    projection,
                    result,
                )
                evaluation = evaluate_gitleaks_benchmark(
                    manifest,
                    parsed,
                    execution_status=result.execution_status,
                    return_code=result.return_code,
                )
                return build_gitleaks_benchmark_report(
                    manifest,
                    evaluation,
                    confidentiality_proof,
                )
            finally:
                try:
                    if projection is not None:
                        projection_manager.cleanup_projection(projection)
                finally:
                    workspace_manager.cleanup_workspace(workspace)
    except GitleaksBenchmarkConfidentialityError:
        raise
    except Exception:
        raise GitleaksBenchmarkError from None


def check_controlled_gitleaks_benchmark(
    repository_root: Path,
    executable_path: Path,
) -> dict[str, object]:
    if (
        not isinstance(repository_root, Path)
        or not repository_root.is_absolute()
        or not isinstance(executable_path, Path)
        or not executable_path.is_absolute()
    ):
        raise GitleaksBenchmarkError
    try:
        verify_gitleaks_benchmark(repository_root)
        binding = create_default_gitleaks_binding(executable_path)
        if binding.binding_digest() != GITLEAKS_BINDING_DIGEST:
            raise GitleaksBenchmarkError
        binding.verify_runtime()
    except Exception:
        raise GitleaksBenchmarkError from None
    return {
        "benchmark_baseline_commit": GITLEAKS_V04F2_BASELINE_COMMIT,
        "benchmark_baseline_tag": GITLEAKS_V04F2_BASELINE_TAG,
        "benchmark_id": GITLEAKS_BENCHMARK_ID,
        "binding_artifact_sha256": GITLEAKS_BINDING_ARTIFACT_SHA256,
        "binding_digest": GITLEAKS_BINDING_DIGEST,
        "contract_sha256": GITLEAKS_BENCHMARK_CONTRACT_SHA256,
        "corpus_digest": GITLEAKS_CORPUS_DIGEST,
        "manifest_sha256": GITLEAKS_CORPUS_MANIFEST_SHA256,
        "plan_sha256": GITLEAKS_CORPUS_PLAN_SHA256,
        "runtime_verified": True,
        "scanner_id": GITLEAKS_SCANNER_ID,
        "scanner_version": GITLEAKS_VERSION,
    }


def run_controlled_gitleaks_benchmark(
    repository_root: Path,
    executable_path: Path,
) -> GitleaksBenchmarkReport:
    if (
        not isinstance(repository_root, Path)
        or not repository_root.is_absolute()
        or not isinstance(executable_path, Path)
        or not executable_path.is_absolute()
    ):
        raise GitleaksBenchmarkError
    try:
        binding = create_default_gitleaks_binding(executable_path)
        return _run_with_dependencies(repository_root, binding, None)
    except GitleaksBenchmarkConfidentialityError:
        raise
    except Exception:
        raise GitleaksBenchmarkError from None


def record_gitleaks_benchmark_report(
    repository_root: Path,
    report: GitleaksBenchmarkReport,
) -> Path:
    if (
        not isinstance(repository_root, Path)
        or not repository_root.is_absolute()
        or not isinstance(report, GitleaksBenchmarkReport)
    ):
        raise GitleaksBenchmarkError
    destination = repository_root / GITLEAKS_BENCHMARK_BASELINE_PATH
    staging: Path | None = None
    try:
        manifest = verify_gitleaks_benchmark(repository_root)
        _validate_evaluation_against_manifest(report.evaluation, manifest)
        report.__post_init__()
        payload = report.canonical_json()
        parent_metadata = destination.parent.lstat()
        if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
            raise GitleaksBenchmarkError
        if destination.exists() or destination.is_symlink():
            metadata = destination.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or destination.read_bytes() != payload
            ):
                raise GitleaksBenchmarkError
            return destination
        descriptor, staging_name = tempfile.mkstemp(
            prefix=".initial-v0.4f-baseline-",
            dir=destination.parent,
        )
        staging = Path(staging_name)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(staging, 0o644)
        os.link(staging, destination, follow_symlinks=False)
        return destination
    except GitleaksBenchmarkError:
        raise
    except Exception:
        raise GitleaksBenchmarkError from None
    finally:
        if staging is not None:
            with suppress(OSError):
                staging.unlink(missing_ok=True)

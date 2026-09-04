from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import unicodedata
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final
from uuid import UUID

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.benchmarks.gitleaks_adversarial import (
    GITLEAKS_ADVERSARIAL_CASE_COUNT,
    GITLEAKS_ADVERSARIAL_CONTRACT_SHA256,
    GITLEAKS_ADVERSARIAL_CORPUS_DIGEST,
    GITLEAKS_ADVERSARIAL_CORPUS_PATH,
    GITLEAKS_ADVERSARIAL_ID,
    GITLEAKS_ADVERSARIAL_MANIFEST_SHA256,
    GITLEAKS_ADVERSARIAL_RESULT_PATH,
    GitleaksAdversarialCase,
    GitleaksAdversarialExpectation,
    GitleaksAdversarialManifest,
    GitleaksAdversarialMechanism,
    verify_gitleaks_adversarial,
)
from securescan.benchmarks.gitleaks_contract import GITLEAKS_BINDING_DIGEST
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

GITLEAKS_ADVERSARIAL_RESULT_SCHEMA_VERSION: Final = "securescan-gitleaks-adversarial-result-v1"
GITLEAKS_F4A_BASELINE_COMMIT: Final = "526ce3192885c6fc04ae8b7ac84346466809ca4e"
GITLEAKS_F4A_BASELINE_TAG: Final = "source-v0.4F4A-gitleaks-adversarial-prescan"
GITLEAKS_F3B_BASELINE_COMMIT: Final = "d183336c129977c4279cd1058bbe060742de0e54"
GITLEAKS_F3B_BASELINE_TAG: Final = "source-v0.4F3B-gitleaks-initial-baseline"
GITLEAKS_F3B_BASELINE_SHA256: Final = (
    "62f9c00f79c659d56490a181de231f0aa3cdca6a418f2ca5a9215f7ed1bbbb34"
)

_EXECUTION_MODE = "production-source-current-snapshot"
_FIXED_SOURCE_RUN_ID = str(UUID("00000000-0000-4000-8000-00000000f4b1"))
_FIXED_JOB_ID = str(UUID("00000000-0000-4000-8000-00000000f4b2"))
_FIXED_LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-00000000f4b3"))
_FIXED_TIME = datetime(2065, 4, 11, 4, 11, 4, tzinfo=UTC)
_WORKSPACE_SUFFIX = "f4b1" * 8
_PROJECTION_SUFFIX = "f4" * 16
_CONFIDENTIALITY_PROOF_TOKEN = object()
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,127}\Z", re.ASCII)
_RULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\Z", re.ASCII)
_PROJECTION_ID = re.compile(r"securescan-source-projection-[0-9a-f]{32}\Z", re.ASCII)
_GENERIC_SENTINEL = re.compile(
    rb"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*[\"']([A-Za-z0-9]{16,})[\"']"
)
_GITHUB_SENTINEL = re.compile(rb"ghp_[A-Za-z0-9]{36,}")
_MAX_FIXTURE_BYTES = 16 * 1024


class GitleaksAdversarialBenchmarkError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Gitleaks adversarial characterization failed")


class GitleaksAdversarialConfidentialityError(GitleaksAdversarialBenchmarkError):
    def __init__(self) -> None:
        RuntimeError.__init__(
            self,
            "Gitleaks adversarial confidentiality validation failed",
        )


class GitleaksAdversarialCaseResultValue(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _valid_text(value: object, maximum: int = 4096) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= maximum
        and not any(unicodedata.category(char).startswith("C") for char in value)
    )


def _valid_relative_path(value: object) -> bool:
    if not _valid_text(value) or not isinstance(value, str) or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


@dataclass(frozen=True, slots=True)
class GitleaksAdversarialObservationLocation:
    start_line: int
    end_line: int
    start_column: int | None
    end_column: int | None

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not int or not 1 <= value <= 2_147_483_647
                for value in (self.start_line, self.end_line)
            )
            or self.end_line < self.start_line
            or (self.start_column is None) is not (self.end_column is None)
            or any(
                value is not None and (type(value) is not int or not 1 <= value <= 2_147_483_647)
                for value in (self.start_column, self.end_column)
            )
            or (
                self.start_column is not None
                and self.end_column is not None
                and self.end_column < self.start_column
            )
        ):
            raise GitleaksAdversarialBenchmarkError

    def canonical_data(self) -> dict[str, int | None]:
        return {
            "end_column": self.end_column,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "start_line": self.start_line,
        }


@dataclass(frozen=True, slots=True)
class GitleaksAdversarialUnexpectedObservation:
    case_id: str
    file_path: str
    rule_id: str
    detection_kind: GitleaksDetectionKind
    location: GitleaksAdversarialObservationLocation | None
    finding_instance_id: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.case_id, str)
            or _ID.fullmatch(self.case_id) is None
            or not _valid_relative_path(self.file_path)
            or not isinstance(self.rule_id, str)
            or _RULE_ID.fullmatch(self.rule_id) is None
            or not isinstance(self.detection_kind, GitleaksDetectionKind)
            or not _valid_sha256(self.finding_instance_id)
            or (self.detection_kind is GitleaksDetectionKind.PATH and self.location is not None)
            or (
                self.detection_kind is GitleaksDetectionKind.CONTENT
                and not isinstance(
                    self.location,
                    GitleaksAdversarialObservationLocation,
                )
            )
        ):
            raise GitleaksAdversarialBenchmarkError

    def canonical_data(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "detection_kind": self.detection_kind.value,
            "file_path": self.file_path,
            "finding_instance_id": self.finding_instance_id,
            "location": (None if self.location is None else self.location.canonical_data()),
            "rule_id": self.rule_id,
        }


@dataclass(frozen=True, slots=True)
class GitleaksAdversarialCaseResult:
    case_id: str
    relative_path: str
    expected_rule_id: str
    expected_detection_kind: GitleaksDetectionKind
    expectation: GitleaksAdversarialExpectation
    mechanism: GitleaksAdversarialMechanism
    result: str
    matching_observation_count: int
    matching_finding_instance_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        observed = self.matching_observation_count > 0
        expected_result = (
            GitleaksAdversarialCaseResultValue.PASS
            if observed is (self.expectation is GitleaksAdversarialExpectation.EXPECTED_OBSERVED)
            else GitleaksAdversarialCaseResultValue.FAIL
        )
        if (
            not isinstance(self.case_id, str)
            or _ID.fullmatch(self.case_id) is None
            or not _valid_relative_path(self.relative_path)
            or not isinstance(self.expected_rule_id, str)
            or _RULE_ID.fullmatch(self.expected_rule_id) is None
            or not isinstance(self.expected_detection_kind, GitleaksDetectionKind)
            or not isinstance(self.expectation, GitleaksAdversarialExpectation)
            or not isinstance(self.mechanism, GitleaksAdversarialMechanism)
            or self.result
            not in {
                GitleaksAdversarialCaseResultValue.PASS,
                GitleaksAdversarialCaseResultValue.FAIL,
            }
            or self.result != expected_result
            or type(self.matching_observation_count) is not int
            or self.matching_observation_count < 0
            or not isinstance(self.matching_finding_instance_ids, tuple)
            or len(self.matching_finding_instance_ids) != self.matching_observation_count
            or any(not _valid_sha256(value) for value in self.matching_finding_instance_ids)
        ):
            raise GitleaksAdversarialBenchmarkError

    def canonical_data(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "expectation": self.expectation.value,
            "expected_detection_kind": self.expected_detection_kind.value,
            "expected_rule_id": self.expected_rule_id,
            "matching_finding_instance_ids": list(self.matching_finding_instance_ids),
            "matching_observation_count": self.matching_observation_count,
            "mechanism": self.mechanism.value,
            "relative_path": self.relative_path,
            "result": self.result,
        }


@dataclass(frozen=True, slots=True)
class GitleaksAdversarialEvaluation:
    execution_status: GitleaksExecutionStatus
    return_code: int
    parsed_finding_count: int
    pass_count: int
    fail_count: int
    cases: tuple[GitleaksAdversarialCaseResult, ...]
    unexpected_cross_rule_observations: tuple[GitleaksAdversarialUnexpectedObservation, ...]
    unexpected_detection_kind_observations: tuple[
        GitleaksAdversarialUnexpectedObservation, ...
    ]
    projection_id: str = field(repr=False)
    context_digest: str = field(repr=False)
    projection_digest: str = field(repr=False)
    parse_result_digest: str = field(repr=False)

    def __post_init__(self) -> None:
        _validate_evaluation(self)


@dataclass(frozen=True, slots=True)
class _GitleaksAdversarialConfidentialityProof:
    projection_id: str
    context_digest: str
    projection_digest: str
    execution_status: GitleaksExecutionStatus
    return_code: int
    corpus_digest: str
    parse_result_digest: str = field(repr=False)
    _token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            self._token is not _CONFIDENTIALITY_PROOF_TOKEN
            or _PROJECTION_ID.fullmatch(self.projection_id) is None
            or not _valid_sha256(self.context_digest)
            or not _valid_sha256(self.projection_digest)
            or not _valid_sha256(self.parse_result_digest)
            or self.corpus_digest != GITLEAKS_ADVERSARIAL_CORPUS_DIGEST
            or not _successful_status_code(
                self.execution_status,
                self.return_code,
            )
        ):
            raise GitleaksAdversarialConfidentialityError


@dataclass(frozen=True, slots=True)
class GitleaksAdversarialReport:
    evaluation: GitleaksAdversarialEvaluation
    _confidentiality_proof: _GitleaksAdversarialConfidentialityProof = field(
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.evaluation, GitleaksAdversarialEvaluation) or not isinstance(
            self._confidentiality_proof,
            _GitleaksAdversarialConfidentialityProof,
        ):
            raise GitleaksAdversarialBenchmarkError
        _validate_evaluation(self.evaluation)
        proof = self._confidentiality_proof
        if (
            proof._token is not _CONFIDENTIALITY_PROOF_TOKEN
            or proof.projection_id != self.evaluation.projection_id
            or proof.context_digest != self.evaluation.context_digest
            or proof.projection_digest != self.evaluation.projection_digest
            or proof.execution_status is not self.evaluation.execution_status
            or proof.return_code != self.evaluation.return_code
            or proof.corpus_digest != GITLEAKS_ADVERSARIAL_CORPUS_DIGEST
            or proof.parse_result_digest != self.evaluation.parse_result_digest
        ):
            raise GitleaksAdversarialBenchmarkError

    @property
    def cases(self) -> tuple[GitleaksAdversarialCaseResult, ...]:
        return self.evaluation.cases

    @property
    def pass_count(self) -> int:
        return self.evaluation.pass_count

    @property
    def fail_count(self) -> int:
        return self.evaluation.fail_count

    def canonical_data(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "adversarial_id": GITLEAKS_ADVERSARIAL_ID,
            "binding_digest": GITLEAKS_BINDING_DIGEST,
            "case_count": GITLEAKS_ADVERSARIAL_CASE_COUNT,
            "cases": [case.canonical_data() for case in self.cases],
            "confidentiality": {
                "raw_fixture_sentinels_absent_from_scanner_output": True,
                "raw_scanner_output_persisted": False,
            },
            "contract_sha256": GITLEAKS_ADVERSARIAL_CONTRACT_SHA256,
            "corpus_digest": GITLEAKS_ADVERSARIAL_CORPUS_DIGEST,
            "execution": {
                "mode": _EXECUTION_MODE,
                "parsed_finding_count": self.evaluation.parsed_finding_count,
                "return_code": self.evaluation.return_code,
                "status": self.evaluation.execution_status.value,
            },
            "f3b_baseline_commit": GITLEAKS_F3B_BASELINE_COMMIT,
            "fail_count": self.fail_count,
            "f3b_baseline_sha256": GITLEAKS_F3B_BASELINE_SHA256,
            "f3b_baseline_tag": GITLEAKS_F3B_BASELINE_TAG,
            "f4a_baseline_commit": GITLEAKS_F4A_BASELINE_COMMIT,
            "f4a_baseline_tag": GITLEAKS_F4A_BASELINE_TAG,
            "manifest_sha256": GITLEAKS_ADVERSARIAL_MANIFEST_SHA256,
            "pass_count": self.pass_count,
            "scanner_id": GITLEAKS_SCANNER_ID,
            "scanner_version": GITLEAKS_VERSION,
            "schema_version": GITLEAKS_ADVERSARIAL_RESULT_SCHEMA_VERSION,
            "unexpected_cross_rule_observations": [
                row.canonical_data() for row in self.evaluation.unexpected_cross_rule_observations
            ],
            "unexpected_detection_kind_observations": [
                row.canonical_data()
                for row in self.evaluation.unexpected_detection_kind_observations
            ],
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
                ).encode()
                + b"\n"
            )
        except (TypeError, ValueError, UnicodeEncodeError):
            raise GitleaksAdversarialBenchmarkError from None


def _successful_status_code(
    status: object,
    return_code: object,
) -> bool:
    return (status is GitleaksExecutionStatus.COMPLETED_NO_FINDINGS and return_code == 0) or (
        status is GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS and return_code == 1
    )


def _unexpected_observation_sort_key(
    row: GitleaksAdversarialUnexpectedObservation,
) -> tuple[str, str, str, str]:
    return (
        row.case_id,
        row.rule_id,
        row.detection_kind.value,
        row.finding_instance_id,
    )


def _validate_evaluation(evaluation: GitleaksAdversarialEvaluation) -> None:
    typed_cases = isinstance(evaluation.cases, tuple) and all(
        isinstance(case, GitleaksAdversarialCaseResult) for case in evaluation.cases
    )
    typed_unexpected = isinstance(
        evaluation.unexpected_cross_rule_observations,
        tuple,
    ) and all(
        isinstance(row, GitleaksAdversarialUnexpectedObservation)
        for row in evaluation.unexpected_cross_rule_observations
    )
    typed_kind_mismatches = isinstance(
        evaluation.unexpected_detection_kind_observations,
        tuple,
    ) and all(
        isinstance(row, GitleaksAdversarialUnexpectedObservation)
        for row in evaluation.unexpected_detection_kind_observations
    )
    cases_by_id = (
        {case.case_id: case for case in evaluation.cases}
        if typed_cases
        else {}
    )
    cross_rule_partitioned = typed_unexpected and all(
        (case := cases_by_id.get(row.case_id)) is not None
        and row.file_path == case.relative_path
        and row.rule_id != case.expected_rule_id
        for row in evaluation.unexpected_cross_rule_observations
    )
    kind_mismatches_partitioned = typed_kind_mismatches and all(
        (case := cases_by_id.get(row.case_id)) is not None
        and row.file_path == case.relative_path
        and row.rule_id == case.expected_rule_id
        and row.detection_kind is not case.expected_detection_kind
        for row in evaluation.unexpected_detection_kind_observations
    )
    observation_count = (
        sum(case.matching_observation_count for case in evaluation.cases)
        + len(evaluation.unexpected_cross_rule_observations)
        + len(evaluation.unexpected_detection_kind_observations)
        if typed_cases and typed_unexpected and typed_kind_mismatches
        else -1
    )
    if (
        not _successful_status_code(
            evaluation.execution_status,
            evaluation.return_code,
        )
        or type(evaluation.parsed_finding_count) is not int
        or evaluation.parsed_finding_count < 0
        or type(evaluation.pass_count) is not int
        or type(evaluation.fail_count) is not int
        or evaluation.pass_count + evaluation.fail_count != GITLEAKS_ADVERSARIAL_CASE_COUNT
        or not typed_cases
        or len(evaluation.cases) != GITLEAKS_ADVERSARIAL_CASE_COUNT
        or evaluation.cases != tuple(sorted(evaluation.cases, key=lambda case: case.case_id))
        or len({case.case_id for case in evaluation.cases}) != GITLEAKS_ADVERSARIAL_CASE_COUNT
        or evaluation.pass_count
        != sum(case.result == GitleaksAdversarialCaseResultValue.PASS for case in evaluation.cases)
        or evaluation.fail_count
        != sum(case.result == GitleaksAdversarialCaseResultValue.FAIL for case in evaluation.cases)
        or not typed_unexpected
        or not typed_kind_mismatches
        or not cross_rule_partitioned
        or not kind_mismatches_partitioned
        or evaluation.unexpected_cross_rule_observations
        != tuple(
            sorted(
                evaluation.unexpected_cross_rule_observations,
                key=_unexpected_observation_sort_key,
            )
        )
        or evaluation.unexpected_detection_kind_observations
        != tuple(
            sorted(
                evaluation.unexpected_detection_kind_observations,
                key=_unexpected_observation_sort_key,
            )
        )
        or observation_count != evaluation.parsed_finding_count
        or (
            evaluation.execution_status is GitleaksExecutionStatus.COMPLETED_NO_FINDINGS
            and evaluation.parsed_finding_count != 0
        )
        or (
            evaluation.execution_status is GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
            and evaluation.parsed_finding_count == 0
        )
        or _PROJECTION_ID.fullmatch(evaluation.projection_id) is None
        or not _valid_sha256(evaluation.context_digest)
        or not _valid_sha256(evaluation.projection_digest)
        or not _valid_sha256(evaluation.parse_result_digest)
    ):
        raise GitleaksAdversarialBenchmarkError


def _validate_manifest(
    manifest: object,
) -> GitleaksAdversarialManifest:
    if (
        not isinstance(manifest, GitleaksAdversarialManifest)
        or manifest.contract_sha256 != GITLEAKS_ADVERSARIAL_CONTRACT_SHA256
        or manifest.corpus_digest != GITLEAKS_ADVERSARIAL_CORPUS_DIGEST
        or len(manifest.cases) != GITLEAKS_ADVERSARIAL_CASE_COUNT
        or hashlib.sha256(manifest.canonical_json()).hexdigest()
        != GITLEAKS_ADVERSARIAL_MANIFEST_SHA256
    ):
        raise GitleaksAdversarialBenchmarkError
    return manifest


def _validate_parse_result(result: object) -> GitleaksParseResult:
    if (
        not isinstance(result, GitleaksParseResult)
        or result.scanner_id != GITLEAKS_SCANNER_ID
        or result.scanner_version != GITLEAKS_VERSION
        or result.binding_digest != GITLEAKS_BINDING_DIGEST
        or result.finding_count != len(result.findings)
    ):
        raise GitleaksAdversarialBenchmarkError
    return result


def _adversarial_path(file_path: str) -> str:
    return f"adversarial-corpus/{file_path}"


def _location(
    finding: NormalizedGitleaksFinding,
) -> GitleaksAdversarialObservationLocation | None:
    if finding.detection_kind is GitleaksDetectionKind.PATH:
        return None
    if finding.start_line is None or finding.end_line is None:
        raise GitleaksAdversarialBenchmarkError
    return GitleaksAdversarialObservationLocation(
        start_line=finding.start_line,
        end_line=finding.end_line,
        start_column=finding.start_column,
        end_column=finding.end_column,
    )


def _observation_sort_key(
    item: tuple[NormalizedGitleaksFinding, str],
) -> tuple[object, ...]:
    finding, identity = item
    return (
        _adversarial_path(finding.file_path),
        finding.rule_id,
        finding.detection_kind.value,
        finding.start_line or 0,
        finding.end_line or 0,
        finding.start_column or 0,
        finding.end_column or 0,
        identity,
    )


def evaluate_gitleaks_adversarial(
    manifest: GitleaksAdversarialManifest,
    parse_result: GitleaksParseResult,
    *,
    execution_status: GitleaksExecutionStatus,
    return_code: int,
) -> GitleaksAdversarialEvaluation:
    try:
        trusted_manifest = _validate_manifest(manifest)
        trusted_result = _validate_parse_result(parse_result)
        if not _successful_status_code(execution_status, return_code):
            raise GitleaksAdversarialBenchmarkError
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
        by_path = {case.relative_path: case for case in trusted_manifest.cases}
        if any(
            _adversarial_path(finding.file_path) not in by_path
            for finding, _identity in observations
        ):
            raise GitleaksAdversarialBenchmarkError

        case_rows: list[GitleaksAdversarialCaseResult] = []
        unexpected_cross_rule: list[GitleaksAdversarialUnexpectedObservation] = []
        unexpected_detection_kind: list[GitleaksAdversarialUnexpectedObservation] = []
        for case in trusted_manifest.cases:
            same_path = tuple(
                item
                for item in observations
                if _adversarial_path(item[0].file_path) == case.relative_path
            )
            intended = tuple(
                item
                for item in same_path
                if item[0].rule_id == case.expected_rule_id
                and item[0].detection_kind is case.expected_detection_kind
            )
            observed = bool(intended)
            passed = observed is (
                case.expectation is GitleaksAdversarialExpectation.EXPECTED_OBSERVED
            )
            case_rows.append(
                GitleaksAdversarialCaseResult(
                    case_id=case.case_id,
                    relative_path=case.relative_path,
                    expected_rule_id=case.expected_rule_id,
                    expected_detection_kind=case.expected_detection_kind,
                    expectation=case.expectation,
                    mechanism=case.mechanism,
                    result=(
                        GitleaksAdversarialCaseResultValue.PASS
                        if passed
                        else GitleaksAdversarialCaseResultValue.FAIL
                    ),
                    matching_observation_count=len(intended),
                    matching_finding_instance_ids=tuple(
                        identity for _finding, identity in intended
                    ),
                )
            )
            for finding, identity in same_path:
                if (
                    finding.rule_id == case.expected_rule_id
                    and finding.detection_kind is case.expected_detection_kind
                ):
                    continue
                observation = GitleaksAdversarialUnexpectedObservation(
                    case_id=case.case_id,
                    file_path=case.relative_path,
                    rule_id=finding.rule_id,
                    detection_kind=finding.detection_kind,
                    location=_location(finding),
                    finding_instance_id=identity,
                )
                if finding.rule_id != case.expected_rule_id:
                    unexpected_cross_rule.append(observation)
                else:
                    unexpected_detection_kind.append(observation)

        frozen_rows = tuple(case_rows)
        return GitleaksAdversarialEvaluation(
            execution_status=execution_status,
            return_code=return_code,
            parsed_finding_count=trusted_result.finding_count,
            pass_count=sum(
                row.result == GitleaksAdversarialCaseResultValue.PASS for row in frozen_rows
            ),
            fail_count=sum(
                row.result == GitleaksAdversarialCaseResultValue.FAIL for row in frozen_rows
            ),
            cases=frozen_rows,
            unexpected_cross_rule_observations=tuple(
                sorted(
                    unexpected_cross_rule,
                    key=_unexpected_observation_sort_key,
                )
            ),
            unexpected_detection_kind_observations=tuple(
                sorted(
                    unexpected_detection_kind,
                    key=_unexpected_observation_sort_key,
                )
            ),
            projection_id=trusted_result.projection_id,
            context_digest=trusted_result.context_digest,
            projection_digest=trusted_result.projection_digest,
            parse_result_digest=hashlib.sha256(trusted_result.canonical_json()).hexdigest(),
        )
    except GitleaksAdversarialBenchmarkError:
        raise
    except Exception:
        raise GitleaksAdversarialBenchmarkError from None


def build_gitleaks_adversarial_report(
    manifest: GitleaksAdversarialManifest,
    evaluation: GitleaksAdversarialEvaluation,
    proof: _GitleaksAdversarialConfidentialityProof,
) -> GitleaksAdversarialReport:
    _validate_manifest(manifest)
    if not isinstance(proof, _GitleaksAdversarialConfidentialityProof):
        raise GitleaksAdversarialBenchmarkError
    if any(
        result.case_id != case.case_id
        or result.relative_path != case.relative_path
        or result.expected_rule_id != case.expected_rule_id
        or result.expected_detection_kind is not case.expected_detection_kind
        or result.expectation is not case.expectation
        or result.mechanism is not case.mechanism
        for case, result in zip(manifest.cases, evaluation.cases, strict=True)
    ):
        raise GitleaksAdversarialBenchmarkError
    return GitleaksAdversarialReport(evaluation, proof)


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


def _read_projection_fixture(
    projection: PreparedSourceProjection,
    case: GitleaksAdversarialCase,
) -> bytes:
    relative = PurePosixPath(case.relative_path).relative_to("adversarial-corpus")
    target = projection.source_directory / relative
    descriptor = -1
    try:
        before = target.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_size > _MAX_FIXTURE_BYTES
        ):
            raise OSError
        descriptor = os.open(
            target,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stat_identity(before) != _stat_identity(opened):
            raise OSError
        payload = bytearray()
        while len(payload) <= _MAX_FIXTURE_BYTES:
            chunk = os.read(
                descriptor,
                min(4096, _MAX_FIXTURE_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        finished = os.fstat(descriptor)
        after_path = target.lstat()
        if (
            len(payload) > _MAX_FIXTURE_BYTES
            or len(payload) != before.st_size
            or _stat_identity(before) != _stat_identity(finished)
            or _stat_identity(before) != _stat_identity(after_path)
            or hashlib.sha256(bytes(payload)).hexdigest() != case.sha256
        ):
            raise OSError
        return bytes(payload)
    except (OSError, ValueError):
        raise GitleaksAdversarialConfidentialityError from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _projection_sentinels(
    manifest: GitleaksAdversarialManifest,
    projection: PreparedSourceProjection,
) -> tuple[bytes, ...]:
    sentinels: set[bytes] = set()
    for case in manifest.cases:
        if case.expected_detection_kind is not GitleaksDetectionKind.CONTENT:
            continue
        payload = _read_projection_fixture(projection, case)
        sentinels.update(_GENERIC_SENTINEL.findall(payload))
        sentinels.update(_GITHUB_SENTINEL.findall(payload))
    if not sentinels or any(len(value) < 16 for value in sentinels):
        raise GitleaksAdversarialConfidentialityError
    return tuple(sorted(sentinels))


def _validate_and_parse_controlled_execution(
    manifest: GitleaksAdversarialManifest,
    projection: PreparedSourceProjection,
    result: GitleaksExecutionResultEnvelope,
) -> tuple[GitleaksParseResult, _GitleaksAdversarialConfidentialityProof]:
    if (
        not isinstance(result, GitleaksExecutionResultEnvelope)
        or result.scanner_id != GITLEAKS_SCANNER_ID
        or result.scanner_version != GITLEAKS_VERSION
        or result.binding_digest != GITLEAKS_BINDING_DIGEST
        or not _successful_status_code(
            result.execution_status,
            result.return_code,
        )
    ):
        raise GitleaksAdversarialConfidentialityError
    if any(
        sentinel in stream
        for sentinel in _projection_sentinels(manifest, projection)
        for stream in (result.stdout_bytes, result.stderr_bytes)
    ):
        raise GitleaksAdversarialConfidentialityError
    parse_result = parse_gitleaks_execution_result(result, projection)
    digest = hashlib.sha256(parse_result.canonical_json()).hexdigest()
    return parse_result, _GitleaksAdversarialConfidentialityProof(
        projection_id=result.projection_id,
        context_digest=result.context_digest,
        projection_digest=result.projection_digest,
        execution_status=result.execution_status,
        return_code=result.return_code,
        corpus_digest=manifest.corpus_digest,
        parse_result_digest=digest,
        _token=_CONFIDENTIALITY_PROOF_TOKEN,
    )


def _workspace_matches_manifest(
    manifest: GitleaksAdversarialManifest,
    entries: tuple[RepositoryManifestEntry, ...],
) -> bool:
    expected = tuple(
        sorted(
            (
                PurePosixPath(case.relative_path).relative_to("adversarial-corpus").as_posix(),
                case.sha256,
            )
            for case in manifest.cases
        )
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
        leased_by="gitleaks-adversarial",
        lease_expires_at=_FIXED_TIME,
        heartbeat_at=_FIXED_TIME,
        cancel_requested=False,
        idempotency_key=hashlib.sha256(b"securescan-gitleaks-f4b1").hexdigest(),
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
) -> GitleaksAdversarialReport:
    try:
        manifest = verify_gitleaks_adversarial(repository_root)
        if binding.binding_digest() != GITLEAKS_BINDING_DIGEST:
            raise GitleaksAdversarialBenchmarkError
        corpus_root = repository_root / GITLEAKS_ADVERSARIAL_CORPUS_PATH
        with tempfile.TemporaryDirectory(
            prefix="securescan-gitleaks-adversarial-"
        ) as temporary_name:
            temporary_root = Path(temporary_name).resolve()
            if temporary_root.is_relative_to(repository_root):
                raise GitleaksAdversarialBenchmarkError
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
                    raise GitleaksAdversarialBenchmarkError
                context = SourceExecutionContext(
                    source_run_id=_FIXED_SOURCE_RUN_ID,
                    job_id=_FIXED_JOB_ID,
                    repository_digest=workspace.manifest.content_digest,
                    profile_digest=GITLEAKS_ADVERSARIAL_MANIFEST_SHA256,
                    plan_digest=GITLEAKS_ADVERSARIAL_CONTRACT_SHA256,
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
                    raise GitleaksAdversarialBenchmarkError
                parsed, proof = _validate_and_parse_controlled_execution(
                    manifest,
                    projection,
                    result,
                )
                evaluation = evaluate_gitleaks_adversarial(
                    manifest,
                    parsed,
                    execution_status=result.execution_status,
                    return_code=result.return_code,
                )
                return build_gitleaks_adversarial_report(
                    manifest,
                    evaluation,
                    proof,
                )
            finally:
                try:
                    if projection is not None:
                        projection_manager.cleanup_projection(projection)
                finally:
                    workspace_manager.cleanup_workspace(workspace)
    except GitleaksAdversarialConfidentialityError:
        raise
    except Exception:
        raise GitleaksAdversarialBenchmarkError from None


def check_controlled_gitleaks_adversarial(
    repository_root: Path,
    executable_path: Path,
) -> dict[str, object]:
    if (
        not isinstance(repository_root, Path)
        or not repository_root.is_absolute()
        or not isinstance(executable_path, Path)
        or not executable_path.is_absolute()
    ):
        raise GitleaksAdversarialBenchmarkError
    try:
        verify_gitleaks_adversarial(repository_root)
        binding = create_default_gitleaks_binding(executable_path)
        if binding.binding_digest() != GITLEAKS_BINDING_DIGEST:
            raise GitleaksAdversarialBenchmarkError
        binding.verify_runtime()
    except Exception:
        raise GitleaksAdversarialBenchmarkError from None
    return {
        "adversarial_id": GITLEAKS_ADVERSARIAL_ID,
        "binding_digest": GITLEAKS_BINDING_DIGEST,
        "case_count": GITLEAKS_ADVERSARIAL_CASE_COUNT,
        "contract_sha256": GITLEAKS_ADVERSARIAL_CONTRACT_SHA256,
        "corpus_digest": GITLEAKS_ADVERSARIAL_CORPUS_DIGEST,
        "f3b_baseline_commit": GITLEAKS_F3B_BASELINE_COMMIT,
        "f3b_baseline_sha256": GITLEAKS_F3B_BASELINE_SHA256,
        "f3b_baseline_tag": GITLEAKS_F3B_BASELINE_TAG,
        "f4a_baseline_commit": GITLEAKS_F4A_BASELINE_COMMIT,
        "f4a_baseline_tag": GITLEAKS_F4A_BASELINE_TAG,
        "manifest_sha256": GITLEAKS_ADVERSARIAL_MANIFEST_SHA256,
        "runtime_verified": True,
        "scanner_id": GITLEAKS_SCANNER_ID,
        "scanner_version": GITLEAKS_VERSION,
    }


def run_controlled_gitleaks_adversarial(
    repository_root: Path,
    executable_path: Path,
) -> GitleaksAdversarialReport:
    if (
        not isinstance(repository_root, Path)
        or not repository_root.is_absolute()
        or not isinstance(executable_path, Path)
        or not executable_path.is_absolute()
    ):
        raise GitleaksAdversarialBenchmarkError
    try:
        binding = create_default_gitleaks_binding(executable_path)
        return _run_with_dependencies(repository_root, binding, None)
    except GitleaksAdversarialConfidentialityError:
        raise
    except Exception:
        raise GitleaksAdversarialBenchmarkError from None


def record_gitleaks_adversarial_report(
    repository_root: Path,
    report: GitleaksAdversarialReport,
) -> Path:
    if (
        not isinstance(repository_root, Path)
        or not repository_root.is_absolute()
        or not isinstance(report, GitleaksAdversarialReport)
    ):
        raise GitleaksAdversarialBenchmarkError
    destination = repository_root / GITLEAKS_ADVERSARIAL_RESULT_PATH
    staging: Path | None = None
    try:
        manifest = verify_gitleaks_adversarial(repository_root)
        build_gitleaks_adversarial_report(
            manifest,
            report.evaluation,
            report._confidentiality_proof,
        )
        payload = report.canonical_json()
        parent = destination.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
            raise GitleaksAdversarialBenchmarkError
        try:
            destination.lstat()
        except FileNotFoundError:
            pass
        else:
            raise GitleaksAdversarialBenchmarkError
        descriptor, staging_name = tempfile.mkstemp(
            prefix=".adversarial-v1-result-",
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
    except GitleaksAdversarialBenchmarkError:
        raise
    except Exception:
        raise GitleaksAdversarialBenchmarkError from None
    finally:
        if staging is not None:
            with suppress(OSError):
                staging.unlink(missing_ok=True)

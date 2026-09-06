from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Final

from securescan.scanners.checkov.binding import (
    CHECKOV_FRAMEWORKS,
    CHECKOV_SCANNER_ID,
    CHECKOV_VERSION,
)
from securescan.scanners.checkov.source_execution import (
    CheckovExecutionResultEnvelope,
    CheckovExecutionStatus,
    CheckovFailureCode,
)

CHECKOV_PARSER_SCHEMA_VERSION: Final = "securescan-checkov-parser-s3"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PROJECTION_ID = re.compile(r"securescan-source-projection-[0-9a-f]{16,48}\Z", re.ASCII)
_CHECK_ID = re.compile(r"CKV(?:2)?_[A-Z0-9][A-Z0-9_]{1,126}\Z", re.ASCII)
_MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
_MAX_RECORDS = 250_000
_MAX_FINDINGS = 100_000
_MAX_SUPPRESSIONS = 100_000
_MAX_PARSE_GAPS = 10_000
_MAX_STRING = 16_384
_MAX_NAME = 2_048
_MAX_PATH = 16_384
_MAX_DEPTH = 64
_FINDING_DOMAIN = b"securescan-configuration-security-finding-s3\0"
_SUMMARY_KEYS = {
    "passed",
    "failed",
    "skipped",
    "parsing_errors",
    "resource_count",
    "checkov_version",
}


class CheckovParserError(RuntimeError):
    def __init__(self, code: CheckovFailureCode = CheckovFailureCode.OUTPUT_INVALID) -> None:
        self.code = code
        super().__init__("Checkov output is invalid")


class CheckovFrameworkState(StrEnum):
    COMPLETED = "completed"
    COMPLETED_WITH_FINDINGS = "completed_with_findings"
    COMPLETED_WITH_SUPPRESSIONS = "completed_with_suppressions"
    NOT_APPLICABLE = "not_applicable"
    INCOMPLETE_PARSE_GAP = "incomplete_parse_gap"


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> None:
    raise ValueError


def _validate_tree(value: object, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise ValueError
    if value is None or isinstance(value, (str, bool)) or type(value) is int:
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError
        return
    if isinstance(value, list):
        for item in value:
            _validate_tree(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError
            _validate_tree(item, depth + 1)
        return
    raise ValueError


def _bounded_string(value: object, *, limit: int = _MAX_STRING) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > limit
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise ValueError
    return value


def _normalized_string(value: object, *, limit: int = _MAX_STRING) -> str:
    if not isinstance(value, str):
        raise ValueError
    normalized = value.strip()
    return _bounded_string(normalized, limit=limit)


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _identity(framework: str, check_id: str, path: str, resource: str) -> str:
    digest = hashlib.sha256()
    digest.update(_FINDING_DOMAIN)
    digest.update(_canonical_json([framework, check_id, path, resource]))
    return digest.hexdigest()


def expected_checkov_frameworks(authorized_paths: frozenset[str]) -> frozenset[str]:
    expected: set[str] = set()
    for raw in authorized_paths:
        path = PurePosixPath(raw)
        name = path.name.casefold()
        if name.endswith(".tf") or name.endswith(".tf.json"):
            expected.add("terraform")
        if name == "dockerfile" or name.startswith("dockerfile."):
            expected.add("dockerfile")
        if (
            len(path.parts) >= 3
            and path.parts[0:2] == (".github", "workflows")
            and name.endswith((".yml", ".yaml"))
        ):
            expected.add("github_actions")
    return frozenset(expected)


def _normalize_path(value: object, authorized_paths: frozenset[str]) -> str:
    raw = _bounded_string(value, limit=_MAX_PATH)
    if raw.startswith("/"):
        raw = raw[1:]
    path = PurePosixPath(raw)
    if (
        not raw
        or "\\" in raw
        or path.is_absolute()
        or path.as_posix() != raw
        or any(part in {"", ".", ".."} for part in raw.split("/"))
        or raw not in authorized_paths
    ):
        raise ValueError
    return raw


def _normalize_error_path(
    value: object,
    projection_root: Path,
    authorized_paths: frozenset[str],
) -> str:
    raw = _bounded_string(value, limit=_MAX_PATH)
    path = Path(raw)
    if path.is_absolute():
        try:
            relative = path.relative_to(projection_root).as_posix()
        except ValueError:
            raise ValueError from None
        return _normalize_path(relative, authorized_paths)
    return _normalize_path(raw, authorized_paths)


def _line_range(value: object) -> tuple[int | None, int | None]:
    if value is None:
        return None, None
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(type(item) is not int or item < 0 for item in value)
        or value[1] < value[0]
    ):
        raise ValueError
    if value[0] == 0:
        return None, None
    return value[0], value[1]


def _severity(value: object) -> str | None:
    if value is None:
        return None
    text = _bounded_string(value, limit=64).upper()
    if text not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}:
        raise ValueError
    return text


@dataclass(frozen=True, slots=True)
class CheckovMisconfigurationObservation:
    scanner_id: str
    scanner_version: str
    framework: str
    check_id: str
    check_name: str
    resource: str
    normalized_path: str
    line_start: int | None
    line_end: int | None
    result: str
    severity: str | None
    projection_id: str
    snapshot_digest: str
    binding_digest: str
    observation_id: str

    def __post_init__(self) -> None:
        if (
            self.scanner_id != CHECKOV_SCANNER_ID
            or self.scanner_version != CHECKOV_VERSION
            or self.framework not in CHECKOV_FRAMEWORKS
            or _CHECK_ID.fullmatch(self.check_id) is None
            or _bounded_string(self.check_name, limit=_MAX_NAME) != self.check_name
            or _bounded_string(self.resource, limit=_MAX_NAME) != self.resource
            or _normalize_path(self.normalized_path, frozenset({self.normalized_path}))
            != self.normalized_path
            or (self.line_start is None) != (self.line_end is None)
            or (
                self.line_start is not None
                and (
                    type(self.line_start) is not int
                    or type(self.line_end) is not int
                    or self.line_start < 1
                    or self.line_end < self.line_start
                )
            )
            or self.result != "FAILED"
            or _severity(self.severity) != self.severity
            or _PROJECTION_ID.fullmatch(self.projection_id) is None
            or not _valid_digest(self.snapshot_digest)
            or not _valid_digest(self.binding_digest)
            or self.observation_id
            != _identity(self.framework, self.check_id, self.normalized_path, self.resource)
        ):
            raise ValueError("Checkov misconfiguration observation is invalid")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "binding_digest": self.binding_digest,
            "check_id": self.check_id,
            "check_name": self.check_name,
            "framework": self.framework,
            "line_end": self.line_end,
            "line_start": self.line_start,
            "normalized_path": self.normalized_path,
            "observation_id": self.observation_id,
            "projection_id": self.projection_id,
            "resource": self.resource,
            "result": self.result,
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
            "severity": self.severity,
            "snapshot_digest": self.snapshot_digest,
        }


@dataclass(frozen=True, slots=True)
class CheckovSuppressionObservation:
    framework: str
    check_id: str
    resource: str
    normalized_path: str
    reason: str | None

    def __post_init__(self) -> None:
        if (
            self.framework not in CHECKOV_FRAMEWORKS
            or _CHECK_ID.fullmatch(self.check_id) is None
            or _bounded_string(self.resource, limit=_MAX_NAME) != self.resource
            or _normalize_path(self.normalized_path, frozenset({self.normalized_path}))
            != self.normalized_path
            or (self.reason is not None and _bounded_string(self.reason, limit=512) != self.reason)
        ):
            raise ValueError("Checkov suppression observation is invalid")

    def canonical_data(self) -> dict[str, str | None]:
        return {
            "check_id": self.check_id,
            "framework": self.framework,
            "normalized_path": self.normalized_path,
            "reason": self.reason,
            "resource": self.resource,
        }


@dataclass(frozen=True, slots=True)
class CheckovParseGap:
    framework: str
    code: str
    normalized_path: str

    def __post_init__(self) -> None:
        if (
            self.framework not in CHECKOV_FRAMEWORKS
            or self.code != CheckovFailureCode.PARSE_GAP.value
            or _normalize_path(self.normalized_path, frozenset({self.normalized_path}))
            != self.normalized_path
        ):
            raise ValueError("Checkov parse gap is invalid")

    def canonical_data(self) -> dict[str, str]:
        return {
            "code": self.code,
            "framework": self.framework,
            "normalized_path": self.normalized_path,
        }


@dataclass(frozen=True, slots=True)
class CheckovPassedObservation:
    framework: str
    check_id: str
    resource: str
    normalized_path: str

    def __post_init__(self) -> None:
        if (
            self.framework not in CHECKOV_FRAMEWORKS
            or _CHECK_ID.fullmatch(self.check_id) is None
            or _bounded_string(self.resource, limit=_MAX_NAME) != self.resource
            or _normalize_path(self.normalized_path, frozenset({self.normalized_path}))
            != self.normalized_path
        ):
            raise ValueError("Checkov passed observation is invalid")


@dataclass(frozen=True, slots=True)
class CheckovFrameworkOutcome:
    framework: str
    state: CheckovFrameworkState
    failed_count: int
    passed_count: int
    suppressed_count: int
    parsing_gap_count: int
    resource_count: int

    def __post_init__(self) -> None:
        counts = (
            self.failed_count,
            self.passed_count,
            self.suppressed_count,
            self.parsing_gap_count,
            self.resource_count,
        )
        expected = (
            CheckovFrameworkState.INCOMPLETE_PARSE_GAP
            if self.parsing_gap_count
            else CheckovFrameworkState.COMPLETED_WITH_FINDINGS
            if self.failed_count
            else CheckovFrameworkState.COMPLETED_WITH_SUPPRESSIONS
            if self.suppressed_count
            else CheckovFrameworkState.COMPLETED
        )
        if (
            self.framework not in CHECKOV_FRAMEWORKS
            or not isinstance(self.state, CheckovFrameworkState)
            or any(type(value) is not int or value < 0 for value in counts)
            or (self.state is CheckovFrameworkState.NOT_APPLICABLE and any(counts))
            or (
                self.state is not CheckovFrameworkState.NOT_APPLICABLE
                and self.state is not expected
            )
        ):
            raise ValueError("Checkov framework outcome is invalid")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "failed_count": self.failed_count,
            "framework": self.framework,
            "parsing_gap_count": self.parsing_gap_count,
            "passed_count": self.passed_count,
            "resource_count": self.resource_count,
            "state": self.state.value,
            "suppressed_count": self.suppressed_count,
        }


@dataclass(frozen=True, slots=True)
class ConfigurationSecurityFinding:
    finding_id: str
    scanner_id: str
    scanner_version: str
    source: str
    framework: str
    check_id: str
    check_name: str
    resource: str
    normalized_path: str
    line_start: int | None
    line_end: int | None
    severity: str | None
    projection_id: str
    snapshot_digest: str
    checkov_binding_digest: str

    def __post_init__(self) -> None:
        if (
            self.finding_id
            != _identity(self.framework, self.check_id, self.normalized_path, self.resource)
            or self.scanner_id != CHECKOV_SCANNER_ID
            or self.scanner_version != CHECKOV_VERSION
            or self.source != CHECKOV_SCANNER_ID
            or self.framework not in CHECKOV_FRAMEWORKS
            or _CHECK_ID.fullmatch(self.check_id) is None
            or _bounded_string(self.check_name, limit=_MAX_NAME) != self.check_name
            or _bounded_string(self.resource, limit=_MAX_NAME) != self.resource
            or _normalize_path(self.normalized_path, frozenset({self.normalized_path}))
            != self.normalized_path
            or (self.line_start is None) != (self.line_end is None)
            or (
                self.line_start is not None
                and (
                    type(self.line_start) is not int
                    or type(self.line_end) is not int
                    or self.line_start < 1
                    or self.line_end < self.line_start
                )
            )
            or _severity(self.severity) != self.severity
            or _PROJECTION_ID.fullmatch(self.projection_id) is None
            or not _valid_digest(self.snapshot_digest)
            or not _valid_digest(self.checkov_binding_digest)
        ):
            raise ValueError("Configuration security finding is invalid")

    @classmethod
    def from_observation(
        cls, observation: CheckovMisconfigurationObservation
    ) -> ConfigurationSecurityFinding:
        return cls(
            finding_id=observation.observation_id,
            scanner_id=observation.scanner_id,
            scanner_version=observation.scanner_version,
            source=CHECKOV_SCANNER_ID,
            framework=observation.framework,
            check_id=observation.check_id,
            check_name=observation.check_name,
            resource=observation.resource,
            normalized_path=observation.normalized_path,
            line_start=observation.line_start,
            line_end=observation.line_end,
            severity=observation.severity,
            projection_id=observation.projection_id,
            snapshot_digest=observation.snapshot_digest,
            checkov_binding_digest=observation.binding_digest,
        )

    def canonical_data(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "checkov_binding_digest": self.checkov_binding_digest,
            "finding_id": self.finding_id,
            "framework": self.framework,
            "line_end": self.line_end,
            "line_start": self.line_start,
            "normalized_path": self.normalized_path,
            "projection_id": self.projection_id,
            "resource": self.resource,
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
            "severity": self.severity,
            "snapshot_digest": self.snapshot_digest,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class CheckovParseResult:
    scanner_id: str
    scanner_version: str
    binding_digest: str
    projection_id: str
    snapshot_digest: str
    observations: tuple[CheckovMisconfigurationObservation, ...]
    findings: tuple[ConfigurationSecurityFinding, ...]
    suppressions: tuple[CheckovSuppressionObservation, ...]
    gaps: tuple[CheckovParseGap, ...]
    framework_outcomes: tuple[CheckovFrameworkOutcome, ...]
    passed_observations: tuple[CheckovPassedObservation, ...] = field(repr=False)
    schema_version: str = CHECKOV_PARSER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        expected_findings = tuple(
            ConfigurationSecurityFinding.from_observation(item) for item in self.observations
        )
        if (
            self.schema_version != CHECKOV_PARSER_SCHEMA_VERSION
            or self.scanner_id != CHECKOV_SCANNER_ID
            or self.scanner_version != CHECKOV_VERSION
            or not _valid_digest(self.binding_digest)
            or _PROJECTION_ID.fullmatch(self.projection_id) is None
            or not _valid_digest(self.snapshot_digest)
            or self.observations
            != tuple(sorted(self.observations, key=lambda item: item.observation_id))
            or len({item.observation_id for item in self.observations}) != len(self.observations)
            or self.findings != expected_findings
            or self.suppressions
            != tuple(
                sorted(
                    self.suppressions,
                    key=lambda item: (
                        item.framework,
                        item.check_id,
                        item.normalized_path,
                        item.resource,
                    ),
                )
            )
            or self.gaps
            != tuple(sorted(self.gaps, key=lambda item: (item.framework, item.normalized_path)))
            or self.framework_outcomes
            != tuple(
                sorted(
                    self.framework_outcomes,
                    key=lambda item: CHECKOV_FRAMEWORKS.index(item.framework),
                )
            )
            or tuple(item.framework for item in self.framework_outcomes) != CHECKOV_FRAMEWORKS
            or self.passed_observations
            != tuple(
                sorted(
                    self.passed_observations,
                    key=lambda item: (
                        item.framework,
                        item.check_id,
                        item.normalized_path,
                        item.resource,
                    ),
                )
            )
            or any(
                item.projection_id != self.projection_id
                or item.snapshot_digest != self.snapshot_digest
                or item.binding_digest != self.binding_digest
                for item in self.observations
            )
        ):
            raise ValueError("Checkov parse result is invalid")
        for outcome in self.framework_outcomes:
            if (
                outcome.failed_count
                != sum(item.framework == outcome.framework for item in self.observations)
                or outcome.passed_count
                != sum(item.framework == outcome.framework for item in self.passed_observations)
                or outcome.suppressed_count
                != sum(item.framework == outcome.framework for item in self.suppressions)
                or outcome.parsing_gap_count
                != sum(item.framework == outcome.framework for item in self.gaps)
            ):
                raise ValueError("Checkov parse result is invalid")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "binding_digest": self.binding_digest,
            "findings": [item.canonical_data() for item in self.findings],
            "framework_outcomes": [item.canonical_data() for item in self.framework_outcomes],
            "gaps": [item.canonical_data() for item in self.gaps],
            "observation_count": len(self.observations),
            "projection_id": self.projection_id,
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
            "schema_version": self.schema_version,
            "snapshot_digest": self.snapshot_digest,
            "suppressions": [item.canonical_data() for item in self.suppressions],
        }

    def canonical_json(self) -> bytes:
        return _canonical_json(self.canonical_data()) + b"\n"


def _parse_record(
    record: object,
    *,
    framework: str,
    expected_result: str,
    authorized_paths: frozenset[str],
    projection_id: str,
    snapshot_digest: str,
    binding_digest: str,
) -> tuple[
    CheckovMisconfigurationObservation | None,
    CheckovSuppressionObservation | None,
    CheckovPassedObservation | None,
]:
    if not isinstance(record, dict):
        raise ValueError
    check_id = _bounded_string(record.get("check_id"), limit=128)
    if _CHECK_ID.fullmatch(check_id) is None:
        raise ValueError
    check_name = _normalized_string(record.get("check_name"), limit=_MAX_NAME)
    resource = _bounded_string(record.get("resource"), limit=_MAX_NAME)
    try:
        path = _normalize_path(record.get("file_path"), authorized_paths)
    except ValueError:
        raise CheckovParserError(CheckovFailureCode.PATH_INVALID) from None
    line_start, line_end = _line_range(record.get("file_line_range"))
    result_data = record.get("check_result")
    if not isinstance(result_data, dict) or result_data.get("result") != expected_result:
        raise ValueError
    severity = _severity(record.get("severity"))
    if expected_result == "FAILED":
        observation = CheckovMisconfigurationObservation(
            scanner_id=CHECKOV_SCANNER_ID,
            scanner_version=CHECKOV_VERSION,
            framework=framework,
            check_id=check_id,
            check_name=check_name,
            resource=resource,
            normalized_path=path,
            line_start=line_start,
            line_end=line_end,
            result="FAILED",
            severity=severity,
            projection_id=projection_id,
            snapshot_digest=snapshot_digest,
            binding_digest=binding_digest,
            observation_id=_identity(framework, check_id, path, resource),
        )
        return observation, None, None
    if expected_result == "SKIPPED":
        reason_value = result_data.get("suppress_comment")
        reason = None if reason_value in {None, ""} else _bounded_string(reason_value, limit=512)
        return (
            None,
            CheckovSuppressionObservation(framework, check_id, resource, path, reason),
            None,
        )
    return None, None, CheckovPassedObservation(framework, check_id, resource, path)


def parse_checkov_json(
    payload: bytes,
    *,
    projection_root: Path,
    authorized_paths: frozenset[str],
    projection_id: str,
    snapshot_digest: str,
    binding_digest: str,
) -> CheckovParseResult:
    try:
        if (
            not isinstance(payload, bytes)
            or len(payload) > _MAX_DOCUMENT_BYTES
            or not projection_root.is_absolute()
            or not authorized_paths
            or _PROJECTION_ID.fullmatch(projection_id) is None
            or not _valid_digest(snapshot_digest)
            or not _valid_digest(binding_digest)
        ):
            raise ValueError
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
        _validate_tree(document)
        expected_frameworks = expected_checkov_frameworks(authorized_paths)
        summary_only = isinstance(document, dict) and set(document) == _SUMMARY_KEYS
        if summary_only:
            if (
                document.get("checkov_version") != CHECKOV_VERSION
                or any(
                    type(document.get(key)) is not int or document[key] != 0
                    for key in _SUMMARY_KEYS - {"checkov_version"}
                )
                or expected_frameworks
            ):
                raise CheckovParserError(CheckovFailureCode.RESULT_INCONSISTENT)
            reports: list[object] = []
        else:
            reports = [document] if isinstance(document, dict) else document
        if (
            not isinstance(reports, list)
            or len(reports) > len(CHECKOV_FRAMEWORKS)
            or (not reports and not summary_only)
        ):
            raise ValueError
        observations: list[CheckovMisconfigurationObservation] = []
        suppressions: list[CheckovSuppressionObservation] = []
        gaps: list[CheckovParseGap] = []
        passed: list[CheckovPassedObservation] = []
        outcomes: dict[str, CheckovFrameworkOutcome] = {}
        total_records = 0
        for report in reports:
            if not isinstance(report, dict) or set(report) != {
                "check_type",
                "results",
                "summary",
                "url",
            }:
                raise ValueError
            _bounded_string(report.get("url"), limit=_MAX_NAME)
            framework = report.get("check_type")
            if framework not in CHECKOV_FRAMEWORKS or framework in outcomes:
                raise CheckovParserError(CheckovFailureCode.UNSUPPORTED_FRAMEWORK)
            results = report.get("results")
            summary = report.get("summary")
            if not isinstance(results, dict) or not isinstance(summary, dict):
                raise ValueError
            expected_keys = {"failed_checks", "passed_checks", "skipped_checks", "parsing_errors"}
            if set(results) != expected_keys:
                raise ValueError
            collections = {key: results[key] for key in expected_keys}
            if any(not isinstance(value, list) for value in collections.values()):
                raise ValueError
            counts = {
                "failed": len(collections["failed_checks"]),
                "passed": len(collections["passed_checks"]),
                "skipped": len(collections["skipped_checks"]),
                "parsing_errors": len(collections["parsing_errors"]),
            }
            total_records += sum(counts.values())
            if (
                total_records > _MAX_RECORDS
                or summary.get("checkov_version") != CHECKOV_VERSION
                or any(summary.get(key) != value for key, value in counts.items())
                or type(summary.get("resource_count")) is not int
                or not 0 <= summary["resource_count"] <= _MAX_RECORDS
            ):
                raise CheckovParserError(CheckovFailureCode.RESULT_INCONSISTENT)
            for key, expected_result in (
                ("failed_checks", "FAILED"),
                ("passed_checks", "PASSED"),
                ("skipped_checks", "SKIPPED"),
            ):
                for record in collections[key]:
                    observation, suppression, passed_item = _parse_record(
                        record,
                        framework=framework,
                        expected_result=expected_result,
                        authorized_paths=authorized_paths,
                        projection_id=projection_id,
                        snapshot_digest=snapshot_digest,
                        binding_digest=binding_digest,
                    )
                    if observation is not None:
                        observations.append(observation)
                    if suppression is not None:
                        suppressions.append(suppression)
                    if passed_item is not None:
                        passed.append(passed_item)
            for raw_path in collections["parsing_errors"]:
                try:
                    normalized_gap_path = _normalize_error_path(
                        raw_path,
                        projection_root,
                        authorized_paths,
                    )
                except ValueError:
                    raise CheckovParserError(CheckovFailureCode.PATH_INVALID) from None
                gaps.append(
                    CheckovParseGap(
                        framework=framework,
                        code=CheckovFailureCode.PARSE_GAP.value,
                        normalized_path=normalized_gap_path,
                    )
                )
            state = (
                CheckovFrameworkState.INCOMPLETE_PARSE_GAP
                if counts["parsing_errors"]
                else CheckovFrameworkState.COMPLETED_WITH_FINDINGS
                if counts["failed"]
                else CheckovFrameworkState.COMPLETED_WITH_SUPPRESSIONS
                if counts["skipped"]
                else CheckovFrameworkState.COMPLETED
            )
            outcomes[framework] = CheckovFrameworkOutcome(
                framework,
                state,
                counts["failed"],
                counts["passed"],
                counts["skipped"],
                counts["parsing_errors"],
                summary["resource_count"],
            )
        if not expected_frameworks.issubset(outcomes.keys()):
            raise CheckovParserError(CheckovFailureCode.RESULT_INCONSISTENT)
        for framework in CHECKOV_FRAMEWORKS:
            outcomes.setdefault(
                framework,
                CheckovFrameworkOutcome(
                    framework,
                    CheckovFrameworkState.NOT_APPLICABLE,
                    0,
                    0,
                    0,
                    0,
                    0,
                ),
            )
        observations.sort(key=lambda item: item.observation_id)
        suppressions.sort(
            key=lambda item: (item.framework, item.check_id, item.normalized_path, item.resource)
        )
        gaps.sort(key=lambda item: (item.framework, item.normalized_path))
        passed.sort(
            key=lambda item: (item.framework, item.check_id, item.normalized_path, item.resource)
        )
        if (
            len(observations) > _MAX_FINDINGS
            or len(suppressions) > _MAX_SUPPRESSIONS
            or len(gaps) > _MAX_PARSE_GAPS
            or len({item.observation_id for item in observations}) != len(observations)
        ):
            raise CheckovParserError(CheckovFailureCode.RESULT_INCONSISTENT)
        findings = tuple(
            ConfigurationSecurityFinding.from_observation(item) for item in observations
        )
        return CheckovParseResult(
            scanner_id=CHECKOV_SCANNER_ID,
            scanner_version=CHECKOV_VERSION,
            binding_digest=binding_digest,
            projection_id=projection_id,
            snapshot_digest=snapshot_digest,
            observations=tuple(observations),
            findings=findings,
            suppressions=tuple(suppressions),
            gaps=tuple(gaps),
            framework_outcomes=tuple(outcomes[item] for item in CHECKOV_FRAMEWORKS),
            passed_observations=tuple(passed),
        )
    except CheckovParserError:
        raise
    except (AttributeError, KeyError, TypeError, UnicodeDecodeError, ValueError):
        raise CheckovParserError from None


def parse_checkov_execution_result(
    envelope: CheckovExecutionResultEnvelope,
    *,
    projection_root: Path,
    authorized_paths: frozenset[str],
) -> CheckovParseResult:
    if (
        not isinstance(envelope, CheckovExecutionResultEnvelope)
        or envelope.execution_status is not CheckovExecutionStatus.COMPLETED
        or envelope.failure_code is not None
        or envelope.return_code != 0
        or envelope.stderr_bytes
    ):
        raise CheckovParserError(CheckovFailureCode.PROCESS_FAILURE)
    return parse_checkov_json(
        envelope.stdout_bytes,
        projection_root=projection_root,
        authorized_paths=authorized_paths,
        projection_id=envelope.projection_id,
        snapshot_digest=envelope.projection_digest,
        binding_digest=envelope.binding_digest,
    )

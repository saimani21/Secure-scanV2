from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID

from securescan.domain.enums import ObservationType
from securescan.domain.models import AnalysisGap, Observation
from securescan.scanners.semgrep.models import (
    ParsedSemgrepOutput,
    SemgrepFindingNormalizationError,
    SemgrepOutputMalformedError,
    SemgrepOutputMissingError,
    SemgrepOutputTooLargeError,
    SemgrepScanPlan,
)
from securescan.workspaces.models import RepositoryManifest

_SOURCE_PREFIX = "/workspace/source/"
_MAX_RULE_ID_LENGTH = 512
_MAX_METADATA_ITEMS = 64
_MAX_STORED_GAPS = 100
_READ_CHUNK_BYTES = 1024 * 1024
_FIXED_FINDING_MESSAGE = "Semgrep security rule matched"
_CWE_ID_PATTERN = re.compile(r"CWE-[1-9][0-9]{0,5}\Z", re.ASCII)
_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def _contains_control_characters(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def _bounded_text(value: object, maximum: int) -> str:
    normalized = value.strip() if isinstance(value, str) else ""
    if (
        not isinstance(value, str)
        or not normalized
        or len(value) > maximum
        or _contains_control_characters(value)
    ):
        raise SemgrepFindingNormalizationError
    return normalized


def _positive_integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise SemgrepFindingNormalizationError
    return value


def _normalize_path(value: object, manifest_paths: set[str], maximum_bytes: int) -> str:
    scanner_path = _bounded_text(value, maximum_bytes + len(_SOURCE_PREFIX))
    if scanner_path.startswith(_SOURCE_PREFIX):
        scanner_path = scanner_path.removeprefix(_SOURCE_PREFIX)
    elif scanner_path.startswith("/"):
        raise SemgrepFindingNormalizationError
    scanner_path = scanner_path.replace("\\", "/")
    if (
        not scanner_path
        or scanner_path.startswith("/")
        or (
            len(scanner_path) >= 3
            and scanner_path[0].isalpha()
            and scanner_path[1:3] == ":/"
        )
        or "//" in scanner_path
        or len(scanner_path.encode("utf-8")) > maximum_bytes
    ):
        raise SemgrepFindingNormalizationError
    components = scanner_path.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise SemgrepFindingNormalizationError
    normalized = PurePosixPath(*components).as_posix()
    if normalized != scanner_path or normalized not in manifest_paths:
        raise SemgrepFindingNormalizationError
    return normalized


def _normalize_metadata(value: object) -> dict[str, list[str]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise SemgrepFindingNormalizationError
    raw_cwe = value.get("cwe", [])
    cwe_values = raw_cwe if isinstance(raw_cwe, list) else [raw_cwe]
    cwe_ids = sorted(
        {
            item
            for item in cwe_values
            if isinstance(item, str) and _CWE_ID_PATTERN.fullmatch(item) is not None
        }
    )[:_MAX_METADATA_ITEMS]
    return {"cwe": cwe_ids} if cwe_ids else {}


def _fingerprint(
    scanner_id: str,
    rule_id: str,
    path: str,
    start_line: int,
    start_column: int,
    end_line: int,
    end_column: int,
) -> str:
    identity = "\x1f".join(
        (
            scanner_id,
            rule_id,
            path,
            str(start_line),
            str(start_column),
            str(end_line),
            str(end_column),
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _normalize_finding(
    value: object,
    manifest_paths: set[str],
    maximum_path_bytes: int,
    scanner_id: str,
    scanner_version: str,
) -> Observation:
    if not isinstance(value, dict):
        raise SemgrepFindingNormalizationError
    rule_id = _bounded_text(value.get("check_id"), _MAX_RULE_ID_LENGTH)
    path = _normalize_path(value.get("path"), manifest_paths, maximum_path_bytes)
    start = value.get("start")
    end = value.get("end")
    extra = value.get("extra")
    if not isinstance(start, dict) or not isinstance(end, dict) or not isinstance(extra, dict):
        raise SemgrepFindingNormalizationError
    start_line = _positive_integer(start.get("line"))
    start_column = _positive_integer(start.get("col"))
    end_line = _positive_integer(end.get("line"))
    end_column = _positive_integer(end.get("col"))
    if (end_line, end_column) < (start_line, start_column):
        raise SemgrepFindingNormalizationError
    raw_severity = _bounded_text(extra.get("severity"), 64).upper()
    severity = _SEVERITY_MAP.get(raw_severity, "informational")
    metadata = _normalize_metadata(extra.get("metadata"))
    fingerprint = _fingerprint(
        scanner_id,
        rule_id,
        path,
        start_line,
        start_column,
        end_line,
        end_column,
    )
    cwe = metadata.get("cwe", [])
    cwe_ids = list(cwe) if isinstance(cwe, list) else []
    properties: dict[str, Any] = {
        "end_column": end_column,
        "scanner_version": scanner_version,
        "severity": severity,
        "start_column": start_column,
    }
    if metadata:
        properties["metadata"] = metadata
    return Observation(
        observation_id=UUID(fingerprint[:32]),
        producer=scanner_id,
        observation_type=ObservationType.SOURCE_RULE_MATCH,
        rule_id=rule_id,
        message=_FIXED_FINDING_MESSAGE,
        native_severity=severity,
        path=path,
        start_line=start_line,
        end_line=end_line,
        cwe_ids=cwe_ids,
        fingerprint=fingerprint,
        properties=properties,
    )


def _append_gap(
    gaps: list[AnalysisGap],
    gap: AnalysisGap,
    *,
    omitted_count: list[int],
) -> None:
    if len(gaps) < _MAX_STORED_GAPS:
        gaps.append(gap)
    else:
        omitted_count[0] += 1


def _diagnostic_category(value: object) -> tuple[str, str]:
    if not isinstance(value, dict):
        return "SEMGREP_UNKNOWN_DIAGNOSTIC", "Semgrep reported an unknown diagnostic"
    diagnostic_type = value.get("type")
    if isinstance(diagnostic_type, str):
        normalized = diagnostic_type.lower()
    elif (
        isinstance(diagnostic_type, list)
        and diagnostic_type
        and isinstance(diagnostic_type[0], str)
    ):
        normalized = diagnostic_type[0].lower()
    else:
        normalized = ""
    if "parse" in normalized or "syntax" in normalized:
        return "SEMGREP_PARSE_ERROR", "Semgrep could not parse part of the repository"
    if "invalid" in normalized or "target" in normalized:
        return "SEMGREP_INVALID_TARGET", "Semgrep rejected a repository target"
    if "language" in normalized:
        return "SEMGREP_UNSUPPORTED_LANGUAGE", "Semgrep reported an unsupported language"
    if "timeout" in normalized:
        return "SEMGREP_TIMEOUT", "Semgrep timed out while analyzing a repository file"
    if "rule" in normalized or "pattern" in normalized:
        return "SEMGREP_RULE_ERROR", "Semgrep reported a trusted rule diagnostic"
    if "internal" in normalized or "fatal" in normalized:
        return "SEMGREP_INTERNAL_ERROR", "Semgrep reported an internal scanner diagnostic"
    return "SEMGREP_UNKNOWN_DIAGNOSTIC", "Semgrep reported an unknown diagnostic"


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_non_finite_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def parse_semgrep_output(
    raw_json: bytes,
    manifest: RepositoryManifest,
    *,
    scanner_id: str,
    scanner_version: str,
    maximum_findings: int = 100_000,
) -> ParsedSemgrepOutput:
    if (
        not isinstance(raw_json, bytes)
        or not isinstance(manifest, RepositoryManifest)
        or not isinstance(scanner_id, str)
        or not scanner_id
        or len(scanner_id) > 64
        or _contains_control_characters(scanner_id)
        or not isinstance(scanner_version, str)
        or not scanner_version
        or len(scanner_version) > 64
        or _contains_control_characters(scanner_version)
        or not isinstance(maximum_findings, int)
        or isinstance(maximum_findings, bool)
        or not 1 <= maximum_findings <= 1_000_000
    ):
        raise SemgrepOutputMalformedError
    try:
        document = json.loads(
            raw_json.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise SemgrepOutputMalformedError from exc
    if not isinstance(document, dict):
        raise SemgrepOutputMalformedError
    results = document.get("results")
    errors = document.get("errors", [])
    if not isinstance(results, list) or not isinstance(errors, list):
        raise SemgrepOutputMalformedError

    manifest_paths = {entry.relative_path for entry in manifest.entries}
    maximum_path_bytes = max(
        (len(path.encode("utf-8")) for path in manifest_paths),
        default=1,
    )
    maximum_path_bytes = max(maximum_path_bytes, 1)
    gaps: list[AnalysisGap] = []
    omitted_gaps = [0]
    normalized_findings: list[Observation] = []
    rejected_count = 0
    for result in results:
        try:
            normalized_findings.append(
                _normalize_finding(
                    result,
                    manifest_paths,
                    maximum_path_bytes,
                    scanner_id,
                    scanner_version,
                )
            )
        except SemgrepFindingNormalizationError:
            rejected_count += 1
            _append_gap(
                gaps,
                AnalysisGap(
                    code="SEMGREP_FINDING_REJECTED",
                    message="Semgrep returned a finding that could not be safely normalized",
                    adapter_id=scanner_id,
                ),
                omitted_count=omitted_gaps,
            )

    by_fingerprint: dict[str, Observation] = {}
    duplicate_count = 0
    for finding in sorted(
        normalized_findings,
        key=lambda item: (
            item.path or "",
            item.start_line or 0,
            item.properties.get("start_column", 0),
            item.end_line or 0,
            item.properties.get("end_column", 0),
            item.rule_id,
        ),
    ):
        assert finding.fingerprint is not None
        if finding.fingerprint in by_fingerprint:
            duplicate_count += 1
        else:
            by_fingerprint[finding.fingerprint] = finding
    findings = list(by_fingerprint.values())
    if len(findings) > maximum_findings:
        excess = len(findings) - maximum_findings
        findings = findings[:maximum_findings]
        rejected_count += excess
        _append_gap(
            gaps,
            AnalysisGap(
                code="SEMGREP_FINDING_LIMIT",
                message="Additional Semgrep findings were omitted by the configured limit",
                adapter_id=scanner_id,
            ),
            omitted_count=omitted_gaps,
        )

    for diagnostic in errors:
        code, message = _diagnostic_category(diagnostic)
        _append_gap(
            gaps,
            AnalysisGap(code=code, message=message, adapter_id=scanner_id),
            omitted_count=omitted_gaps,
        )
    if omitted_gaps[0]:
        gaps.append(
            AnalysisGap(
                code="SEMGREP_DIAGNOSTIC_LIMIT",
                message="Additional Semgrep diagnostics were omitted by the configured limit",
                adapter_id=scanner_id,
            )
        )

    output_version = document.get("version")
    if (
        not isinstance(output_version, str)
        or not output_version
        or len(output_version) > 64
        or _contains_control_characters(output_version)
    ):
        output_version = None
    return ParsedSemgrepOutput(
        findings=tuple(findings),
        analysis_gaps=tuple(gaps),
        raw_result_count=len(results),
        accepted_result_count=len(findings),
        rejected_result_count=rejected_count,
        duplicate_result_count=duplicate_count,
        semgrep_error_count=len(errors),
        output_version=output_version,
    )


def read_semgrep_result(
    output_directory: Path,
    plan: SemgrepScanPlan,
) -> bytes:
    if not isinstance(plan, SemgrepScanPlan):
        raise SemgrepOutputMalformedError
    descriptor: int | None = None
    try:
        output = output_directory.resolve(strict=True)
        if output != output_directory or not output.is_dir() or output.is_symlink():
            raise SemgrepOutputMissingError
        result_path = output / plan.result_filename
        try:
            initial = result_path.stat(follow_symlinks=False)
        except FileNotFoundError as exc:
            raise SemgrepOutputMissingError from exc
        if (
            not stat.S_ISREG(initial.st_mode)
            or result_path.is_symlink()
            or initial.st_nlink != 1
            or result_path.parent != output
        ):
            raise SemgrepOutputMissingError
        descriptor = os.open(
            result_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)
        ):
            raise SemgrepOutputMissingError
        chunks: list[bytes] = []
        total = 0
        while total <= plan.maximum_result_bytes:
            chunk = os.read(
                descriptor,
                min(_READ_CHUNK_BYTES, plan.maximum_result_bytes + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > plan.maximum_result_bytes:
            raise SemgrepOutputTooLargeError
        return b"".join(chunks)
    except (
        SemgrepOutputMissingError,
        SemgrepOutputTooLargeError,
        SemgrepOutputMalformedError,
    ):
        raise
    except Exception as exc:
        raise SemgrepOutputMissingError from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

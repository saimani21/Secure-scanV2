from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Final

from securescan.scanners.gitleaks.binding import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
)
from securescan.scanners.gitleaks.source_execution import (
    GitleaksExecutionResultEnvelope,
    GitleaksExecutionStatus,
)
from securescan.source.projection import PreparedSourceProjection
from securescan.workspaces.models import RepositoryManifestEntry

GITLEAKS_PARSER_SCHEMA_VERSION: Final = "securescan-gitleaks-parser-v0.4C"
GITLEAKS_V04B_BASELINE_COMMIT: Final = (
    "4ac76be1ff8b2e2d9081cde4f689c5dae1808080"
)
GITLEAKS_V8301_PATH_ONLY_RULE_IDS: Final = frozenset({"pkcs12-file"})

_REDACTED_SECRET = "REDACTED"
_MAX_JSON_DEPTH = 32
_MAX_FINDINGS = 100_000
_MAX_RULE_ID_LENGTH = 256
_MAX_PATH_LENGTH = 4096
_MAX_DESCRIPTION_LENGTH = 4096
_MAX_TAGS = 64
_MAX_TAG_LENGTH = 256
_MAX_IGNORED_STRING_LENGTH = 64 * 1024
_MAX_LOCATION = 2_147_483_647
_RULE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\Z", re.ASCII)
_URL_SCHEME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:", re.ASCII)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PROJECTION_ID_PATTERN = re.compile(
    r"securescan-source-projection-[0-9a-f]{16,48}\Z",
    re.ASCII,
)
_PKCS12_PATH_PATTERN = re.compile(
    r"(?:^|/)[^/]+\.p(?:12|fx)\Z",
    re.IGNORECASE,
)
_REQUIRED_FIELDS = frozenset({"File", "RuleID", "StartLine"})
_KNOWN_FIELDS = frozenset(
    {
        "Author",
        "Commit",
        "Date",
        "Description",
        "Email",
        "EndColumn",
        "EndLine",
        "Entropy",
        "File",
        "Fingerprint",
        "Match",
        "Message",
        "RuleID",
        "Secret",
        "StartColumn",
        "StartLine",
        "SymlinkFile",
        "Tags",
    }
)
# Gitleaks 8.30.1's Finding has optional Link and Fragment members. The frozen
# `dir` producer cannot populate Link because filesystem fragments have no Git
# CommitInfo, and its detector never assigns Fragment. Keep both outside this
# accepted schema rather than broadening it for unreachable producer states.
_IGNORED_STRING_FIELDS = (
    "Author",
    "Commit",
    "Date",
    "Email",
    "Fingerprint",
    "Message",
    "SymlinkFile",
)


class GitleaksParserFailureCode(StrEnum):
    EXECUTION_INCOMPLETE = "GITLEAKS_EXECUTION_INCOMPLETE"
    OUTPUT_INVALID_UTF8 = "GITLEAKS_OUTPUT_INVALID_UTF8"
    OUTPUT_INVALID_JSON = "GITLEAKS_OUTPUT_INVALID_JSON"
    OUTPUT_INVALID_SCHEMA = "GITLEAKS_OUTPUT_INVALID_SCHEMA"
    OUTPUT_CONTRADICTORY = "GITLEAKS_OUTPUT_CONTRADICTORY"
    SECRET_NOT_REDACTED = "GITLEAKS_SECRET_NOT_REDACTED"
    PATH_INVALID = "GITLEAKS_PATH_INVALID"
    LOCATION_INVALID = "GITLEAKS_LOCATION_INVALID"
    PROJECTION_MISMATCH = "GITLEAKS_PROJECTION_MISMATCH"


class GitleaksDetectionKind(StrEnum):
    CONTENT = "CONTENT"
    PATH = "PATH"


_FAILURE_MESSAGES = {
    GitleaksParserFailureCode.EXECUTION_INCOMPLETE: (
        "Incomplete Gitleaks execution cannot be parsed"
    ),
    GitleaksParserFailureCode.OUTPUT_INVALID_UTF8: (
        "Gitleaks output is not valid UTF-8"
    ),
    GitleaksParserFailureCode.OUTPUT_INVALID_JSON: (
        "Gitleaks output is not valid canonical JSON input"
    ),
    GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA: (
        "Gitleaks output does not match the trusted schema"
    ),
    GitleaksParserFailureCode.OUTPUT_CONTRADICTORY: (
        "Gitleaks output contradicts the completed execution status"
    ),
    GitleaksParserFailureCode.SECRET_NOT_REDACTED: (
        "Gitleaks output contains a non-redacted secret field"
    ),
    GitleaksParserFailureCode.PATH_INVALID: (
        "Gitleaks output contains an invalid repository path"
    ),
    GitleaksParserFailureCode.LOCATION_INVALID: (
        "Gitleaks output contains an invalid source location"
    ),
    GitleaksParserFailureCode.PROJECTION_MISMATCH: (
        "Gitleaks output does not match the authorized Source projection"
    ),
}


class GitleaksParserError(RuntimeError):
    """Fixed-message parser error that never embeds scanner-controlled data."""

    def __init__(self, code: GitleaksParserFailureCode) -> None:
        if not isinstance(code, GitleaksParserFailureCode):
            raise TypeError("Gitleaks parser failure code is invalid")
        self.code = code
        super().__init__(_FAILURE_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class NormalizedGitleaksFinding:
    scanner_id: str
    scanner_version: str
    rule_id: str
    file_path: str
    detection_kind: GitleaksDetectionKind
    start_line: int | None
    end_line: int | None
    start_column: int | None
    end_column: int | None
    projection_id: str
    context_digest: str
    projection_digest: str

    def __post_init__(self) -> None:
        if (
            self.scanner_id != GITLEAKS_SCANNER_ID
            or self.scanner_version != GITLEAKS_VERSION
            or not isinstance(self.rule_id, str)
            or _RULE_ID_PATTERN.fullmatch(self.rule_id) is None
            or not _valid_normalized_relative_path(self.file_path)
            or not _valid_normalized_location(
                self.detection_kind,
                self.start_line,
                self.end_line,
                self.start_column,
                self.end_column,
            )
            or not isinstance(self.projection_id, str)
            or _PROJECTION_ID_PATTERN.fullmatch(self.projection_id) is None
            or any(
                not isinstance(digest, str)
                or _SHA256_PATTERN.fullmatch(digest) is None
                for digest in (self.context_digest, self.projection_digest)
            )
        ):
            raise ValueError("Normalized Gitleaks finding is invalid")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "context_digest": self.context_digest,
            "detection_kind": self.detection_kind.value,
            "end_column": self.end_column,
            "end_line": self.end_line,
            "file_path": self.file_path,
            "projection_digest": self.projection_digest,
            "projection_id": self.projection_id,
            "rule_id": self.rule_id,
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
            "start_column": self.start_column,
            "start_line": self.start_line,
        }


@dataclass(frozen=True, slots=True)
class GitleaksParseResult:
    scanner_id: str
    scanner_version: str
    binding_digest: str
    projection_id: str
    context_digest: str
    projection_digest: str
    findings: tuple[NormalizedGitleaksFinding, ...]
    finding_count: int
    schema_version: str = GITLEAKS_PARSER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != GITLEAKS_PARSER_SCHEMA_VERSION
            or self.scanner_id != GITLEAKS_SCANNER_ID
            or self.scanner_version != GITLEAKS_VERSION
            or not isinstance(self.binding_digest, str)
            or _SHA256_PATTERN.fullmatch(self.binding_digest) is None
            or not isinstance(self.projection_id, str)
            or _PROJECTION_ID_PATTERN.fullmatch(self.projection_id) is None
            or any(
                not isinstance(digest, str)
                or _SHA256_PATTERN.fullmatch(digest) is None
                for digest in (self.context_digest, self.projection_digest)
            )
            or not isinstance(self.findings, tuple)
            or any(
                not isinstance(finding, NormalizedGitleaksFinding)
                or finding.scanner_id != self.scanner_id
                or finding.scanner_version != self.scanner_version
                or finding.projection_id != self.projection_id
                or finding.context_digest != self.context_digest
                or finding.projection_digest != self.projection_digest
                for finding in self.findings
            )
            or type(self.finding_count) is not int
            or self.finding_count != len(self.findings)
        ):
            raise ValueError("Gitleaks parse result is invalid")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "binding_digest": self.binding_digest,
            "context_digest": self.context_digest,
            "finding_count": self.finding_count,
            "findings": [finding.canonical_data() for finding in self.findings],
            "projection_digest": self.projection_digest,
            "projection_id": self.projection_id,
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
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )


def _has_forbidden_character(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def _valid_bounded_string(
    value: object,
    *,
    maximum_length: int,
    allow_empty: bool,
) -> bool:
    return (
        isinstance(value, str)
        and (allow_empty or bool(value))
        and len(value) <= maximum_length
        and not _has_forbidden_character(value)
    )


def _valid_normalized_relative_path(value: object) -> bool:
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


def _valid_location(value: object) -> bool:
    return type(value) is int and 1 <= value <= _MAX_LOCATION


def _valid_location_tuple(
    start_line: object,
    end_line: object,
    start_column: object,
    end_column: object,
) -> bool:
    if (
        not _valid_location(start_line)
        or not _valid_location(end_line)
        or end_line < start_line
    ):
        return False
    if start_column is None and end_column is None:
        return True
    return (
        _valid_location(start_column)
        and _valid_location(end_column)
        and end_column >= start_column
    )


def _valid_normalized_location(
    detection_kind: object,
    start_line: object,
    end_line: object,
    start_column: object,
    end_column: object,
) -> bool:
    if detection_kind is GitleaksDetectionKind.PATH:
        return all(
            location is None
            for location in (start_line, end_line, start_column, end_column)
        )
    return detection_kind is GitleaksDetectionKind.CONTENT and _valid_location_tuple(
        start_line,
        end_line,
        start_column,
        end_column,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_non_finite_constant(_value: str) -> None:
    raise ValueError


def _validate_json_depth(payload: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in payload:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
        elif byte in (ord("["), ord("{")):
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                raise GitleaksParserError(
                    GitleaksParserFailureCode.OUTPUT_INVALID_JSON
                )
        elif byte in (ord("]"), ord("}")):
            depth -= 1
            if depth < 0:
                raise GitleaksParserError(
                    GitleaksParserFailureCode.OUTPUT_INVALID_JSON
                )


def _decode_findings(payload: bytes) -> list[dict[str, Any]]:
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise GitleaksParserError(
            GitleaksParserFailureCode.OUTPUT_INVALID_UTF8
        ) from None
    _validate_json_depth(payload)
    try:
        document = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except (RecursionError, TypeError, ValueError):
        raise GitleaksParserError(
            GitleaksParserFailureCode.OUTPUT_INVALID_JSON
        ) from None
    if (
        not isinstance(document, list)
        or len(document) > _MAX_FINDINGS
        or any(not isinstance(item, dict) for item in document)
    ):
        raise GitleaksParserError(
            GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA
        )
    return document


def _validate_projection_identity(
    envelope: GitleaksExecutionResultEnvelope,
    projection: PreparedSourceProjection,
) -> None:
    if (
        envelope.projection_id != projection.projection_id
        or envelope.context_digest != projection.context_digest
        or envelope.projection_digest != projection.projection_digest
        or projection.manifest.content_digest != projection.projection_digest
    ):
        raise GitleaksParserError(
            GitleaksParserFailureCode.PROJECTION_MISMATCH
        )


def _canonical_file_path(
    value: object,
    projection: PreparedSourceProjection,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_PATH_LENGTH
        or "\\" in value
        or _has_forbidden_character(value)
        or _URL_SCHEME_PATTERN.match(value) is not None
    ):
        raise GitleaksParserError(GitleaksParserFailureCode.PATH_INVALID)
    scanner_path = PurePosixPath(value)
    raw_parts = value.split("/")
    path_parts = raw_parts[1:] if scanner_path.is_absolute() else raw_parts
    if not path_parts or any(part in {"", ".", ".."} for part in path_parts):
        raise GitleaksParserError(GitleaksParserFailureCode.PATH_INVALID)
    if scanner_path.is_absolute():
        trusted_root = PurePosixPath(projection.source_directory.as_posix())
        try:
            scanner_path = scanner_path.relative_to(trusted_root)
        except ValueError:
            raise GitleaksParserError(
                GitleaksParserFailureCode.PATH_INVALID
            ) from None
    canonical = scanner_path.as_posix()
    if not _valid_normalized_relative_path(canonical):
        raise GitleaksParserError(GitleaksParserFailureCode.PATH_INVALID)
    if canonical not in {
        entry.relative_path for entry in projection.manifest.entries
    }:
        raise GitleaksParserError(GitleaksParserFailureCode.PATH_INVALID)
    return canonical


def _manifest_entry(
    file_path: str,
    projection: PreparedSourceProjection,
) -> RepositoryManifestEntry:
    for entry in projection.manifest.entries:
        if entry.relative_path == file_path:
            return entry
    raise GitleaksParserError(GitleaksParserFailureCode.PATH_INVALID)


def _read_verified_file(
    entry: RepositoryManifestEntry,
    projection: PreparedSourceProjection,
) -> bytes:
    path = projection.source_directory.joinpath(*PurePosixPath(entry.relative_path).parts)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != entry.size_bytes:
            raise OSError
        content = bytearray()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            content.extend(chunk)
    except OSError:
        raise GitleaksParserError(
            GitleaksParserFailureCode.PROJECTION_MISMATCH
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    payload = bytes(content)
    if hashlib.sha256(payload).hexdigest() != entry.sha256:
        raise GitleaksParserError(
            GitleaksParserFailureCode.PROJECTION_MISMATCH
        )
    return payload


def _validate_schema_strings(finding: dict[str, Any]) -> None:
    if "Description" in finding:
        description = finding["Description"]
        if not _valid_bounded_string(
            description,
            maximum_length=_MAX_DESCRIPTION_LENGTH,
            allow_empty=True,
        ):
            raise GitleaksParserError(
                GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA
            )
    for name in _IGNORED_STRING_FIELDS:
        if name in finding:
            value = finding[name]
            if not _valid_bounded_string(
                value,
                maximum_length=_MAX_IGNORED_STRING_LENGTH,
                allow_empty=True,
            ):
                raise GitleaksParserError(
                    GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA
                )
    if "Match" in finding:
        match = finding["Match"]
        if not _valid_bounded_string(
            match,
            maximum_length=_MAX_IGNORED_STRING_LENGTH,
            allow_empty=True,
        ):
            raise GitleaksParserError(
                GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA
            )


def _validate_tags(value: object) -> None:
    if (
        not isinstance(value, list)
        or len(value) > _MAX_TAGS
        or any(
            not _valid_bounded_string(
                tag,
                maximum_length=_MAX_TAG_LENGTH,
                allow_empty=False,
            )
            for tag in value
        )
    ):
        raise GitleaksParserError(
            GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA
        )


def _validate_entropy(value: object) -> None:
    if (
        type(value) not in {int, float}
        or not math.isfinite(value)
        or value < 0
    ):
        raise GitleaksParserError(
            GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA
        )


def _normalized_finding(
    finding: dict[str, Any],
    envelope: GitleaksExecutionResultEnvelope,
    projection: PreparedSourceProjection,
) -> NormalizedGitleaksFinding:
    if (
        not _REQUIRED_FIELDS.issubset(finding)
        or not set(finding).issubset(_KNOWN_FIELDS)
    ):
        raise GitleaksParserError(
            GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA
        )
    rule_id = finding["RuleID"]
    if (
        not isinstance(rule_id, str)
        or len(rule_id) > _MAX_RULE_ID_LENGTH
        or _RULE_ID_PATTERN.fullmatch(rule_id) is None
    ):
        raise GitleaksParserError(
            GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA
        )
    if "Secret" in finding and finding["Secret"] != _REDACTED_SECRET:
        raise GitleaksParserError(
            GitleaksParserFailureCode.SECRET_NOT_REDACTED
        )
    _validate_schema_strings(finding)
    if "Tags" in finding:
        _validate_tags(finding["Tags"])
    if "Entropy" in finding:
        _validate_entropy(finding["Entropy"])

    file_path = _canonical_file_path(finding["File"], projection)
    start_line = finding["StartLine"]
    end_line = finding.get("EndLine", start_line)
    start_column = finding.get("StartColumn")
    end_column = finding.get("EndColumn")
    entry = _manifest_entry(file_path, projection)
    content = _read_verified_file(entry, projection)

    if rule_id in GITLEAKS_V8301_PATH_ONLY_RULE_IDS:
        location_names = ("StartLine", "EndLine", "StartColumn", "EndColumn")
        if (
            envelope.execution_status
            is not GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
        ):
            raise GitleaksParserError(
                GitleaksParserFailureCode.OUTPUT_CONTRADICTORY
            )
        if (
            not all(name in finding for name in location_names)
            or any(type(finding[name]) is not int for name in location_names)
            or tuple(finding[name] for name in location_names) != (0, 0, 0, 0)
            or _PKCS12_PATH_PATTERN.search(file_path) is None
        ):
            raise GitleaksParserError(
                GitleaksParserFailureCode.LOCATION_INVALID
            )
        return NormalizedGitleaksFinding(
            scanner_id=envelope.scanner_id,
            scanner_version=envelope.scanner_version,
            rule_id=rule_id,
            file_path=file_path,
            detection_kind=GitleaksDetectionKind.PATH,
            start_line=None,
            end_line=None,
            start_column=None,
            end_column=None,
            projection_id=envelope.projection_id,
            context_digest=envelope.context_digest,
            projection_digest=envelope.projection_digest,
        )

    if ("StartColumn" in finding) is not ("EndColumn" in finding) or not (
        _valid_location_tuple(
            start_line,
            end_line,
            start_column,
            end_column,
        )
    ):
        raise GitleaksParserError(
            GitleaksParserFailureCode.LOCATION_INVALID
        )

    lines = content.splitlines()
    if not lines or end_line > len(lines):
        raise GitleaksParserError(
            GitleaksParserFailureCode.LOCATION_INVALID
        )
    if start_column is not None and (
        start_column > len(lines[start_line - 1]) + 1
        or end_column > len(lines[end_line - 1]) + 1
    ):
        raise GitleaksParserError(
            GitleaksParserFailureCode.LOCATION_INVALID
        )
    return NormalizedGitleaksFinding(
        scanner_id=envelope.scanner_id,
        scanner_version=envelope.scanner_version,
        rule_id=rule_id,
        file_path=file_path,
        detection_kind=GitleaksDetectionKind.CONTENT,
        start_line=start_line,
        end_line=end_line,
        start_column=start_column,
        end_column=end_column,
        projection_id=envelope.projection_id,
        context_digest=envelope.context_digest,
        projection_digest=envelope.projection_digest,
    )


def parse_gitleaks_execution_result(
    envelope: GitleaksExecutionResultEnvelope,
    projection: PreparedSourceProjection,
) -> GitleaksParseResult:
    if (
        not isinstance(envelope, GitleaksExecutionResultEnvelope)
        or not isinstance(projection, PreparedSourceProjection)
    ):
        raise GitleaksParserError(
            GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA
        )
    if envelope.execution_status not in {
        GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
        GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS,
    }:
        raise GitleaksParserError(
            GitleaksParserFailureCode.EXECUTION_INCOMPLETE
        )
    _validate_projection_identity(envelope, projection)
    findings = _decode_findings(envelope.stdout_bytes)
    normalized = tuple(
        _normalized_finding(finding, envelope, projection)
        for finding in findings
    )
    if (
        envelope.execution_status is GitleaksExecutionStatus.COMPLETED_NO_FINDINGS
        and normalized
    ) or (
        envelope.execution_status
        is GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
        and not normalized
    ):
        raise GitleaksParserError(
            GitleaksParserFailureCode.OUTPUT_CONTRADICTORY
        )
    return GitleaksParseResult(
        scanner_id=envelope.scanner_id,
        scanner_version=envelope.scanner_version,
        binding_digest=envelope.binding_digest,
        projection_id=envelope.projection_id,
        context_digest=envelope.context_digest,
        projection_digest=envelope.projection_digest,
        findings=normalized,
        finding_count=len(normalized),
    )

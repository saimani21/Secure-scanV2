from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import Any, Final

from securescan.scanners.gitleaks.binding import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
)
from securescan.scanners.gitleaks.parser import (
    GitleaksDetectionKind,
    NormalizedGitleaksFinding,
)

GITLEAKS_IDENTITY_SCHEMA_VERSION: Final = (
    "securescan-gitleaks-finding-identity-v0.4E"
)
GITLEAKS_IDENTITY_SCOPE: Final = "structural_location"
GITLEAKS_V04D_BASELINE_COMMIT: Final = (
    "9b482168e1236729cb47f9e989989aa5cee2d2fa"
)

_IDENTITY_STREAM_VERSION = (
    b"securescan-gitleaks-finding-identity-v0.4E\0"
)
_RULE_ID_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\Z",
    re.ASCII,
)
_URL_SCHEME_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]*:",
    re.ASCII,
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_PATH_LENGTH = 4096
_MAX_LOCATION = 2_147_483_647


class GitleaksIdentityError(RuntimeError):
    """Fixed-message failure for structural Gitleaks finding identity."""

    def __init__(self) -> None:
        super().__init__("Gitleaks finding identity is invalid")


def _has_forbidden_character(value: str) -> bool:
    return any(
        unicodedata.category(character).startswith("C")
        for character in value
    )


def _valid_relative_path(value: object) -> bool:
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
        and all(
            part not in {"", ".", ".."}
            for part in raw_parts
        )
        and path.as_posix() == value
    )


def _valid_positive_location(value: object) -> bool:
    return (
        type(value) is int
        and 1 <= value <= _MAX_LOCATION
    )


def _valid_identity_location(
    detection_kind: object,
    start_line: object,
    end_line: object,
    start_column: object,
    end_column: object,
) -> bool:
    if detection_kind is GitleaksDetectionKind.PATH:
        return (
            start_line is None
            and end_line is None
            and start_column is None
            and end_column is None
        )

    if detection_kind is not GitleaksDetectionKind.CONTENT:
        return False

    if (
        not _valid_positive_location(start_line)
        or not _valid_positive_location(end_line)
        or end_line < start_line
    ):
        return False

    if start_column is None and end_column is None:
        return True

    return (
        _valid_positive_location(start_column)
        and _valid_positive_location(end_column)
        and (end_line > start_line or end_column >= start_column)
    )


def _canonical_json(data: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            data,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (
        TypeError,
        ValueError,
        UnicodeEncodeError,
    ):
        raise GitleaksIdentityError from None


def _identity_digest(
    material: dict[str, Any],
) -> str:
    digest = hashlib.sha256()
    digest.update(_IDENTITY_STREAM_VERSION)
    digest.update(_canonical_json(material))
    return digest.hexdigest()


def _validated_finding(
    finding: object,
) -> NormalizedGitleaksFinding:
    if not isinstance(
        finding,
        NormalizedGitleaksFinding,
    ):
        raise GitleaksIdentityError

    try:
        validated = replace(finding)
    except Exception:
        raise GitleaksIdentityError from None

    if validated != finding:
        raise GitleaksIdentityError

    return finding


def _material_for_finding(
    finding: NormalizedGitleaksFinding,
) -> dict[str, Any]:
    material: dict[str, Any] = {
        "detection_kind": finding.detection_kind.value,
        "file_path": finding.file_path,
        "identity_scope": GITLEAKS_IDENTITY_SCOPE,
        "rule_id": finding.rule_id,
        "scanner_id": finding.scanner_id,
        "scanner_version": finding.scanner_version,
        "schema_version": GITLEAKS_IDENTITY_SCHEMA_VERSION,
    }

    if (
        finding.detection_kind
        is GitleaksDetectionKind.CONTENT
    ):
        material["location"] = {
            "end_column": finding.end_column,
            "end_line": finding.end_line,
            "start_column": finding.start_column,
            "start_line": finding.start_line,
        }
    elif (
        finding.detection_kind
        is not GitleaksDetectionKind.PATH
    ):
        raise GitleaksIdentityError

    return material


@dataclass(frozen=True, slots=True)
class GitleaksFindingIdentity:
    scanner_id: str
    scanner_version: str
    rule_id: str
    file_path: str
    detection_kind: GitleaksDetectionKind
    start_line: int | None
    end_line: int | None
    start_column: int | None
    end_column: int | None
    finding_instance_id: str
    identity_scope: str = GITLEAKS_IDENTITY_SCOPE
    schema_version: str = GITLEAKS_IDENTITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        self._validate_state()

    def _validate_state(self) -> None:
        if (
            self.schema_version
            != GITLEAKS_IDENTITY_SCHEMA_VERSION
            or self.identity_scope
            != GITLEAKS_IDENTITY_SCOPE
            or self.scanner_id
            != GITLEAKS_SCANNER_ID
            or self.scanner_version
            != GITLEAKS_VERSION
            or not isinstance(self.rule_id, str)
            or _RULE_ID_PATTERN.fullmatch(
                self.rule_id
            )
            is None
            or not _valid_relative_path(
                self.file_path
            )
            or not _valid_identity_location(
                self.detection_kind,
                self.start_line,
                self.end_line,
                self.start_column,
                self.end_column,
            )
            or not isinstance(
                self.finding_instance_id,
                str,
            )
            or _SHA256_PATTERN.fullmatch(
                self.finding_instance_id
            )
            is None
            or self.finding_instance_id
            != _identity_digest(
                self.identity_material()
            )
        ):
            raise GitleaksIdentityError

    def identity_material(
        self,
    ) -> dict[str, Any]:
        material: dict[str, Any] = {
            "detection_kind": (
                self.detection_kind.value
            ),
            "file_path": self.file_path,
            "identity_scope": self.identity_scope,
            "rule_id": self.rule_id,
            "scanner_id": self.scanner_id,
            "scanner_version": (
                self.scanner_version
            ),
            "schema_version": self.schema_version,
        }

        if (
            self.detection_kind
            is GitleaksDetectionKind.CONTENT
        ):
            material["location"] = {
                "end_column": self.end_column,
                "end_line": self.end_line,
                "start_column": self.start_column,
                "start_line": self.start_line,
            }

        return material

    def canonical_data(
        self,
    ) -> dict[str, Any]:
        self._validate_state()
        return {
            "finding_instance_id": (
                self.finding_instance_id
            ),
            "identity_material": (
                self.identity_material()
            ),
        }

    def canonical_json(self) -> bytes:
        self._validate_state()
        return (
            _canonical_json(
                self.canonical_data()
            )
            + b"\n"
        )


def build_gitleaks_finding_identity(
    finding: NormalizedGitleaksFinding,
) -> GitleaksFindingIdentity:
    trusted = _validated_finding(finding)
    material = _material_for_finding(
        trusted
    )

    return GitleaksFindingIdentity(
        scanner_id=trusted.scanner_id,
        scanner_version=trusted.scanner_version,
        rule_id=trusted.rule_id,
        file_path=trusted.file_path,
        detection_kind=trusted.detection_kind,
        start_line=trusted.start_line,
        end_line=trusted.end_line,
        start_column=trusted.start_column,
        end_column=trusted.end_column,
        finding_instance_id=_identity_digest(
            material
        ),
    )


def build_gitleaks_finding_identities(
    findings: tuple[
        NormalizedGitleaksFinding,
        ...,
    ],
) -> tuple[
    GitleaksFindingIdentity,
    ...,
]:
    if (
        not isinstance(findings, tuple)
        or any(
            not isinstance(
                finding,
                NormalizedGitleaksFinding,
            )
            for finding in findings
        )
    ):
        raise GitleaksIdentityError

    return tuple(
        build_gitleaks_finding_identity(
            finding
        )
        for finding in findings
    )

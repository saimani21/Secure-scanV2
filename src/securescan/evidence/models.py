from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID

from packageurl import PackageURL

SECURESCAN_EVIDENCE_SCHEMA_VERSION = "securescan-unified-evidence-s4-v1"
SYFT_EVIDENCE_IDENTITY_SCHEMA = "securescan-syft-package-observation-s1"

_FINDING_DOMAIN = b"securescan-unified-finding-s4\0"
_EVIDENCE_DOMAIN = b"securescan-unified-evidence-s4\0"
_COMPONENT_DOMAIN = b"securescan-unified-component-s4\0"
_SUPPRESSION_DOMAIN = b"securescan-unified-suppression-s4\0"
_GAP_DOMAIN = b"securescan-unified-gap-s4\0"
_COVERAGE_DOMAIN = b"securescan-unified-coverage-s4\0"
_OSV_GROUP_DOMAIN = b"securescan-osv-advisory-group-s2\0"
_OSV_FINDING_DOMAIN = b"securescan-dependency-vulnerability-finding-s2\0"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+@/-]{0,511}\Z", re.ASCII)
_PROJECTION_ID = re.compile(r"securescan-source-projection-[0-9a-f]{16,48}\Z", re.ASCII)


class UnifiedEvidenceError(ValueError):
    def __init__(self) -> None:
        super().__init__("SecureScan unified evidence is invalid")


class FindingCategory(StrEnum):
    CODE_SECURITY = "CODE_SECURITY"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"
    DEPENDENCY_VULNERABILITY = "DEPENDENCY_VULNERABILITY"
    CONFIGURATION_SECURITY = "CONFIGURATION_SECURITY"


class EvidenceAuthority(StrEnum):
    SEMGREP = "semgrep-ce"
    GITLEAKS = "gitleaks"
    SYFT = "syft"
    OSV = "osv.dev"
    CHECKOV = "checkov"
    SECURESCAN_SOURCE = "securescan-source"


class EvidenceKind(StrEnum):
    SEMGREP_RULE_MATCH = "SEMGREP_RULE_MATCH"
    GITLEAKS_SECRET_OBSERVATION = "GITLEAKS_SECRET_OBSERVATION"
    SYFT_PACKAGE_OBSERVATION = "SYFT_PACKAGE_OBSERVATION"
    OSV_ADVISORY_GROUP = "OSV_ADVISORY_GROUP"
    OSV_ADVISORY_REVISION = "OSV_ADVISORY_REVISION"
    CHECKOV_POLICY_OBSERVATION = "CHECKOV_POLICY_OBSERVATION"


class ComponentKind(StrEnum):
    REPOSITORY = "REPOSITORY"
    PACKAGE = "PACKAGE"


class SeverityScheme(StrEnum):
    SEMGREP_NORMALIZED = "SEMGREP_NORMALIZED"
    CHECKOV = "CHECKOV"


class CoverageState(StrEnum):
    COMPLETE = "COMPLETE"
    COMPLETE_WITH_FINDINGS = "COMPLETE_WITH_FINDINGS"
    COMPLETE_WITH_SUPPRESSIONS = "COMPLETE_WITH_SUPPRESSIONS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


def _valid_text(value: object, maximum: int = 16_384) -> bool:
    if not isinstance(value, str) or value != value.strip():
        return False
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return False
    return 1 <= size <= maximum and not any(
        unicodedata.category(char).startswith("C") for char in value
    )


def _valid_identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _valid_sha(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _valid_path(value: object, *, allow_root: bool = False) -> bool:
    if value == "" and allow_root:
        return True
    if not _valid_text(value, 16_384) or not isinstance(value, str) or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def _path_within_root(path: str, root: str) -> bool:
    return root == "" or path == root or path.startswith(f"{root}/")


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError):
        raise UnifiedEvidenceError from None


def _digest(domain: bytes, value: object) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(_canonical_json(value))
    return digest.hexdigest()


def _osv_native_digest(domain: bytes, value: object) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(_canonical_json(value) + b"\n")
    return digest.hexdigest()


def build_finding_id(
    authority: EvidenceAuthority, native_identity_schema: str, native_identity: str
) -> str:
    if (
        not isinstance(authority, EvidenceAuthority)
        or not _valid_identifier(native_identity_schema)
        or not _valid_identifier(native_identity)
    ):
        raise UnifiedEvidenceError
    return _digest(
        _FINDING_DOMAIN,
        [authority.value, native_identity_schema, native_identity],
    )


def build_evidence_id(
    authority: EvidenceAuthority, native_identity_schema: str, native_identity: str
) -> str:
    if (
        not isinstance(authority, EvidenceAuthority)
        or not _valid_identifier(native_identity_schema)
        or not _valid_identifier(native_identity)
    ):
        raise UnifiedEvidenceError
    return _digest(
        _EVIDENCE_DOMAIN,
        [authority.value, native_identity_schema, native_identity],
    )


def build_component_ref(kind: ComponentKind, native_identity: str) -> str:
    if not isinstance(kind, ComponentKind) or not _valid_identifier(native_identity):
        raise UnifiedEvidenceError
    return _digest(_COMPONENT_DOMAIN, [kind.value, native_identity])


@dataclass(frozen=True, slots=True)
class SourceSpanLocation:
    path: str
    start_line: int
    end_line: int
    start_column: int | None = None
    end_column: int | None = None

    def __post_init__(self) -> None:
        values = (self.start_line, self.end_line)
        if (
            not _valid_path(self.path)
            or any(type(value) is not int or value < 1 for value in values)
            or self.end_line < self.start_line
            or (self.start_column is None) != (self.end_column is None)
            or (
                self.start_column is not None
                and (
                    type(self.start_column) is not int
                    or type(self.end_column) is not int
                    or self.start_column < 1
                    or self.end_column < 1
                    or (self.start_line == self.end_line and self.end_column < self.start_column)
                )
            )
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "end_column": self.end_column,
            "end_line": self.end_line,
            "kind": "SOURCE_SPAN",
            "path": self.path,
            "start_column": self.start_column,
            "start_line": self.start_line,
        }


@dataclass(frozen=True, slots=True)
class RepositoryPathLocation:
    path: str

    def __post_init__(self) -> None:
        if not _valid_path(self.path):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, str]:
        return {"kind": "REPOSITORY_PATH", "path": self.path}


@dataclass(frozen=True, slots=True)
class RepositoryScopeLocation:
    def canonical_data(self) -> dict[str, str]:
        return {"kind": "REPOSITORY_SCOPE"}


type SecureScanLocation = SourceSpanLocation | RepositoryPathLocation | RepositoryScopeLocation


def _location_key(location: SecureScanLocation) -> bytes:
    if not isinstance(
        location, (SourceSpanLocation, RepositoryPathLocation, RepositoryScopeLocation)
    ):
        raise UnifiedEvidenceError
    return _canonical_json(location.canonical_data())


def _validate_locations(locations: object) -> bool:
    if not isinstance(locations, tuple):
        return False
    try:
        keys = tuple(_location_key(item) for item in locations)
    except UnifiedEvidenceError:
        return False
    return keys == tuple(sorted(keys)) and len(keys) == len(set(keys))


@dataclass(frozen=True, slots=True)
class SourceCodeSubject:
    rule_id: str

    def __post_init__(self) -> None:
        if not _valid_text(self.rule_id, 512):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, str]:
        return {"kind": "SOURCE_CODE", "rule_id": self.rule_id}


@dataclass(frozen=True, slots=True)
class SecretExposureSubject:
    rule_id: str
    detection_kind: str

    def __post_init__(self) -> None:
        if not _valid_text(self.rule_id, 512) or self.detection_kind not in {
            "CONTENT",
            "PATH",
        }:
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, str]:
        return {
            "detection_kind": self.detection_kind,
            "kind": "SECRET_EXPOSURE",
            "rule_id": self.rule_id,
        }


@dataclass(frozen=True, slots=True)
class PackageSubject:
    component_ref: str

    def __post_init__(self) -> None:
        if not _valid_sha(self.component_ref):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, str]:
        return {"component_ref": self.component_ref, "kind": "PACKAGE"}


@dataclass(frozen=True, slots=True)
class ConfigurationResourceSubject:
    framework: str
    resource: str

    def __post_init__(self) -> None:
        if not _valid_text(self.framework, 128) or not _valid_text(self.resource, 2_048):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, str]:
        return {
            "framework": self.framework,
            "kind": "CONFIGURATION_RESOURCE",
            "resource": self.resource,
        }


@dataclass(frozen=True, slots=True)
class RepositorySubject:
    repository_digest: str

    def __post_init__(self) -> None:
        if not _valid_sha(self.repository_digest):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, str]:
        return {"kind": "REPOSITORY", "repository_digest": self.repository_digest}


type SecureScanSubject = (
    SourceCodeSubject
    | SecretExposureSubject
    | PackageSubject
    | ConfigurationResourceSubject
    | RepositorySubject
)


@dataclass(frozen=True, slots=True)
class SeverityProjection:
    value: str
    scheme: SeverityScheme
    authority: EvidenceAuthority

    def __post_init__(self) -> None:
        valid = (
            self.scheme is SeverityScheme.SEMGREP_NORMALIZED
            and self.authority is EvidenceAuthority.SEMGREP
            and self.value in {"HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
        ) or (
            self.scheme is SeverityScheme.CHECKOV
            and self.authority is EvidenceAuthority.CHECKOV
            and self.value in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
        )
        if not valid:
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, str]:
        return {
            "authority": self.authority.value,
            "scheme": self.scheme.value,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class RepositoryComponentPayload:
    component_id: str
    display_name: str
    root_path: str
    manifest_paths: tuple[str, ...]
    lockfile_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        paths = (*self.manifest_paths, *self.lockfile_paths)
        if (
            not _valid_identifier(self.component_id)
            or not _valid_text(self.display_name, 256)
            or not _valid_path(self.root_path, allow_root=True)
            or any(not _valid_path(path) for path in paths)
            or self.manifest_paths != tuple(sorted(set(self.manifest_paths)))
            or self.lockfile_paths != tuple(sorted(set(self.lockfile_paths)))
            or set(self.manifest_paths) & set(self.lockfile_paths)
            or any(not _path_within_root(path, self.root_path) for path in paths)
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "display_name": self.display_name,
            "kind": "REPOSITORY_COMPONENT",
            "lockfile_paths": list(self.lockfile_paths),
            "manifest_paths": list(self.manifest_paths),
            "root_path": self.root_path,
        }


@dataclass(frozen=True, slots=True)
class PackageComponentPayload:
    package_key: str
    package_name: str
    package_version: str | None
    package_type: str
    purl: str | None

    def __post_init__(self) -> None:
        try:
            canonical_purl = (
                None if self.purl is None else PackageURL.from_string(self.purl).to_string()
            )
        except (TypeError, ValueError):
            raise UnifiedEvidenceError from None
        if (
            not _valid_sha(self.package_key)
            or not _valid_text(self.package_name)
            or not _valid_text(self.package_type)
            or (self.package_version is not None and not _valid_text(self.package_version))
            or (self.purl is not None and not _valid_text(self.purl))
            or canonical_purl != self.purl
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "kind": "PACKAGE_COMPONENT",
            "package_key": self.package_key,
            "package_name": self.package_name,
            "package_type": self.package_type,
            "package_version": self.package_version,
            "purl": self.purl,
        }


type ComponentPayload = RepositoryComponentPayload | PackageComponentPayload


@dataclass(frozen=True, slots=True)
class SecureScanComponent:
    component_ref: str
    component_kind: ComponentKind
    native_component_identity: str
    payload: ComponentPayload

    def __post_init__(self) -> None:
        expected_type = (
            RepositoryComponentPayload
            if self.component_kind is ComponentKind.REPOSITORY
            else PackageComponentPayload
        )
        if (
            not isinstance(self.payload, expected_type)
            or not _valid_identifier(self.native_component_identity)
            or self.component_ref
            != build_component_ref(self.component_kind, self.native_component_identity)
            or (
                isinstance(self.payload, RepositoryComponentPayload)
                and self.native_component_identity != self.payload.component_id
            )
            or (
                isinstance(self.payload, PackageComponentPayload)
                and self.native_component_identity != self.payload.package_key
            )
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "component_kind": self.component_kind.value,
            "component_ref": self.component_ref,
            "native_component_identity": self.native_component_identity,
            "payload": self.payload.canonical_data(),
        }


@dataclass(frozen=True, slots=True)
class SemgrepEvidencePayload:
    fingerprint: str
    rule_id: str
    message: str
    cwe_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not _valid_sha(self.fingerprint)
            or not _valid_text(self.rule_id, 512)
            or not _valid_text(self.message, 256)
            or self.cwe_ids != tuple(sorted(set(self.cwe_ids)))
            or any(not _valid_identifier(item) for item in self.cwe_ids)
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "cwe_ids": list(self.cwe_ids),
            "fingerprint": self.fingerprint,
            "kind": "SEMGREP_RULE_MATCH",
            "message": self.message,
            "rule_id": self.rule_id,
        }


@dataclass(frozen=True, slots=True)
class GitleaksEvidencePayload:
    finding_instance_id: str
    rule_id: str
    detection_kind: str
    native_occurrence_count: int = 1

    def __post_init__(self) -> None:
        if (
            not _valid_sha(self.finding_instance_id)
            or not _valid_text(self.rule_id, 512)
            or self.detection_kind not in {"CONTENT", "PATH"}
            or type(self.native_occurrence_count) is not int
            or self.native_occurrence_count < 1
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, str]:
        return {
            "detection_kind": self.detection_kind,
            "finding_instance_id": self.finding_instance_id,
            "kind": "GITLEAKS_SECRET_OBSERVATION",
            "native_occurrence_count": self.native_occurrence_count,
            "rule_id": self.rule_id,
        }


@dataclass(frozen=True, slots=True)
class SyftPackageEvidencePayload:
    package_observation_id: str
    package_key: str
    found_by: str
    language: str | None

    def __post_init__(self) -> None:
        if (
            not _valid_sha(self.package_observation_id)
            or not _valid_sha(self.package_key)
            or not _valid_text(self.found_by)
            or (self.language is not None and not _valid_text(self.language))
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, str]:
        return {
            "found_by": self.found_by,
            "kind": "SYFT_PACKAGE_OBSERVATION",
            "language": self.language,
            "package_key": self.package_key,
            "package_observation_id": self.package_observation_id,
        }


@dataclass(frozen=True, slots=True)
class OsvCvssProjection:
    cvss_type: str
    vector: str
    source: str | None
    base_score: float
    scope: str

    def __post_init__(self) -> None:
        if (
            self.cvss_type not in {"CVSS_V2", "CVSS_V3", "CVSS_V4"}
            or not _valid_text(self.vector)
            or (self.source is not None and not _valid_text(self.source))
            or not isinstance(self.base_score, float)
            or not 0.0 <= self.base_score <= 10.0
            or self.scope not in {"ADVISORY", "MATCHED_PACKAGE"}
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "base_score": self.base_score,
            "cvss_type": self.cvss_type,
            "scope": self.scope,
            "source": self.source,
            "vector": self.vector,
        }


@dataclass(frozen=True, slots=True)
class OsvAdvisoryGroupEvidencePayload:
    finding_id: str
    advisory_group_key: str
    package_observation_ids: tuple[str, ...]
    canonical_advisory_id: str
    osv_record_ids: tuple[str, ...]
    aliases: tuple[str, ...]
    cve_aliases: tuple[str, ...]
    ghsa_aliases: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    cvss: tuple[OsvCvssProjection, ...]
    affected_match: str

    def __post_init__(self) -> None:
        tuples = (
            self.osv_record_ids,
            self.aliases,
            self.cve_aliases,
            self.ghsa_aliases,
            self.fixed_versions,
        )
        if (
            not _valid_sha(self.finding_id)
            or not _valid_sha(self.advisory_group_key)
            or not self.package_observation_ids
            or self.package_observation_ids != tuple(sorted(set(self.package_observation_ids)))
            or any(not _valid_sha(item) for item in self.package_observation_ids)
            or not _valid_identifier(self.canonical_advisory_id)
            or any(value != tuple(sorted(set(value))) for value in tuples)
            or not self.osv_record_ids
            or any(
                not _valid_identifier(item)
                for value in (
                    self.osv_record_ids,
                    self.aliases,
                    self.cve_aliases,
                    self.ghsa_aliases,
                )
                for item in value
            )
            or any(not _valid_text(item) for item in self.fixed_versions)
            or self.cvss
            != tuple(
                sorted(
                    set(self.cvss),
                    key=lambda item: _canonical_json(item.canonical_data()),
                )
            )
            or self.affected_match != "MATCHED_BY_OSV_QUERY"
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "affected_match": self.affected_match,
            "advisory_group_key": self.advisory_group_key,
            "aliases": list(self.aliases),
            "canonical_advisory_id": self.canonical_advisory_id,
            "cve_aliases": list(self.cve_aliases),
            "cvss": [item.canonical_data() for item in self.cvss],
            "finding_id": self.finding_id,
            "fixed_versions": list(self.fixed_versions),
            "ghsa_aliases": list(self.ghsa_aliases),
            "kind": "OSV_ADVISORY_GROUP",
            "osv_record_ids": list(self.osv_record_ids),
            "package_observation_ids": list(self.package_observation_ids),
        }


@dataclass(frozen=True, slots=True)
class OsvAdvisoryRevisionEvidencePayload:
    osv_record_id: str
    modified: str
    published: str | None
    aliases: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not _valid_identifier(self.osv_record_id)
            or not _valid_text(self.modified)
            or (self.published is not None and not _valid_text(self.published))
            or self.aliases != tuple(sorted(set(self.aliases)))
            or any(not _valid_identifier(item) for item in self.aliases)
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "aliases": list(self.aliases),
            "kind": "OSV_ADVISORY_REVISION",
            "modified": self.modified,
            "osv_record_id": self.osv_record_id,
            "published": self.published,
        }


@dataclass(frozen=True, slots=True)
class CheckovEvidencePayload:
    observation_id: str
    framework: str
    check_id: str
    check_name: str
    resource: str
    result: str

    def __post_init__(self) -> None:
        if (
            not _valid_sha(self.observation_id)
            or any(
                not _valid_text(value, maximum)
                for value, maximum in (
                    (self.framework, 128),
                    (self.check_id, 128),
                    (self.check_name, 2_048),
                    (self.resource, 2_048),
                )
            )
            or self.result != "FAILED"
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, str]:
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "framework": self.framework,
            "kind": "CHECKOV_POLICY_OBSERVATION",
            "observation_id": self.observation_id,
            "resource": self.resource,
            "result": self.result,
        }


type EvidencePayload = (
    SemgrepEvidencePayload
    | GitleaksEvidencePayload
    | SyftPackageEvidencePayload
    | OsvAdvisoryGroupEvidencePayload
    | OsvAdvisoryRevisionEvidencePayload
    | CheckovEvidencePayload
)


@dataclass(frozen=True, slots=True)
class SemgrepSanitizedArtifactReference:
    artifact_id: str
    tool_execution_id: str
    sha256: str
    size_bytes: int
    media_type: str
    sanitized: bool
    artifact_kind: str

    def __post_init__(self) -> None:
        try:
            valid_artifact_id = str(UUID(self.artifact_id)) == self.artifact_id
            valid_execution_id = str(UUID(self.tool_execution_id)) == self.tool_execution_id
        except (AttributeError, ValueError):
            valid_artifact_id = False
            valid_execution_id = False
        if (
            not valid_artifact_id
            or not valid_execution_id
            or not _valid_sha(self.sha256)
            or type(self.size_bytes) is not int
            or self.size_bytes < 1
            or self.media_type != "application/json"
            or self.sanitized is not True
            or self.artifact_kind != "sanitized_native_report"
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return _dataclass_public_data(self)


@dataclass(frozen=True, slots=True)
class SemgrepProvenance:
    scanner_id: str
    scanner_version: str
    source_analyzer_id: str
    binding_digest: str
    ruleset_id: str
    ruleset_version: str
    ruleset_digest: str
    projection_id: str
    context_digest: str
    projection_digest: str
    sanitized_artifact: SemgrepSanitizedArtifactReference

    def __post_init__(self) -> None:
        if (
            self.scanner_id != EvidenceAuthority.SEMGREP.value
            or any(
                not _valid_text(item)
                for item in (
                    self.scanner_version,
                    self.source_analyzer_id,
                    self.ruleset_id,
                    self.ruleset_version,
                )
            )
            or _PROJECTION_ID.fullmatch(self.projection_id) is None
            or any(
                not _valid_sha(item)
                for item in (
                    self.binding_digest,
                    self.ruleset_digest,
                    self.context_digest,
                    self.projection_digest,
                )
            )
            or not isinstance(self.sanitized_artifact, SemgrepSanitizedArtifactReference)
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "binding_digest": self.binding_digest,
            "context_digest": self.context_digest,
            "kind": "SEMGREP",
            "projection_digest": self.projection_digest,
            "projection_id": self.projection_id,
            "ruleset_digest": self.ruleset_digest,
            "ruleset_id": self.ruleset_id,
            "ruleset_version": self.ruleset_version,
            "sanitized_artifact": self.sanitized_artifact.canonical_data(),
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
            "source_analyzer_id": self.source_analyzer_id,
        }


@dataclass(frozen=True, slots=True)
class LocalScannerProvenance:
    scanner_id: str
    scanner_version: str
    binding_digest: str
    projection_id: str
    context_digest: str
    projection_digest: str

    def __post_init__(self) -> None:
        if (
            self.scanner_id
            not in {
                EvidenceAuthority.GITLEAKS.value,
                EvidenceAuthority.SYFT.value,
                EvidenceAuthority.CHECKOV.value,
            }
            or not _valid_text(self.scanner_version)
            or _PROJECTION_ID.fullmatch(self.projection_id) is None
            or any(
                not _valid_sha(item)
                for item in (self.binding_digest, self.context_digest, self.projection_digest)
            )
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {"kind": "LOCAL_SCANNER", **_dataclass_public_data(self)}


@dataclass(frozen=True, slots=True)
class OsvProvenance:
    source_service: str
    api_version: str
    schema_version: str
    projection_id: str
    snapshot_digest: str
    syft_binding_digest: str

    def __post_init__(self) -> None:
        if (
            self.source_service != EvidenceAuthority.OSV.value
            or any(not _valid_text(item) for item in (self.api_version, self.schema_version))
            or _PROJECTION_ID.fullmatch(self.projection_id) is None
            or not _valid_sha(self.snapshot_digest)
            or not _valid_sha(self.syft_binding_digest)
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {"kind": "OSV", **_dataclass_public_data(self)}


type EvidenceProvenance = SemgrepProvenance | LocalScannerProvenance | OsvProvenance


def _dataclass_public_data(value: object) -> dict[str, Any]:
    return {
        field: getattr(value, field)
        for field in value.__dataclass_fields__  # type: ignore[attr-defined]
    }


_EVIDENCE_TYPES: dict[tuple[EvidenceAuthority, EvidenceKind], tuple[type[Any], type[Any]]] = {
    (EvidenceAuthority.SEMGREP, EvidenceKind.SEMGREP_RULE_MATCH): (
        SemgrepEvidencePayload,
        SemgrepProvenance,
    ),
    (EvidenceAuthority.GITLEAKS, EvidenceKind.GITLEAKS_SECRET_OBSERVATION): (
        GitleaksEvidencePayload,
        LocalScannerProvenance,
    ),
    (EvidenceAuthority.SYFT, EvidenceKind.SYFT_PACKAGE_OBSERVATION): (
        SyftPackageEvidencePayload,
        LocalScannerProvenance,
    ),
    (EvidenceAuthority.OSV, EvidenceKind.OSV_ADVISORY_GROUP): (
        OsvAdvisoryGroupEvidencePayload,
        OsvProvenance,
    ),
    (EvidenceAuthority.OSV, EvidenceKind.OSV_ADVISORY_REVISION): (
        OsvAdvisoryRevisionEvidencePayload,
        OsvProvenance,
    ),
    (EvidenceAuthority.CHECKOV, EvidenceKind.CHECKOV_POLICY_OBSERVATION): (
        CheckovEvidencePayload,
        LocalScannerProvenance,
    ),
}


@dataclass(frozen=True, slots=True)
class SecureScanEvidence:
    evidence_id: str
    authority: EvidenceAuthority
    evidence_kind: EvidenceKind
    native_identity_schema: str
    native_identity: str
    payload: EvidencePayload
    provenance: EvidenceProvenance
    component_refs: tuple[str, ...] = ()
    locations: tuple[SecureScanLocation, ...] = ()

    def __post_init__(self) -> None:
        expected = _EVIDENCE_TYPES.get((self.authority, self.evidence_kind))
        payload_identity = (
            self.payload.fingerprint
            if isinstance(self.payload, SemgrepEvidencePayload)
            else self.payload.finding_instance_id
            if isinstance(self.payload, GitleaksEvidencePayload)
            else self.payload.package_observation_id
            if isinstance(self.payload, SyftPackageEvidencePayload)
            else self.payload.advisory_group_key
            if isinstance(self.payload, OsvAdvisoryGroupEvidencePayload)
            else f"{self.payload.osv_record_id}@{self.payload.modified}"
            if isinstance(self.payload, OsvAdvisoryRevisionEvidencePayload)
            else self.payload.observation_id
            if isinstance(self.payload, CheckovEvidencePayload)
            else None
        )
        if (
            expected is None
            or not isinstance(self.payload, expected[0])
            or not isinstance(self.provenance, expected[1])
            or (
                isinstance(self.provenance, LocalScannerProvenance)
                and self.provenance.scanner_id != self.authority.value
            )
            or not _valid_identifier(self.native_identity_schema)
            or not _valid_identifier(self.native_identity)
            or self.evidence_id
            != build_evidence_id(self.authority, self.native_identity_schema, self.native_identity)
            or payload_identity != self.native_identity
            or self.component_refs != tuple(sorted(set(self.component_refs)))
            or any(not _valid_sha(item) for item in self.component_refs)
            or not _validate_locations(self.locations)
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "authority": self.authority.value,
            "component_refs": list(self.component_refs),
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.value,
            "locations": [item.canonical_data() for item in self.locations],
            "native_identity": self.native_identity,
            "native_identity_schema": self.native_identity_schema,
            "payload": self.payload.canonical_data(),
            "provenance": self.provenance.canonical_data(),
        }


_FINDING_TYPES: dict[EvidenceAuthority, tuple[FindingCategory, type[Any]]] = {
    EvidenceAuthority.SEMGREP: (FindingCategory.CODE_SECURITY, SourceCodeSubject),
    EvidenceAuthority.GITLEAKS: (
        FindingCategory.SECRET_EXPOSURE,
        SecretExposureSubject,
    ),
    EvidenceAuthority.OSV: (FindingCategory.DEPENDENCY_VULNERABILITY, PackageSubject),
    EvidenceAuthority.CHECKOV: (
        FindingCategory.CONFIGURATION_SECURITY,
        ConfigurationResourceSubject,
    ),
}


@dataclass(frozen=True, slots=True)
class SecureScanFinding:
    finding_id: str
    category: FindingCategory
    authority: EvidenceAuthority
    native_identity_schema: str
    native_finding_identity: str
    subject: SecureScanSubject
    locations: tuple[SecureScanLocation, ...]
    primary_evidence_refs: tuple[str, ...]
    supporting_evidence_refs: tuple[str, ...] = ()
    severity: SeverityProjection | None = None

    def __post_init__(self) -> None:
        expected = _FINDING_TYPES.get(self.authority)
        if (
            expected is None
            or self.category is not expected[0]
            or not isinstance(self.subject, expected[1])
            or not _valid_identifier(self.native_identity_schema)
            or not _valid_identifier(self.native_finding_identity)
            or self.finding_id
            != build_finding_id(
                self.authority,
                self.native_identity_schema,
                self.native_finding_identity,
            )
            or not _validate_locations(self.locations)
            or not self.primary_evidence_refs
            or self.primary_evidence_refs != tuple(sorted(set(self.primary_evidence_refs)))
            or self.supporting_evidence_refs != tuple(sorted(set(self.supporting_evidence_refs)))
            or set(self.primary_evidence_refs) & set(self.supporting_evidence_refs)
            or any(
                not _valid_sha(item)
                for item in (*self.primary_evidence_refs, *self.supporting_evidence_refs)
            )
            or (self.severity is not None and self.severity.authority is not self.authority)
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "authority": self.authority.value,
            "category": self.category.value,
            "finding_id": self.finding_id,
            "locations": [item.canonical_data() for item in self.locations],
            "native_finding_identity": self.native_finding_identity,
            "native_identity_schema": self.native_identity_schema,
            "primary_evidence_refs": list(self.primary_evidence_refs),
            "severity": None if self.severity is None else self.severity.canonical_data(),
            "subject": self.subject.canonical_data(),
            "supporting_evidence_refs": list(self.supporting_evidence_refs),
        }


@dataclass(frozen=True, slots=True)
class CheckovSuppressionPayload:
    framework: str
    check_id: str
    resource: str
    reason: str | None

    def __post_init__(self) -> None:
        if any(
            not _valid_text(value, maximum)
            for value, maximum in (
                (self.framework, 128),
                (self.check_id, 128),
                (self.resource, 2_048),
            )
        ) or (self.reason is not None and not _valid_text(self.reason, 512)):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "framework": self.framework,
            "reason": self.reason,
            "resource": self.resource,
        }


@dataclass(frozen=True, slots=True)
class SecureScanSuppression:
    suppression_id: str
    authority: EvidenceAuthority
    native_identity_schema: str
    native_identity: str
    subject: ConfigurationResourceSubject
    locations: tuple[SecureScanLocation, ...]
    payload: CheckovSuppressionPayload
    provenance: LocalScannerProvenance

    def __post_init__(self) -> None:
        expected = _digest(
            _SUPPRESSION_DOMAIN,
            [self.authority.value, self.native_identity_schema, self.native_identity],
        )
        if (
            self.authority is not EvidenceAuthority.CHECKOV
            or self.provenance.scanner_id != self.authority.value
            or not _valid_identifier(self.native_identity_schema)
            or not _valid_identifier(self.native_identity)
            or self.suppression_id != expected
            or self.subject.framework != self.payload.framework
            or self.subject.resource != self.payload.resource
            or not _validate_locations(self.locations)
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "authority": self.authority.value,
            "locations": [item.canonical_data() for item in self.locations],
            "native_identity": self.native_identity,
            "native_identity_schema": self.native_identity_schema,
            "payload": self.payload.canonical_data(),
            "provenance": self.provenance.canonical_data(),
            "subject": self.subject.canonical_data(),
            "suppression_id": self.suppression_id,
        }


class GapScopeKind(StrEnum):
    REPOSITORY = "REPOSITORY"
    CAPABILITY = "CAPABILITY"
    FRAMEWORK = "FRAMEWORK"
    PACKAGE = "PACKAGE"
    PATH = "PATH"


@dataclass(frozen=True, slots=True)
class SecureScanGapScope:
    kind: GapScopeKind
    value: str
    component_ref: str | None = None
    framework: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.kind, GapScopeKind)
            or not _valid_text(self.value)
            or (self.kind is GapScopeKind.PATH and not _valid_path(self.value))
            or (self.component_ref is not None and not _valid_sha(self.component_ref))
            or (self.kind is GapScopeKind.PACKAGE and self.component_ref is None)
            or (self.framework is not None and not _valid_text(self.framework, 128))
            or (self.framework is not None and self.kind is not GapScopeKind.PATH)
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "component_ref": self.component_ref,
            "framework": self.framework,
            "kind": self.kind.value,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class SecureScanGap:
    gap_id: str
    authority: EvidenceAuthority
    native_identity_schema: str
    native_identity: str
    code: str
    scope: SecureScanGapScope
    message: str | None = None

    def __post_init__(self) -> None:
        if (
            not _valid_identifier(self.native_identity_schema)
            or not _valid_identifier(self.native_identity)
            or not _valid_identifier(self.code)
            or (self.message is not None and not _valid_text(self.message, 512))
            or self.gap_id
            != gap_id(
                self.authority,
                self.native_identity_schema,
                self.native_identity,
            )
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "authority": self.authority.value,
            "code": self.code,
            "gap_id": self.gap_id,
            "message": self.message,
            "native_identity": self.native_identity,
            "native_identity_schema": self.native_identity_schema,
            "scope": self.scope.canonical_data(),
        }


@dataclass(frozen=True, slots=True)
class SecureScanCoverageOutcome:
    coverage_id: str
    authority: EvidenceAuthority
    capability: str
    state: CoverageState
    framework: str | None
    component_ref: str | None
    selected_scope: tuple[SecureScanLocation, ...]
    finding_count: int
    suppression_count: int
    gap_count: int
    reason_code: str | None = None

    def __post_init__(self) -> None:
        material = [
            self.authority.value,
            self.capability,
            self.framework,
            self.component_ref,
            [item.canonical_data() for item in self.selected_scope],
        ]
        if (
            not _valid_text(self.capability, 128)
            or (self.framework is not None and not _valid_text(self.framework, 128))
            or (self.component_ref is not None and not _valid_sha(self.component_ref))
            or not self.selected_scope
            or not _validate_locations(self.selected_scope)
            or any(
                type(value) is not int or value < 0
                for value in (self.finding_count, self.suppression_count, self.gap_count)
            )
            or (self.reason_code is not None and not _valid_identifier(self.reason_code))
            or self.coverage_id != _digest(_COVERAGE_DOMAIN, material)
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "authority": self.authority.value,
            "capability": self.capability,
            "component_ref": self.component_ref,
            "coverage_id": self.coverage_id,
            "finding_count": self.finding_count,
            "framework": self.framework,
            "gap_count": self.gap_count,
            "reason_code": self.reason_code,
            "selected_scope": [item.canonical_data() for item in self.selected_scope],
            "state": self.state.value,
            "suppression_count": self.suppression_count,
        }


@dataclass(frozen=True, slots=True)
class SecureScanReportScope:
    source_run_id: str
    repository_digest: str
    profile_digest: str | None = None
    plan_digest: str | None = None

    def __post_init__(self) -> None:
        try:
            valid_uuid = str(UUID(self.source_run_id)) == self.source_run_id
        except (AttributeError, ValueError):
            valid_uuid = False
        if (
            not valid_uuid
            or not _valid_sha(self.repository_digest)
            or (self.profile_digest is None) != (self.plan_digest is None)
            or (
                self.profile_digest is not None
                and (not _valid_sha(self.profile_digest) or not _valid_sha(self.plan_digest))
            )
        ):
            raise UnifiedEvidenceError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "plan_digest": self.plan_digest,
            "profile_digest": self.profile_digest,
            "repository_digest": self.repository_digest,
            "source_run_id": self.source_run_id,
        }


@dataclass(frozen=True, slots=True)
class SecureScanEvidenceFragment:
    scope: SecureScanReportScope | None = None
    components: tuple[SecureScanComponent, ...] = ()
    evidence: tuple[SecureScanEvidence, ...] = ()
    findings: tuple[SecureScanFinding, ...] = ()
    suppressions: tuple[SecureScanSuppression, ...] = ()
    gaps: tuple[SecureScanGap, ...] = ()
    coverage_outcomes: tuple[SecureScanCoverageOutcome, ...] = ()


@dataclass(frozen=True, slots=True)
class SecureScanEvidenceReport:
    scope: SecureScanReportScope
    components: tuple[SecureScanComponent, ...]
    evidence: tuple[SecureScanEvidence, ...]
    findings: tuple[SecureScanFinding, ...]
    suppressions: tuple[SecureScanSuppression, ...]
    gaps: tuple[SecureScanGap, ...]
    coverage_outcomes: tuple[SecureScanCoverageOutcome, ...]
    schema_version: str = SECURESCAN_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        collections = (
            (self.components, SecureScanComponent, "component_ref"),
            (self.evidence, SecureScanEvidence, "evidence_id"),
            (self.findings, SecureScanFinding, "finding_id"),
            (self.suppressions, SecureScanSuppression, "suppression_id"),
            (self.gaps, SecureScanGap, "gap_id"),
            (self.coverage_outcomes, SecureScanCoverageOutcome, "coverage_id"),
        )
        if self.schema_version != SECURESCAN_EVIDENCE_SCHEMA_VERSION or not isinstance(
            self.scope, SecureScanReportScope
        ):
            raise UnifiedEvidenceError
        for values, expected_type, identity_field in collections:
            if (
                not isinstance(values, tuple)
                or any(not isinstance(item, expected_type) for item in values)
                or values != tuple(sorted(values, key=lambda item: getattr(item, identity_field)))
                or len({getattr(item, identity_field) for item in values}) != len(values)
            ):
                raise UnifiedEvidenceError
        evidence = {item.evidence_id: item for item in self.evidence}
        components = {item.component_ref: item for item in self.components}
        for item in self.evidence:
            if any(reference not in components for reference in item.component_refs):
                raise UnifiedEvidenceError
            if item.authority in {EvidenceAuthority.SYFT, EvidenceAuthority.OSV} and (
                not item.component_refs
                or any(
                    components[reference].component_kind is not ComponentKind.PACKAGE
                    for reference in item.component_refs
                )
            ):
                raise UnifiedEvidenceError
            if item.authority not in {EvidenceAuthority.SYFT, EvidenceAuthority.OSV} and (
                item.component_refs
            ):
                raise UnifiedEvidenceError
        for finding in self.findings:
            refs = (*finding.primary_evidence_refs, *finding.supporting_evidence_refs)
            if any(reference not in evidence for reference in refs):
                raise UnifiedEvidenceError
            if any(
                evidence[reference].authority is not finding.authority
                for reference in finding.primary_evidence_refs
            ):
                raise UnifiedEvidenceError
            primary = tuple(evidence[reference] for reference in finding.primary_evidence_refs)
            if finding.authority is EvidenceAuthority.SEMGREP and (
                len(primary) != 1
                or not isinstance(primary[0].payload, SemgrepEvidencePayload)
                or primary[0].native_identity != finding.native_finding_identity
                or primary[0].payload.rule_id != finding.subject.rule_id
            ):
                raise UnifiedEvidenceError
            if finding.authority is EvidenceAuthority.GITLEAKS and (
                len(primary) != 1
                or not isinstance(primary[0].payload, GitleaksEvidencePayload)
                or primary[0].native_identity != finding.native_finding_identity
                or primary[0].payload.rule_id != finding.subject.rule_id
                or primary[0].payload.detection_kind != finding.subject.detection_kind
            ):
                raise UnifiedEvidenceError
            if finding.authority is EvidenceAuthority.CHECKOV and (
                len(primary) != 1
                or not isinstance(primary[0].payload, CheckovEvidencePayload)
                or primary[0].native_identity != finding.native_finding_identity
                or primary[0].payload.framework != finding.subject.framework
                or primary[0].payload.resource != finding.subject.resource
            ):
                raise UnifiedEvidenceError
            if isinstance(finding.subject, PackageSubject):
                component = components.get(finding.subject.component_ref)
                if component is None or component.component_kind is not ComponentKind.PACKAGE:
                    raise UnifiedEvidenceError
                if any(
                    finding.subject.component_ref not in evidence[reference].component_refs
                    for reference in refs
                ):
                    raise UnifiedEvidenceError
            if finding.authority is EvidenceAuthority.OSV:
                self._validate_osv_syft_relationship(
                    finding,
                    primary,
                    tuple(evidence[reference] for reference in finding.supporting_evidence_refs),
                    components,
                )
            if finding.authority is not EvidenceAuthority.OSV and (
                finding.supporting_evidence_refs
            ):
                raise UnifiedEvidenceError
        for gap in self.gaps:
            ref = gap.scope.component_ref
            if ref is not None and ref not in components:
                raise UnifiedEvidenceError
        for outcome in self.coverage_outcomes:
            if outcome.component_ref is None:
                continue
            component = components.get(outcome.component_ref)
            if (
                component is None
                or component.component_kind is not ComponentKind.REPOSITORY
                or not isinstance(component.payload, RepositoryComponentPayload)
                or any(
                    isinstance(location, RepositoryScopeLocation)
                    or not _path_within_root(location.path, component.payload.root_path)
                    for location in outcome.selected_scope
                )
            ):
                raise UnifiedEvidenceError
        self._validate_counts()

    @staticmethod
    def _validate_osv_syft_relationship(
        finding: SecureScanFinding,
        primary: tuple[SecureScanEvidence, ...],
        supporting: tuple[SecureScanEvidence, ...],
        components: dict[str, SecureScanComponent],
    ) -> None:
        if not isinstance(finding.subject, PackageSubject) or not supporting:
            raise UnifiedEvidenceError
        component_ref = finding.subject.component_ref
        component = components[component_ref]
        if not isinstance(component.payload, PackageComponentPayload):
            raise UnifiedEvidenceError
        groups = tuple(
            item for item in primary if isinstance(item.payload, OsvAdvisoryGroupEvidencePayload)
        )
        revisions = tuple(
            item for item in primary if isinstance(item.payload, OsvAdvisoryRevisionEvidencePayload)
        )
        expected_group_key = _osv_native_digest(
            _OSV_GROUP_DOMAIN,
            {
                "aliases": groups[0].payload.aliases if groups else (),
                "osv_record_ids": groups[0].payload.osv_record_ids if groups else (),
                "package_key": component.payload.package_key,
            },
        )
        expected_native_finding_id = _osv_native_digest(
            _OSV_FINDING_DOMAIN,
            {"advisory_group_key": expected_group_key},
        )
        expected_supporting_refs = tuple(
            sorted(
                build_evidence_id(
                    EvidenceAuthority.SYFT,
                    SYFT_EVIDENCE_IDENTITY_SCHEMA,
                    package_observation_id,
                )
                for package_observation_id in (
                    groups[0].payload.package_observation_ids if groups else ()
                )
            )
        )
        if (
            len(groups) != 1
            or len(primary) != len(groups) + len(revisions)
            or groups[0].payload.finding_id != finding.native_finding_identity
            or groups[0].payload.finding_id != expected_native_finding_id
            or groups[0].payload.advisory_group_key != groups[0].native_identity
            or groups[0].payload.advisory_group_key != expected_group_key
            or finding.supporting_evidence_refs != expected_supporting_refs
            or groups[0].component_refs != (component_ref,)
            or {item.payload.osv_record_id for item in revisions}
            != set(groups[0].payload.osv_record_ids)
            or any(component_ref not in item.component_refs for item in revisions)
        ):
            raise UnifiedEvidenceError
        osv_provenance = groups[0].provenance
        if not isinstance(osv_provenance, OsvProvenance) or any(
            item.provenance != osv_provenance for item in primary
        ):
            raise UnifiedEvidenceError
        for item in supporting:
            if (
                item.authority is not EvidenceAuthority.SYFT
                or item.evidence_kind is not EvidenceKind.SYFT_PACKAGE_OBSERVATION
                or not isinstance(item.payload, SyftPackageEvidencePayload)
                or not isinstance(item.provenance, LocalScannerProvenance)
                or item.provenance.scanner_id != EvidenceAuthority.SYFT.value
                or item.component_refs != (component_ref,)
                or item.payload.package_key != component.payload.package_key
                or item.provenance.projection_id != osv_provenance.projection_id
                or item.provenance.projection_digest != osv_provenance.snapshot_digest
                or item.provenance.binding_digest != osv_provenance.syft_binding_digest
            ):
                raise UnifiedEvidenceError

    def _validate_counts(self) -> None:
        for outcome in self.coverage_outcomes:
            if outcome.gap_count and outcome.state not in {
                CoverageState.PARTIAL,
                CoverageState.FAILED,
            }:
                raise UnifiedEvidenceError
            findings = sum(self._finding_count_for_outcome(item, outcome) for item in self.findings)
            suppressions = sum(
                self._suppression_belongs_to_outcome(item, outcome) for item in self.suppressions
            )
            gaps = sum(self._gap_belongs_to_outcome(item, outcome) for item in self.gaps)
            if (
                outcome.finding_count != findings
                or outcome.suppression_count != suppressions
                or outcome.gap_count != gaps
            ):
                raise UnifiedEvidenceError

    @staticmethod
    def _paths_in_scope(
        locations: tuple[SecureScanLocation, ...],
        selected_scope: tuple[SecureScanLocation, ...],
    ) -> bool:
        if any(isinstance(item, RepositoryScopeLocation) for item in selected_scope):
            return True
        selected_paths = tuple(
            item.path
            for item in selected_scope
            if isinstance(item, (SourceSpanLocation, RepositoryPathLocation))
        )
        record_paths = tuple(
            item.path
            for item in locations
            if isinstance(item, (SourceSpanLocation, RepositoryPathLocation))
        )
        return bool(record_paths) and all(
            any(_path_within_root(path, selected) for selected in selected_paths)
            for path in record_paths
        )

    def _finding_count_for_outcome(
        self,
        finding: SecureScanFinding,
        outcome: SecureScanCoverageOutcome,
    ) -> int:
        if finding.authority is not outcome.authority:
            return 0
        if outcome.framework is not None and (
            not isinstance(finding.subject, ConfigurationResourceSubject)
            or finding.subject.framework != outcome.framework
        ):
            return 0
        if (
            outcome.component_ref is not None
            and isinstance(finding.subject, PackageSubject)
            and finding.subject.component_ref != outcome.component_ref
        ):
            return 0
        if not self._paths_in_scope(finding.locations, outcome.selected_scope):
            return 0
        if finding.authority is EvidenceAuthority.GITLEAKS:
            primary = next(
                item
                for item in self.evidence
                if item.evidence_id == finding.primary_evidence_refs[0]
            )
            assert isinstance(primary.payload, GitleaksEvidencePayload)
            return primary.payload.native_occurrence_count
        return 1

    def _suppression_belongs_to_outcome(
        self,
        suppression: SecureScanSuppression,
        outcome: SecureScanCoverageOutcome,
    ) -> bool:
        return (
            suppression.authority is outcome.authority
            and (outcome.framework is None or suppression.subject.framework == outcome.framework)
            and self._paths_in_scope(suppression.locations, outcome.selected_scope)
        )

    def _gap_belongs_to_outcome(
        self,
        gap: SecureScanGap,
        outcome: SecureScanCoverageOutcome,
    ) -> bool:
        if gap.authority is not outcome.authority:
            return False
        if outcome.component_ref is not None and gap.scope.component_ref not in {
            None,
            outcome.component_ref,
        }:
            return False
        if outcome.framework is not None and not (
            (gap.scope.kind is GapScopeKind.FRAMEWORK and gap.scope.value == outcome.framework)
            or gap.scope.framework == outcome.framework
        ):
            return False
        if gap.scope.kind is GapScopeKind.PATH:
            return self._paths_in_scope(
                (RepositoryPathLocation(gap.scope.value),), outcome.selected_scope
            )
        if gap.scope.kind is GapScopeKind.CAPABILITY:
            return gap.scope.value == outcome.capability
        return True

    def _validated_copy(self) -> SecureScanEvidenceReport:
        try:
            scope = replace(self.scope)
            components = tuple(
                replace(item, payload=replace(item.payload)) for item in self.components
            )
            evidence_values = []
            for item in self.evidence:
                payload = (
                    replace(
                        item.payload,
                        cvss=tuple(replace(value) for value in item.payload.cvss),
                    )
                    if isinstance(item.payload, OsvAdvisoryGroupEvidencePayload)
                    else replace(item.payload)
                )
                evidence_values.append(
                    replace(
                        item,
                        payload=payload,
                        provenance=(
                            replace(
                                item.provenance,
                                sanitized_artifact=replace(item.provenance.sanitized_artifact),
                            )
                            if isinstance(item.provenance, SemgrepProvenance)
                            else replace(item.provenance)
                        ),
                        locations=tuple(replace(location) for location in item.locations),
                    )
                )
            evidence = tuple(evidence_values)
            findings = tuple(
                replace(
                    item,
                    subject=replace(item.subject),
                    locations=tuple(replace(location) for location in item.locations),
                    severity=(None if item.severity is None else replace(item.severity)),
                )
                for item in self.findings
            )
            suppressions = tuple(
                replace(
                    item,
                    subject=replace(item.subject),
                    locations=tuple(replace(location) for location in item.locations),
                    payload=replace(item.payload),
                    provenance=replace(item.provenance),
                )
                for item in self.suppressions
            )
            gaps = tuple(replace(item, scope=replace(item.scope)) for item in self.gaps)
            outcomes = tuple(
                replace(
                    item,
                    selected_scope=tuple(replace(location) for location in item.selected_scope),
                )
                for item in self.coverage_outcomes
            )
            trusted = replace(
                self,
                scope=scope,
                components=components,
                evidence=evidence,
                findings=findings,
                suppressions=suppressions,
                gaps=gaps,
                coverage_outcomes=outcomes,
            )
        except Exception:
            raise UnifiedEvidenceError from None
        if trusted != self:
            raise UnifiedEvidenceError
        return trusted

    def canonical_data(self) -> dict[str, Any]:
        trusted = self._validated_copy()
        return trusted._canonical_data_unchecked()

    def _canonical_data_unchecked(self) -> dict[str, Any]:
        return {
            "components": [item.canonical_data() for item in self.components],
            "coverage_outcomes": [item.canonical_data() for item in self.coverage_outcomes],
            "evidence": [item.canonical_data() for item in self.evidence],
            "findings": [item.canonical_data() for item in self.findings],
            "gaps": [item.canonical_data() for item in self.gaps],
            "schema_version": self.schema_version,
            "scope": self.scope.canonical_data(),
            "suppressions": [item.canonical_data() for item in self.suppressions],
        }

    def canonical_json(self) -> bytes:
        return _canonical_json(self.canonical_data()) + b"\n"


def build_report(
    scope: SecureScanReportScope, *fragments: SecureScanEvidenceFragment
) -> SecureScanEvidenceReport:
    if not isinstance(scope, SecureScanReportScope) or any(
        not isinstance(item, SecureScanEvidenceFragment) for item in fragments
    ):
        raise UnifiedEvidenceError
    if any(fragment.scope is not None and fragment.scope != scope for fragment in fragments):
        raise UnifiedEvidenceError
    return SecureScanEvidenceReport(
        scope=scope,
        components=tuple(
            sorted(
                (item for fragment in fragments for item in fragment.components),
                key=lambda item: item.component_ref,
            )
        ),
        evidence=tuple(
            sorted(
                (item for fragment in fragments for item in fragment.evidence),
                key=lambda item: item.evidence_id,
            )
        ),
        findings=tuple(
            sorted(
                (item for fragment in fragments for item in fragment.findings),
                key=lambda item: item.finding_id,
            )
        ),
        suppressions=tuple(
            sorted(
                (item for fragment in fragments for item in fragment.suppressions),
                key=lambda item: item.suppression_id,
            )
        ),
        gaps=tuple(
            sorted(
                (item for fragment in fragments for item in fragment.gaps),
                key=lambda item: item.gap_id,
            )
        ),
        coverage_outcomes=tuple(
            sorted(
                (item for fragment in fragments for item in fragment.coverage_outcomes),
                key=lambda item: item.coverage_id,
            )
        ),
    )


def suppression_id(authority: EvidenceAuthority, schema: str, native_identity: str) -> str:
    if not _valid_identifier(schema) or not _valid_identifier(native_identity):
        raise UnifiedEvidenceError
    return _digest(_SUPPRESSION_DOMAIN, [authority.value, schema, native_identity])


def gap_id(authority: EvidenceAuthority, native_identity_schema: str, native_identity: str) -> str:
    if (
        not isinstance(authority, EvidenceAuthority)
        or not _valid_identifier(native_identity_schema)
        or not _valid_identifier(native_identity)
    ):
        raise UnifiedEvidenceError
    return _digest(
        _GAP_DOMAIN,
        [authority.value, native_identity_schema, native_identity],
    )


def coverage_id(
    authority: EvidenceAuthority,
    capability: str,
    framework: str | None = None,
    component_ref: str | None = None,
    selected_scope: tuple[SecureScanLocation, ...] = (RepositoryScopeLocation(),),
) -> str:
    if (
        not isinstance(authority, EvidenceAuthority)
        or not _valid_text(capability, 128)
        or (framework is not None and not _valid_text(framework, 128))
        or (component_ref is not None and not _valid_sha(component_ref))
        or not selected_scope
        or not _validate_locations(selected_scope)
    ):
        raise UnifiedEvidenceError
    return _digest(
        _COVERAGE_DOMAIN,
        [
            authority.value,
            capability,
            framework,
            component_ref,
            [item.canonical_data() for item in selected_scope],
        ],
    )

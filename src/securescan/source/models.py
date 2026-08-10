from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from securescan.source.enums import (
    AnalysisCapability,
    AssessmentStatus,
    CoverageStatus,
    FileContentKind,
    SourceExecutionStatus,
    SourceFileFlag,
    SourceFileRole,
    SourceInputType,
    SourceSupportState,
)
from securescan.workspaces.models import (
    RepositoryManifestEntry,
    repository_content_digest,
)

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTIFIER_PATTERN = re.compile(
    r"[a-z0-9][a-z0-9._-]{0,127}\Z",
    re.ASCII,
)
_REASON_CODE_PATTERN = re.compile(
    r"[A-Z][A-Z0-9_]{1,127}\Z",
    re.ASCII,
)
_PROFILE_STREAM_VERSION = b"securescan-source-profile-v0.2.1\0"


def _valid_label(value: object, *, maximum_length: int = 200) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 1 <= len(value) <= maximum_length
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _valid_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and _IDENTIFIER_PATTERN.fullmatch(value) is not None
    )


def _valid_reason_code(value: object) -> bool:
    return (
        isinstance(value, str)
        and _REASON_CODE_PATTERN.fullmatch(value) is not None
    )


def _valid_repository_path(value: object, *, allow_root: bool = False) -> bool:
    if allow_root and value == ".":
        return True
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(component not in {"", ".", ".."} for component in path.parts)
    )


def _path_is_within_root(path: str, root_path: str) -> bool:
    return root_path == "." or path.startswith(f"{root_path}/")


def _valid_sorted_path_tuple(value: object) -> bool:
    return (
        isinstance(value, tuple)
        and all(_valid_repository_path(item) for item in value)
        and value == tuple(sorted(value))
        and len(set(value)) == len(value)
    )


def _canonical_json_digest(data: dict[str, Any]) -> str:
    payload = json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256()
    digest.update(_PROFILE_STREAM_VERSION)
    digest.update(payload)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceFileRecord:
    entry: RepositoryManifestEntry
    content_kind: FileContentKind
    role: SourceFileRole
    language: str | None = None
    component_id: str | None = None
    flags: tuple[SourceFileFlag, ...] = ()
    eligible_capabilities: tuple[AnalysisCapability, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.entry, RepositoryManifestEntry)
            or not isinstance(self.content_kind, FileContentKind)
            or not isinstance(self.role, SourceFileRole)
            or (
                self.language is not None
                and not _valid_label(self.language, maximum_length=100)
            )
            or (
                self.component_id is not None
                and not _valid_identifier(self.component_id)
            )
            or not isinstance(self.flags, tuple)
            or any(not isinstance(flag, SourceFileFlag) for flag in self.flags)
            or self.flags != tuple(sorted(self.flags, key=lambda flag: flag.value))
            or len(set(self.flags)) != len(self.flags)
            or not isinstance(self.eligible_capabilities, tuple)
            or any(
                not isinstance(capability, AnalysisCapability)
                for capability in self.eligible_capabilities
            )
            or self.eligible_capabilities
            != tuple(
                sorted(
                    self.eligible_capabilities,
                    key=lambda capability: capability.value,
                )
            )
            or len(set(self.eligible_capabilities))
            != len(self.eligible_capabilities)
            or (
                self.content_kind is FileContentKind.BINARY
                and SourceFileFlag.BINARY not in self.flags
            )
            or (
                SourceFileFlag.BINARY in self.flags
                and self.content_kind is not FileContentKind.BINARY
            )
        ):
            raise ValueError("Source file record is invalid")

    @property
    def relative_path(self) -> str:
        return self.entry.relative_path

    def canonical_data(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "content_kind": self.content_kind.value,
            "eligible_capabilities": [
                capability.value for capability in self.eligible_capabilities
            ],
            "flags": [flag.value for flag in self.flags],
            "language": self.language,
            "relative_path": self.entry.relative_path,
            "role": self.role.value,
            "sha256": self.entry.sha256,
            "size_bytes": self.entry.size_bytes,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class RepositoryComponent:
    component_id: str
    display_name: str
    root_path: str
    manifest_paths: tuple[str, ...] = ()
    lockfile_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        all_paths = (*self.manifest_paths, *self.lockfile_paths)
        if (
            not _valid_identifier(self.component_id)
            or not _valid_label(self.display_name)
            or not _valid_repository_path(self.root_path, allow_root=True)
            or not _valid_sorted_path_tuple(self.manifest_paths)
            or not _valid_sorted_path_tuple(self.lockfile_paths)
            or set(self.manifest_paths) & set(self.lockfile_paths)
            or any(
                not _path_is_within_root(path, self.root_path)
                for path in all_paths
            )
        ):
            raise ValueError("Repository component is invalid")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "display_name": self.display_name,
            "lockfile_paths": list(self.lockfile_paths),
            "manifest_paths": list(self.manifest_paths),
            "root_path": self.root_path,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class LanguageSupport:
    language: str
    file_count: int
    eligible_file_count: int
    support_state: SourceSupportState
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if (
            not _valid_label(self.language, maximum_length=100)
            or not isinstance(self.file_count, int)
            or isinstance(self.file_count, bool)
            or self.file_count < 1
            or not isinstance(self.eligible_file_count, int)
            or isinstance(self.eligible_file_count, bool)
            or not 0 <= self.eligible_file_count <= self.file_count
            or not isinstance(self.support_state, SourceSupportState)
            or (
                self.reason_code is not None
                and not _valid_reason_code(self.reason_code)
            )
            or (
                self.support_state is SourceSupportState.UNSUPPORTED
                and (
                    self.eligible_file_count != 0
                    or self.reason_code is None
                )
            )
        ):
            raise ValueError("Language support record is invalid")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "eligible_file_count": self.eligible_file_count,
            "file_count": self.file_count,
            "language": self.language,
            "reason_code": self.reason_code,
            "support_state": self.support_state.value,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class AnalysisSurface:
    capability: AnalysisCapability
    support_state: SourceSupportState
    component_id: str | None = None
    eligible_paths: tuple[str, ...] = ()
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.capability, AnalysisCapability)
            or not isinstance(self.support_state, SourceSupportState)
            or (
                self.component_id is not None
                and not _valid_identifier(self.component_id)
            )
            or not _valid_sorted_path_tuple(self.eligible_paths)
            or (
                self.reason_code is not None
                and not _valid_reason_code(self.reason_code)
            )
            or (
                self.support_state is SourceSupportState.UNSUPPORTED
                and (
                    self.eligible_paths
                    or self.reason_code is None
                )
            )
        ):
            raise ValueError("Analysis surface is invalid")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "capability": self.capability.value,
            "component_id": self.component_id,
            "eligible_paths": list(self.eligible_paths),
            "reason_code": self.reason_code,
            "support_state": self.support_state.value,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class RepositoryProfile:
    repository_digest: str
    files: tuple[SourceFileRecord, ...]
    components: tuple[RepositoryComponent, ...] = ()
    languages: tuple[LanguageSupport, ...] = ()
    surfaces: tuple[AnalysisSurface, ...] = ()
    input_type: SourceInputType = SourceInputType.LOCAL_DIRECTORY
    schema_version: str = "0.2.1"

    def __post_init__(self) -> None:
        if (
            self.schema_version != "0.2.1"
            or not isinstance(self.input_type, SourceInputType)
            or not isinstance(self.repository_digest, str)
            or _SHA256_PATTERN.fullmatch(self.repository_digest) is None
            or not isinstance(self.files, tuple)
            or any(not isinstance(file, SourceFileRecord) for file in self.files)
            or self.files
            != tuple(sorted(self.files, key=lambda file: file.relative_path))
            or len({file.relative_path for file in self.files}) != len(self.files)
            or not isinstance(self.components, tuple)
            or any(
                not isinstance(component, RepositoryComponent)
                for component in self.components
            )
            or self.components
            != tuple(
                sorted(
                    self.components,
                    key=lambda component: component.component_id,
                )
            )
            or len({component.component_id for component in self.components})
            != len(self.components)
            or not isinstance(self.languages, tuple)
            or any(
                not isinstance(language, LanguageSupport)
                for language in self.languages
            )
            or self.languages
            != tuple(
                sorted(
                    self.languages,
                    key=lambda language: language.language.casefold(),
                )
            )
            or len({language.language.casefold() for language in self.languages})
            != len(self.languages)
            or not isinstance(self.surfaces, tuple)
            or any(
                not isinstance(surface, AnalysisSurface)
                for surface in self.surfaces
            )
            or self.surfaces
            != tuple(
                sorted(
                    self.surfaces,
                    key=lambda surface: (
                        surface.capability.value,
                        surface.component_id or "",
                    ),
                )
            )
            or len(
                {
                    (surface.capability, surface.component_id)
                    for surface in self.surfaces
                }
            )
            != len(self.surfaces)
        ):
            raise ValueError("Repository profile is invalid")

        expected_digest = repository_content_digest(
            tuple(file.entry for file in self.files)
        )
        if self.repository_digest != expected_digest:
            raise ValueError("Repository profile digest does not match its files")

        files_by_path = {
            file.relative_path: file
            for file in self.files
        }
        components_by_id = {
            component.component_id: component
            for component in self.components
        }

        if any(
            file.component_id is not None
            and file.component_id not in components_by_id
            for file in self.files
        ):
            raise ValueError("Repository profile references an unknown component")

        for component in self.components:
            for path in component.manifest_paths:
                file = files_by_path.get(path)
                if (
                    file is None
                    or file.role is not SourceFileRole.MANIFEST
                    or file.component_id != component.component_id
                ):
                    raise ValueError("Component manifest reference is invalid")
            for path in component.lockfile_paths:
                file = files_by_path.get(path)
                if (
                    file is None
                    or file.role is not SourceFileRole.LOCKFILE
                    or file.component_id != component.component_id
                ):
                    raise ValueError("Component lockfile reference is invalid")

        language_counts = Counter(
            file.language
            for file in self.files
            if file.language is not None
        )
        declared_languages = {
            language.language: language
            for language in self.languages
        }
        if set(language_counts) != set(declared_languages):
            raise ValueError("Repository language summary is incomplete")
        if any(
            declared_languages[name].file_count != count
            for name, count in language_counts.items()
        ):
            raise ValueError("Repository language count is inconsistent")

        for surface in self.surfaces:
            if (
                surface.component_id is not None
                and surface.component_id not in components_by_id
            ):
                raise ValueError("Analysis surface references an unknown component")
            for path in surface.eligible_paths:
                file = files_by_path.get(path)
                if file is None:
                    raise ValueError("Analysis surface references an unknown file")
                if (
                    surface.component_id is not None
                    and file.component_id != surface.component_id
                ):
                    raise ValueError(
                        "Analysis surface crosses a component boundary"
                    )

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(file.entry.size_bytes for file in self.files)

    def canonical_data(self) -> dict[str, Any]:
        return {
            "components": [
                component.canonical_data()
                for component in self.components
            ],
            "file_count": self.file_count,
            "files": [
                file.canonical_data()
                for file in self.files
            ],
            "input_type": self.input_type.value,
            "languages": [
                language.canonical_data()
                for language in self.languages
            ],
            "repository_digest": self.repository_digest,
            "schema_version": self.schema_version,
            "surfaces": [
                surface.canonical_data()
                for surface in self.surfaces
            ],
            "total_bytes": self.total_bytes,
        }

    def profile_digest(self) -> str:
        return _canonical_json_digest(self.canonical_data())


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceStatusSummary:
    execution_status: SourceExecutionStatus
    coverage_status: CoverageStatus
    assessment_status: AssessmentStatus

    def __post_init__(self) -> None:
        if (
            not isinstance(self.execution_status, SourceExecutionStatus)
            or not isinstance(self.coverage_status, CoverageStatus)
            or not isinstance(self.assessment_status, AssessmentStatus)
        ):
            raise ValueError("Source status summary is invalid")

    @property
    def automated_scope_completed(self) -> bool:
        return (
            self.execution_status is SourceExecutionStatus.COMPLETE
            and self.coverage_status
            is CoverageStatus.FULL_FOR_DECLARED_SCOPE
        )

    @property
    def human_validated(self) -> bool:
        return (
            self.automated_scope_completed
            and self.assessment_status is AssessmentStatus.VALIDATED
        )

    def canonical_data(self) -> dict[str, str]:
        return {
            "assessment_status": self.assessment_status.value,
            "coverage_status": self.coverage_status.value,
            "execution_status": self.execution_status.value,
        }

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from securescan.source.enums import AnalysisCapability
from securescan.workspaces.models import RepositoryManifestEntry

_CONTEXT_STREAM_VERSION = b"securescan-source-execution-context-v0.3C1\0"
_SCHEMA_VERSION = "0.3C1"
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTIFIER_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
_CONTEXT_FIELDS = frozenset(
    {
        "binding_digest",
        "capability",
        "component_id",
        "core_adapter_id",
        "job_id",
        "plan_digest",
        "profile_digest",
        "repository_digest",
        "schema_version",
        "selected_files",
        "source_analyzer_id",
        "source_run_id",
    }
)
_SELECTED_FILE_FIELDS = frozenset(
    {"component_id", "relative_path", "sha256", "size_bytes"}
)


class SourceExecutionContextError(RuntimeError):
    """Base class for fixed-message Source execution-context failures."""


class InvalidSourceExecutionContextError(SourceExecutionContextError, ValueError):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source execution context is invalid")


def _canonical_uuid(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 36 or value != value.lower():
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def _valid_identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER_PATTERN.fullmatch(value) is not None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_non_finite_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


@dataclass(frozen=True, slots=True)
class SourceExecutionSelectedFile:
    entry: RepositoryManifestEntry
    component_id: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.entry, RepositoryManifestEntry) or (
            self.component_id is not None and not _valid_identifier(self.component_id)
        ):
            raise InvalidSourceExecutionContextError

    @property
    def relative_path(self) -> str:
        return self.entry.relative_path

    def canonical_data(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "relative_path": self.entry.relative_path,
            "sha256": self.entry.sha256,
            "size_bytes": self.entry.size_bytes,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceExecutionContext:
    source_run_id: str
    job_id: str
    repository_digest: str
    profile_digest: str
    plan_digest: str
    source_analyzer_id: str
    capability: AnalysisCapability
    component_id: str | None
    selected_files: tuple[SourceExecutionSelectedFile, ...]
    binding_digest: str
    core_adapter_id: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        digests = (
            self.repository_digest,
            self.profile_digest,
            self.plan_digest,
            self.binding_digest,
        )
        selected_paths = (
            tuple(file.relative_path for file in self.selected_files)
            if isinstance(self.selected_files, tuple)
            and all(
                isinstance(file, SourceExecutionSelectedFile)
                for file in self.selected_files
            )
            else ()
        )
        if (
            self.schema_version != _SCHEMA_VERSION
            or not _canonical_uuid(self.source_run_id)
            or not _canonical_uuid(self.job_id)
            or any(
                not isinstance(digest, str)
                or _SHA256_PATTERN.fullmatch(digest) is None
                for digest in digests
            )
            or not _valid_identifier(self.source_analyzer_id)
            or not isinstance(self.capability, AnalysisCapability)
            or (
                self.component_id is not None
                and not _valid_identifier(self.component_id)
            )
            or not _valid_identifier(self.core_adapter_id)
            or not isinstance(self.selected_files, tuple)
            or not self.selected_files
            or any(
                not isinstance(file, SourceExecutionSelectedFile)
                for file in self.selected_files
            )
            or selected_paths != tuple(sorted(selected_paths))
            or len(set(selected_paths)) != len(selected_paths)
            or (
                self.component_id is not None
                and any(
                    file.component_id != self.component_id
                    for file in self.selected_files
                )
            )
        ):
            raise InvalidSourceExecutionContextError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "binding_digest": self.binding_digest,
            "capability": self.capability.value,
            "component_id": self.component_id,
            "core_adapter_id": self.core_adapter_id,
            "job_id": self.job_id,
            "plan_digest": self.plan_digest,
            "profile_digest": self.profile_digest,
            "repository_digest": self.repository_digest,
            "schema_version": self.schema_version,
            "selected_files": [
                selected_file.canonical_data()
                for selected_file in self.selected_files
            ],
            "source_analyzer_id": self.source_analyzer_id,
            "source_run_id": self.source_run_id,
        }

    def canonical_json(self) -> bytes:
        try:
            return json.dumps(
                self.canonical_data(),
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise InvalidSourceExecutionContextError from exc

    def context_digest(self) -> str:
        digest = hashlib.sha256()
        digest.update(_CONTEXT_STREAM_VERSION)
        digest.update(self.canonical_json())
        return digest.hexdigest()

    @classmethod
    def from_json(cls, payload: bytes) -> SourceExecutionContext:
        if not isinstance(payload, bytes):
            raise InvalidSourceExecutionContextError
        try:
            document = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_non_finite_constant,
            )
            if not isinstance(document, dict) or set(document) != _CONTEXT_FIELDS:
                raise ValueError
            selected_data = document["selected_files"]
            if not isinstance(selected_data, list) or not selected_data:
                raise ValueError
            selected_files: list[SourceExecutionSelectedFile] = []
            for value in selected_data:
                if not isinstance(value, dict) or set(value) != _SELECTED_FILE_FIELDS:
                    raise ValueError
                selected_files.append(
                    SourceExecutionSelectedFile(
                        entry=RepositoryManifestEntry(
                            relative_path=value["relative_path"],
                            size_bytes=value["size_bytes"],
                            sha256=value["sha256"],
                        ),
                        component_id=value["component_id"],
                    )
                )
            context = cls(
                source_run_id=document["source_run_id"],
                job_id=document["job_id"],
                repository_digest=document["repository_digest"],
                profile_digest=document["profile_digest"],
                plan_digest=document["plan_digest"],
                source_analyzer_id=document["source_analyzer_id"],
                capability=AnalysisCapability(document["capability"]),
                component_id=document["component_id"],
                selected_files=tuple(selected_files),
                binding_digest=document["binding_digest"],
                core_adapter_id=document["core_adapter_id"],
                schema_version=document["schema_version"],
            )
        except (
            AttributeError,
            KeyError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            UnicodeEncodeError,
        ) as exc:
            raise InvalidSourceExecutionContextError from exc
        if context.canonical_json() != payload:
            raise InvalidSourceExecutionContextError
        return context


SOURCE_EXECUTION_CONTEXT_SCHEMA_VERSION = _SCHEMA_VERSION

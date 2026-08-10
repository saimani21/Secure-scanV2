from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol

from securescan.source.enry_client import (
    EnryBatchResult,
    TrustedEnryHelper,
)
from securescan.source.enry_protocol import (
    ENRY_MAX_CONTENT_BYTES,
    EnryClassification,
    EnryFileInput,
    partition_enry_requests,
)
from securescan.source.enums import FileContentKind
from securescan.source.inventory import (
    RepositoryInventory,
    read_verified_repository_file_sample,
    verify_repository_snapshot,
)
from securescan.workspaces.models import PreparedRepositoryWorkspace

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_RELATIVE_PATH_BYTES = 4096


class SourceLanguageProfilingError(RuntimeError):
    """Raised when deterministic source-language profiling cannot complete."""

    def __init__(self) -> None:
        super().__init__("Source language profiling failed")


class InvalidSourceLanguageProfilingRequestError(
    SourceLanguageProfilingError,
    ValueError,
):
    """Raised when a profiling request or profile contract is invalid."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source language profiling request is invalid")


class SourceLanguageCorrelationError(SourceLanguageProfilingError):
    """Raised when repository or helper evidence cannot be correlated exactly."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source language evidence correlation failed")


def _has_control_character(value: str) -> bool:
    return any(unicodedata.category(character) == "Cc" for character in value)


def _valid_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    if _has_control_character(value):
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if len(encoded) > _MAX_RELATIVE_PATH_BYTES:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(component not in {"", ".", ".."} for component in path.parts)
    )


def _valid_clean_string(value: object) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if _has_control_character(value):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_PATTERN.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class SourceLanguageProfilingPolicy:
    sample_bytes: int = ENRY_MAX_CONTENT_BYTES

    def __post_init__(self) -> None:
        if (
            type(self.sample_bytes) is not int
            or not 1 <= self.sample_bytes <= ENRY_MAX_CONTENT_BYTES
        ):
            raise InvalidSourceLanguageProfilingRequestError


DEFAULT_LANGUAGE_PROFILING_POLICY = SourceLanguageProfilingPolicy()


@dataclass(frozen=True, slots=True)
class SourceLanguageEvidence:
    relative_path: str
    language: str | None
    candidate_languages: tuple[str, ...]
    is_binary: bool
    is_vendor: bool
    is_generated: bool
    is_test: bool
    is_configuration: bool
    is_documentation: bool
    is_dot_file: bool
    is_image: bool
    analyzed_bytes: int
    content_complete: bool

    def __post_init__(self) -> None:
        flags = (
            self.is_binary,
            self.is_vendor,
            self.is_generated,
            self.is_test,
            self.is_configuration,
            self.is_documentation,
            self.is_dot_file,
            self.is_image,
        )
        if (
            not _valid_relative_path(self.relative_path)
            or not isinstance(self.candidate_languages, tuple)
            or any(
                not _valid_clean_string(candidate)
                for candidate in self.candidate_languages
            )
            or self.candidate_languages != tuple(sorted(self.candidate_languages))
            or len(set(self.candidate_languages)) != len(self.candidate_languages)
            or (
                self.language is not None
                and (
                    not _valid_clean_string(self.language)
                    or self.language not in self.candidate_languages
                )
            )
            or any(type(flag) is not bool for flag in flags)
            or (
                self.is_binary
                and (self.language is not None or bool(self.candidate_languages))
            )
            or type(self.analyzed_bytes) is not int
            or self.analyzed_bytes < 0
            or type(self.content_complete) is not bool
        ):
            raise InvalidSourceLanguageProfilingRequestError


@dataclass(frozen=True, slots=True)
class SourceLanguageProfile:
    repository_digest: str
    evidence: tuple[SourceLanguageEvidence, ...]
    skipped_binary_paths: tuple[str, ...]
    helper_sha256: str | None
    helper_version: str | None
    enry_version: str | None
    batch_count: int
    duration_ms: int
    schema_version: str = "0.2.3"

    def __post_init__(self) -> None:
        evidence_paths = (
            tuple(item.relative_path for item in self.evidence)
            if isinstance(self.evidence, tuple)
            and all(isinstance(item, SourceLanguageEvidence) for item in self.evidence)
            else ()
        )
        provenance = (
            self.helper_sha256,
            self.helper_version,
            self.enry_version,
        )
        all_provenance_missing = all(value is None for value in provenance)
        all_provenance_present = (
            _valid_sha256(self.helper_sha256)
            and _valid_clean_string(self.helper_version)
            and _valid_clean_string(self.enry_version)
        )
        if (
            self.schema_version != "0.2.3"
            or not _valid_sha256(self.repository_digest)
            or not isinstance(self.evidence, tuple)
            or any(not isinstance(item, SourceLanguageEvidence) for item in self.evidence)
            or evidence_paths != tuple(sorted(evidence_paths))
            or len(set(evidence_paths)) != len(evidence_paths)
            or not isinstance(self.skipped_binary_paths, tuple)
            or any(not _valid_relative_path(path) for path in self.skipped_binary_paths)
            or self.skipped_binary_paths != tuple(sorted(self.skipped_binary_paths))
            or len(set(self.skipped_binary_paths)) != len(self.skipped_binary_paths)
            or bool(set(evidence_paths) & set(self.skipped_binary_paths))
            or type(self.batch_count) is not int
            or self.batch_count < 0
            or type(self.duration_ms) is not int
            or self.duration_ms < 0
            or not (all_provenance_missing or all_provenance_present)
            or (
                self.batch_count == 0
                and (not all_provenance_missing or self.duration_ms != 0)
            )
            or (self.batch_count > 0 and not all_provenance_present)
        ):
            raise InvalidSourceLanguageProfilingRequestError


class _LanguageProfilingClient(Protocol):
    @property
    def configuration(self) -> TrustedEnryHelper: ...

    def classify(
        self,
        files: tuple[EnryFileInput, ...],
    ) -> EnryBatchResult: ...


def _client_configuration(
    client: _LanguageProfilingClient,
) -> TrustedEnryHelper:
    try:
        configuration = client.configuration
        classify = client.classify
    except Exception:
        raise InvalidSourceLanguageProfilingRequestError from None
    if not isinstance(configuration, TrustedEnryHelper) or not callable(classify):
        raise InvalidSourceLanguageProfilingRequestError
    return configuration


def _result_values(
    result: object,
) -> tuple[
    tuple[EnryClassification, ...],
    tuple[str, str, str],
    int,
]:
    try:
        classifications = result.classifications  # type: ignore[attr-defined]
        provenance = (
            result.helper_sha256,  # type: ignore[attr-defined]
            result.helper_version,  # type: ignore[attr-defined]
            result.enry_version,  # type: ignore[attr-defined]
        )
        duration_ms = result.duration_ms  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        raise SourceLanguageCorrelationError from None
    if (
        not isinstance(classifications, tuple)
        or any(not isinstance(item, EnryClassification) for item in classifications)
        or not _valid_sha256(provenance[0])
        or not _valid_clean_string(provenance[1])
        or not _valid_clean_string(provenance[2])
        or type(duration_ms) is not int
        or duration_ms < 0
    ):
        raise SourceLanguageCorrelationError
    return classifications, provenance, duration_ms


def profile_repository_languages(
    workspace: PreparedRepositoryWorkspace,
    inventory: RepositoryInventory,
    client: _LanguageProfilingClient,
    *,
    policy: SourceLanguageProfilingPolicy = DEFAULT_LANGUAGE_PROFILING_POLICY,
) -> SourceLanguageProfile:
    if (
        not isinstance(workspace, PreparedRepositoryWorkspace)
        or not isinstance(inventory, RepositoryInventory)
        or not isinstance(policy, SourceLanguageProfilingPolicy)
    ):
        raise InvalidSourceLanguageProfilingRequestError
    configuration = _client_configuration(client)

    if (
        workspace.manifest.content_digest != inventory.repository_digest
        or tuple(file.entry for file in inventory.files)
        != workspace.manifest.entries
    ):
        raise SourceLanguageCorrelationError

    verify_repository_snapshot(workspace)
    inputs: list[EnryFileInput] = []
    sample_metadata: dict[str, tuple[int, bool]] = {}
    skipped_binary_paths: list[str] = []

    for file in inventory.files:
        verified = read_verified_repository_file_sample(
            workspace,
            file.entry,
            sample_bytes=policy.sample_bytes,
        )
        if file.content_kind is FileContentKind.BINARY:
            skipped_binary_paths.append(file.relative_path)
            continue
        inputs.append(
            EnryFileInput(
                relative_path=file.relative_path,
                content=verified.sample,
            )
        )
        sample_metadata[file.relative_path] = (
            len(verified.sample),
            verified.content_complete,
        )

    batches = partition_enry_requests(
        tuple(inputs),
        maximum_files=configuration.maximum_files_per_batch,
        maximum_payload_bytes=configuration.maximum_payload_bytes,
    )
    evidence: list[SourceLanguageEvidence] = []
    expected_provenance: tuple[str, str, str] | None = None
    duration_ms = 0

    for batch in batches:
        result = client.classify(batch)
        classifications, provenance, batch_duration_ms = _result_values(result)
        if tuple(item.relative_path for item in classifications) != tuple(
            item.relative_path for item in batch
        ):
            raise SourceLanguageCorrelationError
        if expected_provenance is None:
            expected_provenance = provenance
        elif provenance != expected_provenance:
            raise SourceLanguageCorrelationError

        duration_ms += batch_duration_ms
        for classification in classifications:
            analyzed_bytes, content_complete = sample_metadata[
                classification.relative_path
            ]
            evidence.append(
                SourceLanguageEvidence(
                    relative_path=classification.relative_path,
                    language=classification.language,
                    candidate_languages=classification.candidate_languages,
                    is_binary=classification.is_binary,
                    is_vendor=classification.is_vendor,
                    is_generated=classification.is_generated,
                    is_test=classification.is_test,
                    is_configuration=classification.is_configuration,
                    is_documentation=classification.is_documentation,
                    is_dot_file=classification.is_dot_file,
                    is_image=classification.is_image,
                    analyzed_bytes=analyzed_bytes,
                    content_complete=content_complete,
                )
            )

    verify_repository_snapshot(workspace)
    helper_sha256 = expected_provenance[0] if expected_provenance is not None else None
    helper_version = expected_provenance[1] if expected_provenance is not None else None
    enry_version = expected_provenance[2] if expected_provenance is not None else None
    return SourceLanguageProfile(
        repository_digest=inventory.repository_digest,
        evidence=tuple(evidence),
        skipped_binary_paths=tuple(skipped_binary_paths),
        helper_sha256=helper_sha256,
        helper_version=helper_version,
        enry_version=enry_version,
        batch_count=len(batches),
        duration_ms=duration_ms,
    )

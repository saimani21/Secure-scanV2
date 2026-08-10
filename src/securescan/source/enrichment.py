from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from typing import Any

from securescan.source.enums import FileContentKind, SourceFileFlag
from securescan.source.inventory import RepositoryInventory
from securescan.source.language_profiling import (
    SourceLanguageEvidence,
    SourceLanguageProfile,
)
from securescan.source.models import SourceFileRecord
from securescan.workspaces.models import repository_content_digest

_ENRICHMENT_STREAM_VERSION = b"securescan-source-enrichment-v0.2.3\0"
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class SourceEnrichmentError(RuntimeError):
    """Raised when deterministic repository enrichment cannot complete."""

    def __init__(self) -> None:
        super().__init__("Source repository enrichment failed")


class SourceEnrichmentCorrelationError(SourceEnrichmentError):
    """Raised when inventory and language evidence do not correlate exactly."""

    def __init__(self) -> None:
        RuntimeError.__init__(
            self,
            "Source repository enrichment correlation failed",
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class EnrichedRepositoryInventory:
    repository_digest: str
    files: tuple[SourceFileRecord, ...]
    schema_version: str = "0.2.3"

    def __post_init__(self) -> None:
        if (
            self.schema_version != "0.2.3"
            or not isinstance(self.repository_digest, str)
            or _SHA256_PATTERN.fullmatch(self.repository_digest) is None
            or not isinstance(self.files, tuple)
            or any(not isinstance(file, SourceFileRecord) for file in self.files)
            or self.files
            != tuple(sorted(self.files, key=lambda file: file.relative_path))
            or len({file.relative_path for file in self.files}) != len(self.files)
        ):
            raise ValueError("Enriched repository inventory is invalid")

        expected_digest = repository_content_digest(
            tuple(file.entry for file in self.files)
        )
        if self.repository_digest != expected_digest:
            raise ValueError(
                "Enriched repository inventory digest does not match its files"
            )

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(file.entry.size_bytes for file in self.files)

    def canonical_data(self) -> dict[str, Any]:
        return {
            "file_count": self.file_count,
            "files": [file.canonical_data() for file in self.files],
            "repository_digest": self.repository_digest,
            "schema_version": self.schema_version,
            "total_bytes": self.total_bytes,
        }

    def enrichment_digest(self) -> str:
        payload = json.dumps(
            self.canonical_data(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256()
        digest.update(_ENRICHMENT_STREAM_VERSION)
        digest.update(payload)
        return digest.hexdigest()


def _correlated_path_maps(
    inventory: RepositoryInventory,
    language_profile: SourceLanguageProfile,
) -> tuple[
    dict[str, SourceFileRecord],
    dict[str, SourceLanguageEvidence],
    frozenset[str],
]:
    inventory_files = inventory.files
    evidence = language_profile.evidence
    skipped_binary_paths = language_profile.skipped_binary_paths

    if (
        inventory.repository_digest != language_profile.repository_digest
        or not isinstance(inventory_files, tuple)
        or any(not isinstance(file, SourceFileRecord) for file in inventory_files)
        or not isinstance(evidence, tuple)
        or any(not isinstance(item, SourceLanguageEvidence) for item in evidence)
        or not isinstance(skipped_binary_paths, tuple)
        or any(not isinstance(path, str) for path in skipped_binary_paths)
    ):
        raise SourceEnrichmentCorrelationError

    inventory_paths = tuple(file.relative_path for file in inventory_files)
    evidence_paths = tuple(item.relative_path for item in evidence)
    if (
        inventory_paths != tuple(sorted(inventory_paths))
        or len(set(inventory_paths)) != len(inventory_paths)
        or evidence_paths != tuple(sorted(evidence_paths))
        or len(set(evidence_paths)) != len(evidence_paths)
        or skipped_binary_paths != tuple(sorted(skipped_binary_paths))
        or len(set(skipped_binary_paths)) != len(skipped_binary_paths)
        or set(evidence_paths) & set(skipped_binary_paths)
        or tuple(sorted((*evidence_paths, *skipped_binary_paths)))
        != inventory_paths
    ):
        raise SourceEnrichmentCorrelationError

    inventory_by_path = {
        file.relative_path: file
        for file in inventory_files
    }
    evidence_by_path = {
        item.relative_path: item
        for item in evidence
    }
    skipped_paths = frozenset(skipped_binary_paths)

    if any(
        inventory_by_path[path].content_kind is not FileContentKind.BINARY
        or SourceFileFlag.BINARY not in inventory_by_path[path].flags
        for path in skipped_paths
    ):
        raise SourceEnrichmentCorrelationError

    return inventory_by_path, evidence_by_path, skipped_paths


def enrich_repository_inventory(
    inventory: RepositoryInventory,
    language_profile: SourceLanguageProfile,
) -> EnrichedRepositoryInventory:
    if not isinstance(inventory, RepositoryInventory) or not isinstance(
        language_profile,
        SourceLanguageProfile,
    ):
        raise SourceEnrichmentError

    inventory_by_path, evidence_by_path, skipped_paths = _correlated_path_maps(
        inventory,
        language_profile,
    )
    enriched_files: list[SourceFileRecord] = []

    for relative_path, record in inventory_by_path.items():
        if relative_path in skipped_paths:
            enriched_files.append(replace(record))
            continue

        evidence = evidence_by_path[relative_path]
        if record.language is not None and record.language != evidence.language:
            raise SourceEnrichmentCorrelationError

        flags = set(record.flags)
        if evidence.is_generated:
            flags.add(SourceFileFlag.GENERATED)
        if evidence.is_vendor:
            flags.add(SourceFileFlag.VENDORED)
        if evidence.is_test:
            flags.add(SourceFileFlag.TEST)

        try:
            enriched_files.append(
                replace(
                    record,
                    language=evidence.language,
                    flags=tuple(sorted(flags, key=lambda flag: flag.value)),
                )
            )
        except (TypeError, ValueError):
            raise SourceEnrichmentCorrelationError from None

    return EnrichedRepositoryInventory(
        repository_digest=inventory.repository_digest,
        files=tuple(enriched_files),
    )

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .cve import validate_cve_id


class IntelligenceSource(StrEnum):
    CISA_KEV = "CISA_KEV"
    FIRST_EPSS = "FIRST_EPSS"


class KevState(StrEnum):
    LISTED = "LISTED"
    NOT_LISTED_IN_SNAPSHOT = "NOT_LISTED_IN_SNAPSHOT"
    UNAVAILABLE = "UNAVAILABLE"


class EpssState(StrEnum):
    SCORED = "SCORED"
    NOT_SCORED = "NOT_SCORED"
    UNAVAILABLE = "UNAVAILABLE"
    SNAPSHOT_INVALID = "SNAPSHOT_INVALID"


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def identity(domain: bytes, value: object) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(canonical_json(value))
    return digest.hexdigest()


def as_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError("timestamp must be timezone-aware")
    # SQLite drops timezone metadata; every persisted timestamp in this
    # contract is UTC, matching the repository's existing persistence model.
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class ParsedSnapshot:
    source: IntelligenceSource
    source_effective_at: datetime
    parser_contract_version: str
    source_schema: str
    source_metadata: dict[str, Any]
    records: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class IntelligenceSnapshot:
    snapshot_id: str
    source: IntelligenceSource
    retrieved_at: datetime
    source_effective_at: datetime | None
    content_sha256: str
    artifact_size_bytes: int
    parser_contract_version: str
    source_schema: str
    source_metadata: dict[str, Any]
    record_count: int
    records: tuple[dict[str, Any], ...]
    validity_state: str = "VALID"


@dataclass(frozen=True, slots=True)
class NvdEnrichment:
    enrichment_id: str
    cve_id: str
    retrieved_at: datetime
    content_sha256: str
    artifact_size_bytes: int
    parser_contract_version: str
    source_schema: str
    normalized: dict[str, Any]


@dataclass(frozen=True, slots=True)
class IntelligenceBundle:
    bundle_id: str
    kev_snapshot_id: str | None
    epss_snapshot_id: str | None
    nvd_enrichment_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ThreatAssessment:
    assessment_id: str
    project_id: str
    lineage_id: str
    run_id: str
    finding_id: str
    advisory_id: str
    cve_id: str
    intelligence_bundle_id: str
    kev_evidence: dict[str, Any]
    epss_evidence: dict[str, Any]
    nvd_enrichment_id: str | None
    evaluated_at: datetime

    def __post_init__(self) -> None:
        validate_cve_id(self.cve_id)

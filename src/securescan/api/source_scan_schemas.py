from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from securescan.product_core import SourceProductStatus, SourceStageProgressState


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class ScanSubmissionRequest(_StrictModel):
    project_id: UUID
    trusted_target_id: UUID
    lineage_id: UUID | None = None
    idempotency_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    deadline_at: datetime

    def model_post_init(self, __context: Any) -> None:
        if self.deadline_at.tzinfo is None or self.deadline_at.utcoffset() is None:
            raise ValueError("deadline_at must include a UTC offset")


class ScanSubmissionResponse(_StrictModel):
    run_id: str
    lineage_id: str
    submission_sequence_number: int
    predecessor_run_id: str | None
    status: SourceProductStatus


class ScanSummaryResponse(_StrictModel):
    run_id: str
    target_id: str
    project_id: str
    lineage_id: str
    submission_sequence_number: int
    predecessor_run_id: str | None
    product_status: SourceProductStatus
    created_at: datetime
    published_at: datetime | None
    finalized_at: datetime | None
    indexed: bool
    lifecycle_evaluated: bool
    finding_count: int
    priority_counts: dict[str, int]
    category_counts: dict[str, int]
    coverage_complete: bool | None
    coverage_counts: dict[str, int]
    gap_count: int | None


class ScanListItemResponse(_StrictModel):
    run_id: str
    target_id: str
    project_id: str
    lineage_id: str
    submission_sequence_number: int
    predecessor_run_id: str | None
    product_status: SourceProductStatus
    created_at: datetime
    published_at: datetime | None
    finalized_at: datetime | None
    indexed: bool
    lifecycle_evaluated: bool


class StageSummaryResponse(_StrictModel):
    authority: str
    capability: str
    progress_state: SourceStageProgressState
    coverage_states: tuple[str, ...] | None
    reason_code: str | None


class ScanStagesResponse(_StrictModel):
    run_id: str
    product_status: SourceProductStatus
    published_at: datetime | None
    finalized_at: datetime | None
    stages: tuple[StageSummaryResponse, ...]


class ScanPageResponse(_StrictModel):
    items: tuple[ScanListItemResponse, ...]
    total: int
    limit: int
    offset: int


class FindingSummaryResponse(_StrictModel):
    finding_id: str
    authority: str
    category: str
    severity: str | None
    priority_band: str
    priority_reason_codes: tuple[str, ...]
    lifecycle_state: str
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    subject: dict[str, Any]
    primary_location: dict[str, Any] | None


class FindingPageResponse(_StrictModel):
    items: tuple[FindingSummaryResponse, ...]
    total: int
    limit: int
    offset: int


class ComponentSummaryResponse(_StrictModel):
    component_ref: str
    component_kind: str
    payload: dict[str, Any]


class ComponentPageResponse(_StrictModel):
    items: tuple[ComponentSummaryResponse, ...]
    total: int
    limit: int
    offset: int


class DependencyAdvisoryResponse(_StrictModel):
    canonical_advisory_id: str
    finding_id: str
    osv_record_ids: tuple[str, ...]
    aliases: tuple[str, ...]
    cve_aliases: tuple[str, ...]
    ghsa_aliases: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    priority_band: str


class DependencySummaryResponse(_StrictModel):
    component_ref: str
    name: str
    version: str | None
    package_type: str
    purl: str | None
    locations: tuple[dict[str, Any], ...]
    vulnerability_evaluation: str
    vulnerability_evaluation_reason: str | None
    known_vulnerability_count: int | None
    advisories: tuple[DependencyAdvisoryResponse, ...]
    advisory_aliases: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    priority_bands: tuple[str, ...]


class DependencyPageResponse(_StrictModel):
    items: tuple[DependencySummaryResponse, ...]
    total: int
    limit: int
    offset: int


class CoverageResponse(_StrictModel):
    complete: bool
    counts_by_state: dict[str, int]
    outcomes: tuple[dict[str, Any], ...]


class GapSummaryResponse(_StrictModel):
    gap_id: str
    authority: str
    code: str
    scope: dict[str, Any]
    message: str | None


class GapPageResponse(_StrictModel):
    items: tuple[GapSummaryResponse, ...]
    total: int
    limit: int
    offset: int


class PublishedReportResponse(_StrictModel):
    run_id: str
    report: dict[str, Any]


class CancellationResponse(_StrictModel):
    run_id: str
    status: SourceProductStatus
    cancellation_requested: bool
    already_terminal: bool

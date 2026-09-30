from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from securescan.product_core import SecurityDeltaComparisonStatus, SecurityDeltaState


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class TrustedBaselineResponse(_StrictModel):
    baseline_id: str
    lineage_id: str
    run_id: str
    run_sequence_number: int
    revision: int
    actor_type: str
    promoted_at: datetime


class TrustedBaselineStateResponse(_StrictModel):
    lineage_id: str
    revision: int
    baseline: TrustedBaselineResponse | None


class TrustedBaselinePromotionRequest(_StrictModel):
    run_id: str
    expected_revision: int = Field(ge=0)


class TrustedBaselineHistoryPageResponse(_StrictModel):
    items: tuple[TrustedBaselineResponse, ...]
    total: int
    limit: int
    offset: int


class SecurityDeltaFindingResponse(_StrictModel):
    finding_id: str
    authority: str
    category: str
    state: SecurityDeltaState
    reason_codes: tuple[str, ...]


class SecurityDeltaAuthoritySummaryResponse(_StrictModel):
    authority: str
    comparison_status: SecurityDeltaComparisonStatus
    introduced_count: int
    present_count: int
    removed_count: int
    not_comparable_count: int
    reason_codes: tuple[str, ...]


class SecurityDeltaResponse(_StrictModel):
    baseline_id: str
    baseline_run_id: str
    baseline_revision: int
    baseline_sequence_number: int
    candidate_run_id: str
    candidate_sequence_number: int
    comparison_status: SecurityDeltaComparisonStatus
    authority_summaries: tuple[SecurityDeltaAuthoritySummaryResponse, ...]
    findings: tuple[SecurityDeltaFindingResponse, ...]

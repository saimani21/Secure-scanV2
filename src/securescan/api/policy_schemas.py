from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from securescan.product_core import (
    PolicyDecisionKind,
    PolicyResult,
    PolicySpec,
    PriorityBand,
    SecurityDeltaState,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class PolicyUpdateRequest(_StrictModel):
    expected_version: int = Field(ge=1)
    definition: PolicySpec


class TrustedPolicyResponse(_StrictModel):
    policy_id: str
    lineage_id: str
    version: int
    digest: str
    definition: PolicySpec
    actor_type: str
    created_at: datetime | None


class PolicyDecisionResponse(_StrictModel):
    kind: PolicyDecisionKind
    rule_id: str
    reason_code: str
    finding_id: str | None
    authority: str | None
    category: str | None
    delta_state: SecurityDeltaState | None
    priority: PriorityBand | None
    source_reason_codes: tuple[str, ...]


class PolicyEvaluationResponse(_StrictModel):
    evaluation_id: str
    lineage_id: str
    candidate_run_id: str
    baseline_id: str | None
    baseline_revision: int | None
    policy_id: str
    policy_version: int
    policy_digest: str
    result: PolicyResult
    decisions: tuple[PolicyDecisionResponse, ...]
    evaluated_at: datetime

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from securescan.product_core import (
    AnalystDisposition,
    EffectiveGovernanceReasonCode,
    FindingLifecycleState,
)


class EffectiveGovernanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    lineage_id: str
    finding_id: str
    lifecycle_state: FindingLifecycleState
    current_episode_transition_version: int
    disposition: AnalystDisposition
    disposition_revision: int
    governance_lifecycle_transition_version: int | None
    false_positive_effective: bool
    accepted_risk_effective: bool
    accepted_risk_expires_at: datetime | None
    governance_last_changed_at: datetime | None
    suppression_present: bool
    suppression_effective: bool
    suppression_id: str | None
    suppression_revision: int
    suppression_lifecycle_transition_version: int | None
    suppression_expires_at: datetime | None
    suppression_revoked_at: datetime | None
    suppression_last_changed_at: datetime | None
    review_required: bool
    reason_codes: tuple[EffectiveGovernanceReasonCode, ...]
    evaluated_at: datetime

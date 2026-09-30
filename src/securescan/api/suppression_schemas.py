from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from securescan.product_core import SuppressionOperation


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class FindingSuppressionResponse(_StrictModel):
    lineage_id: str
    finding_id: str
    suppression_id: str | None
    reason: str | None
    expires_at: datetime | None
    revoked_at: datetime | None
    revision: int
    active: bool
    actor_type: str | None
    created_at: datetime | None
    updated_at: datetime | None


class FindingSuppressionMutationRequest(_StrictModel):
    reason: str = Field(max_length=1000)
    expires_at: datetime
    expected_revision: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_material(self):
        if not self.reason.strip():
            raise ValueError("reason is required")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("expires_at must include a UTC offset")
        return self


class FindingSuppressionRevokeRequest(_StrictModel):
    expected_revision: int = Field(ge=0)


class FindingSuppressionEventResponse(_StrictModel):
    event_id: str
    lineage_id: str
    finding_id: str
    suppression_id: str
    operation: SuppressionOperation
    previous_reason: str | None
    new_reason: str
    previous_expires_at: datetime | None
    new_expires_at: datetime
    previous_revoked_at: datetime | None
    new_revoked_at: datetime | None
    actor_type: str
    occurred_at: datetime
    resulting_revision: int
    lifecycle_transition_version: int | None


class FindingSuppressionEventPageResponse(_StrictModel):
    items: tuple[FindingSuppressionEventResponse, ...]
    total: int
    limit: int
    offset: int

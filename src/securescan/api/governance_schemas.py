from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from securescan.product_core import AnalystDisposition, GovernanceOperation


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class FindingGovernanceResponse(_StrictModel):
    lineage_id: str
    finding_id: str
    disposition: AnalystDisposition
    reason: str | None
    expires_at: datetime | None
    revision: int
    last_changed_by_type: str | None
    created_at: datetime | None
    updated_at: datetime | None


class FindingGovernanceMutationRequest(_StrictModel):
    disposition: AnalystDisposition
    reason: str | None = Field(default=None, max_length=1000)
    expires_at: datetime | None = None
    expected_revision: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_material(self):
        if self.disposition is AnalystDisposition.UNREVIEWED:
            if self.reason is not None or self.expires_at is not None:
                raise ValueError("UNREVIEWED carries no reason or expiry")
        elif not self.reason or not self.reason.strip():
            raise ValueError("reason is required")
        elif self.disposition is AnalystDisposition.FALSE_POSITIVE:
            if self.expires_at is not None:
                raise ValueError("FALSE_POSITIVE carries no expiry")
        elif self.expires_at is None:
            raise ValueError("ACCEPTED_RISK requires expires_at")
        elif self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("expires_at must include a UTC offset")
        return self


class FindingGovernanceEventResponse(_StrictModel):
    event_id: str
    lineage_id: str
    finding_id: str
    operation: GovernanceOperation
    previous_disposition: AnalystDisposition
    new_disposition: AnalystDisposition
    previous_reason: str | None
    new_reason: str | None
    previous_expires_at: datetime | None
    new_expires_at: datetime | None
    actor_type: str
    occurred_at: datetime
    resulting_revision: int
    lifecycle_transition_version: int | None


class FindingGovernanceEventPageResponse(_StrictModel):
    items: tuple[FindingGovernanceEventResponse, ...]
    total: int
    limit: int
    offset: int

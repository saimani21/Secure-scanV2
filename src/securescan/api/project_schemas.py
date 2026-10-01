from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class ProjectCreateRequest(_StrictModel):
    name: str


class ProjectSummaryResponse(_StrictModel):
    project_id: str
    name: str
    created_at: datetime


class ProjectPageResponse(_StrictModel):
    items: tuple[ProjectSummaryResponse, ...]
    total: int
    limit: int
    offset: int

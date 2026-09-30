from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from securescan.product_core.guidance import GuidanceBasis


class FindingGuidanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    run_id: str
    finding_id: str
    authority: str
    basis_level: GuidanceBasis
    title: str
    summary: str
    remediation_steps: tuple[str, ...]
    verification_steps: tuple[str, ...]
    limitations: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    locations: tuple[dict[str, Any], ...]
    rule_id: str | None = None
    cwe_ids: tuple[str, ...] = ()
    detection_kind: str | None = None
    advisory_id: str | None = None
    advisory_aliases: tuple[str, ...] = ()
    package_name: str | None = None
    observed_version: str | None = None
    reported_fixed_event_versions: tuple[str, ...] = ()
    check_id: str | None = None
    check_name: str | None = None
    framework: str | None = None
    resource: str | None = None

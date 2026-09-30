from __future__ import annotations

from uuid import UUID

import pytest
from fastapi import HTTPException

from securescan.api.effective_governance_routes import get_effective_governance
from securescan.api.main import app
from securescan.product_core import AnalystDisposition, EffectiveGovernanceReasonCode

pytest_plugins = ("tests.test_effective_governance_v12d",)


def test_effective_governance_api_serializes_read_model(effective_context) -> None:
    response = get_effective_governance(
        UUID(effective_context["project_id"]),
        UUID(effective_context["lineage_id"]),
        effective_context["finding_id"],
        effective_context["effective"],
    )
    assert response.disposition is AnalystDisposition.UNREVIEWED
    assert response.false_positive_effective is False
    assert response.accepted_risk_effective is False
    assert response.suppression_effective is False
    assert response.reason_codes == (EffectiveGovernanceReasonCode.NO_GOVERNANCE,)


def test_effective_governance_api_maps_unknown_scope_to_404(effective_context) -> None:
    with pytest.raises(HTTPException) as raised:
        get_effective_governance(
            UUID("99999999-9999-4999-8999-999999999999"),
            UUID(effective_context["lineage_id"]),
            effective_context["finding_id"],
            effective_context["effective"],
        )
    assert raised.value.status_code == 404
    assert raised.value.detail["code"] == "EFFECTIVE_GOVERNANCE_NOT_FOUND"


def test_openapi_exposes_one_read_only_effective_governance_operation() -> None:
    document = app.openapi()
    path = (
        "/v1/projects/{project_id}/lineages/{lineage_id}/findings/"
        "{finding_id}/effective-governance"
    )
    assert set(document["paths"][path]) == {"get"}
    schema = document["components"]["schemas"]["EffectiveGovernanceResponse"]
    assert {
        "false_positive_effective",
        "accepted_risk_effective",
        "suppression_effective",
        "review_required",
        "reason_codes",
        "evaluated_at",
    } <= set(schema["required"])

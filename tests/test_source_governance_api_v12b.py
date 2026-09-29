from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from securescan.api.governance_routes import (
    get_finding_governance,
    list_finding_governance_events,
    mutate_finding_governance,
)
from securescan.api.governance_schemas import FindingGovernanceMutationRequest
from securescan.product_core import AnalystDisposition
from tests.test_source_governance_v12b import _NOW

pytest_plugins = ("tests.test_source_governance_v12b",)


def test_api_read_mutate_clear_and_history(governance_context) -> None:
    _environment, service, project_id, lineage_id, finding_id = governance_context
    initial = get_finding_governance(project_id, lineage_id, finding_id, service)
    assert initial.disposition is AnalystDisposition.UNREVIEWED and initial.revision == 0
    changed = mutate_finding_governance(
        project_id,
        lineage_id,
        finding_id,
        FindingGovernanceMutationRequest(
            disposition=AnalystDisposition.FALSE_POSITIVE,
            reason="<b>untrusted analyst text</b>",
            expected_revision=0,
        ),
        service,
    )
    assert changed.reason == "<b>untrusted analyst text</b>"
    cleared = mutate_finding_governance(
        project_id,
        lineage_id,
        finding_id,
        FindingGovernanceMutationRequest(
            disposition=AnalystDisposition.UNREVIEWED,
            expected_revision=1,
        ),
        service,
    )
    assert cleared.disposition is AnalystDisposition.UNREVIEWED
    history = list_finding_governance_events(
        project_id, lineage_id, finding_id, service, limit=50, offset=0
    )
    assert history.total == 2
    assert tuple(item.resulting_revision for item in history.items) == (1, 2)


def test_api_stale_revision_is_stable_409(governance_context) -> None:
    _environment, service, project_id, lineage_id, finding_id = governance_context
    body = FindingGovernanceMutationRequest(
        disposition=AnalystDisposition.FALSE_POSITIVE,
        reason="first",
        expected_revision=0,
    )
    mutate_finding_governance(project_id, lineage_id, finding_id, body, service)
    with pytest.raises(HTTPException) as raised:
        mutate_finding_governance(project_id, lineage_id, finding_id, body, service)
    assert raised.value.status_code == 409
    assert raised.value.detail["code"] == "GOVERNANCE_REVISION_CONFLICT"


@pytest.mark.parametrize(
    "payload",
    [
        {"disposition": "FALSE_POSITIVE", "expected_revision": 0},
        {
            "disposition": "ACCEPTED_RISK",
            "reason": "reason",
            "expected_revision": 0,
        },
        {
            "disposition": "ACCEPTED_RISK",
            "reason": "reason",
            "expires_at": datetime(2027, 1, 1),
            "expected_revision": 0,
        },
        {
            "disposition": "UNREVIEWED",
            "reason": "not allowed",
            "expected_revision": 0,
        },
        {
            "disposition": "CONFIRMED",
            "reason": "not supported",
            "expected_revision": 0,
        },
    ],
)
def test_mutation_schema_rejects_invalid_material(payload) -> None:
    with pytest.raises(ValidationError):
        FindingGovernanceMutationRequest.model_validate(payload)


def test_mutation_schema_accepts_explicit_future_risk() -> None:
    body = FindingGovernanceMutationRequest(
        disposition=AnalystDisposition.ACCEPTED_RISK,
        reason="bounded reason",
        expires_at=_NOW + timedelta(days=1),
        expected_revision=0,
    )
    assert body.expires_at is not None and body.expires_at.tzinfo is UTC

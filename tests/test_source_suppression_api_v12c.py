from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from securescan.api.main import app
from securescan.api.suppression_routes import (
    get_finding_suppression,
    list_finding_suppression_events,
    mutate_finding_suppression,
    revoke_finding_suppression,
)
from securescan.api.suppression_schemas import (
    FindingSuppressionMutationRequest,
    FindingSuppressionRevokeRequest,
)
from securescan.product_core import SuppressionOperation
from tests.test_source_suppression_v12c import _NOW

pytest_plugins = ("tests.test_source_suppression_v12c",)


def test_api_read_create_update_revoke_and_history(suppression_context) -> None:
    _environment, service, _clock, project_id, lineage_id, finding_id = suppression_context
    project_uuid = UUID(project_id)
    lineage_uuid = UUID(lineage_id)
    initial = get_finding_suppression(project_uuid, lineage_uuid, finding_id, service)
    assert initial.active is False and initial.revision == 0

    created = mutate_finding_suppression(
        project_uuid,
        lineage_uuid,
        finding_id,
        FindingSuppressionMutationRequest(
            reason="<b>hostile text remains data</b>",
            expires_at=_NOW + timedelta(days=2),
            expected_revision=0,
        ),
        service,
    )
    assert created.active is True
    assert created.reason == "<b>hostile text remains data</b>"

    updated = mutate_finding_suppression(
        project_uuid,
        lineage_uuid,
        finding_id,
        FindingSuppressionMutationRequest(
            reason="updated",
            expires_at=_NOW + timedelta(days=3),
            expected_revision=1,
        ),
        service,
    )
    assert updated.suppression_id == created.suppression_id
    assert updated.revision == 2

    revoked = revoke_finding_suppression(
        project_uuid,
        lineage_uuid,
        finding_id,
        FindingSuppressionRevokeRequest(expected_revision=2),
        service,
    )
    assert revoked.active is False and revoked.revision == 3
    history = list_finding_suppression_events(
        project_uuid, lineage_uuid, finding_id, service, limit=50, offset=0
    )
    assert history.total == 3
    assert tuple(item.operation for item in history.items) == (
        SuppressionOperation.CREATE,
        SuppressionOperation.UPDATE,
        SuppressionOperation.REVOKE,
    )


def test_api_revision_and_state_conflicts_are_stable_409(suppression_context) -> None:
    _environment, service, _clock, project_id, lineage_id, finding_id = suppression_context
    project_uuid = UUID(project_id)
    lineage_uuid = UUID(lineage_id)
    body = FindingSuppressionMutationRequest(
        reason="first",
        expires_at=_NOW + timedelta(days=1),
        expected_revision=0,
    )
    mutate_finding_suppression(project_uuid, lineage_uuid, finding_id, body, service)
    with pytest.raises(HTTPException) as stale:
        mutate_finding_suppression(project_uuid, lineage_uuid, finding_id, body, service)
    assert stale.value.status_code == 409
    assert stale.value.detail["code"] == "SUPPRESSION_REVISION_CONFLICT"

    revoke_finding_suppression(
        project_uuid,
        lineage_uuid,
        finding_id,
        FindingSuppressionRevokeRequest(expected_revision=1),
        service,
    )
    with pytest.raises(HTTPException) as inactive:
        revoke_finding_suppression(
            project_uuid,
            lineage_uuid,
            finding_id,
            FindingSuppressionRevokeRequest(expected_revision=2),
            service,
        )
    assert inactive.value.status_code == 409
    assert inactive.value.detail["code"] == "SUPPRESSION_STATE_CONFLICT"


@pytest.mark.parametrize(
    "payload",
    [
        {"expires_at": _NOW + timedelta(days=1), "expected_revision": 0},
        {"reason": "", "expires_at": _NOW + timedelta(days=1), "expected_revision": 0},
        {"reason": " ", "expires_at": _NOW + timedelta(days=1), "expected_revision": 0},
        {"reason": "reason", "expected_revision": 0},
        {
            "reason": "reason",
            "expires_at": datetime(2026, 10, 1),
            "expected_revision": 0,
        },
        {
            "reason": "reason",
            "expires_at": _NOW + timedelta(days=1),
            "expected_revision": -1,
        },
        {
            "reason": "reason",
            "expires_at": _NOW + timedelta(days=1),
            "expected_revision": 0,
            "unknown": True,
        },
    ],
)
def test_mutation_schema_rejects_invalid_material(payload) -> None:
    with pytest.raises(ValidationError):
        FindingSuppressionMutationRequest.model_validate(payload)


def test_mutation_schema_accepts_explicit_aware_expiry() -> None:
    body = FindingSuppressionMutationRequest(
        reason="bounded reason",
        expires_at=_NOW + timedelta(days=1),
        expected_revision=0,
    )
    assert body.expires_at.tzinfo is UTC


def test_openapi_contains_only_bounded_suppression_operations() -> None:
    document = app.openapi()
    root = "/v1/projects/{project_id}/lineages/{lineage_id}/findings/{finding_id}/suppression"
    assert set(document["paths"][root]) == {"get", "put"}
    assert set(document["paths"][f"{root}/revoke"]) == {"post"}
    assert set(document["paths"][f"{root}/events"]) == {"get"}
    schema = document["components"]["schemas"]["FindingSuppressionResponse"]
    assert "active" in schema["required"]

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from securescan.api.policy_routes import (
    evaluate_trusted_policy,
    get_policy_evaluation,
    get_trusted_policy,
    router,
    update_trusted_policy,
)
from securescan.api.policy_schemas import PolicyUpdateRequest
from securescan.product_core import (
    DEFAULT_POLICY,
    PolicyDecision,
    PolicyDecisionKind,
    PolicyEvaluation,
    PolicyNotFoundError,
    PolicyResult,
    TrustedPolicy,
)
from securescan.product_core.policy import _digest

_PROJECT = UUID("77777777-7777-4777-8777-777777777771")
_LINEAGE = UUID("77777777-7777-4777-8777-777777777772")
_RUN = UUID("77777777-7777-4777-8777-777777777773")
_EVALUATION = UUID("77777777-7777-4777-8777-777777777774")
_NOW = datetime(2026, 10, 3, tzinfo=UTC)


def _policy() -> TrustedPolicy:
    return TrustedPolicy(
        policy_id="77777777-7777-4777-8777-777777777775",
        lineage_id=str(_LINEAGE),
        version=1,
        digest=_digest(DEFAULT_POLICY),
        definition=DEFAULT_POLICY,
        actor_type="BUILTIN",
        created_at=None,
    )


def _result() -> PolicyEvaluation:
    return PolicyEvaluation(
        evaluation_id=str(_EVALUATION),
        lineage_id=str(_LINEAGE),
        candidate_run_id=str(_RUN),
        baseline_id=None,
        baseline_revision=None,
        policy_id=_policy().policy_id,
        policy_version=1,
        policy_digest=_policy().digest,
        result=PolicyResult.ERROR,
        decisions=(
            PolicyDecision(
                kind=PolicyDecisionKind.ERROR,
                rule_id="REQUIRED_EVIDENCE",
                reason_code="BASELINE_UNAVAILABLE",
            ),
        ),
        evaluated_at=_NOW,
    )


def test_policy_api_contract_and_strict_schema() -> None:
    service = SimpleNamespace(
        get_policy=lambda **_kwargs: _policy(),
        update_policy=lambda **_kwargs: _policy(),
        evaluate=lambda **_kwargs: _result(),
        get_evaluation=lambda **_kwargs: _result(),
    )
    body = PolicyUpdateRequest(expected_version=1, definition=DEFAULT_POLICY)
    assert get_trusted_policy(_PROJECT, _LINEAGE, service).digest == _policy().digest
    assert update_trusted_policy(_PROJECT, _LINEAGE, body, service).version == 1
    assert evaluate_trusted_policy(_PROJECT, _LINEAGE, _RUN, service).result is PolicyResult.ERROR
    assert get_policy_evaluation(_PROJECT, _LINEAGE, _EVALUATION, service).evaluation_id == str(
        _EVALUATION
    )
    with pytest.raises(ValidationError):
        PolicyUpdateRequest.model_validate(
            {
                "expected_version": 1,
                "definition": DEFAULT_POLICY.model_dump(mode="json"),
                "candidate_chosen_policy": "unsafe",
            }
        )
    paths = {route.path for route in router.routes}
    assert "/v1/projects/{project_id}/lineages/{lineage_id}/policy" in paths
    assert (
        "/v1/projects/{project_id}/lineages/{lineage_id}/runs/{candidate_run_id}/policy-evaluations"
        in paths
    )


def test_policy_api_not_found_is_scoped() -> None:
    service = SimpleNamespace(
        get_policy=lambda **_kwargs: (_ for _ in ()).throw(PolicyNotFoundError())
    )
    with pytest.raises(HTTPException) as error:
        get_trusted_policy(_PROJECT, _LINEAGE, service)
    assert error.value.status_code == 404
    assert error.value.detail["code"] == "POLICY_TARGET_NOT_FOUND"

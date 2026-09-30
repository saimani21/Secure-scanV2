from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from securescan.api.main import app
from securescan.api.trusted_baseline_routes import (
    get_current_trusted_baseline,
    get_security_delta,
    list_trusted_baseline_history,
    promote_trusted_baseline,
)
from securescan.api.trusted_baseline_schemas import TrustedBaselinePromotionRequest
from securescan.product_core import (
    SecurityDelta,
    SecurityDeltaAuthoritySummary,
    SecurityDeltaComparisonStatus,
    SecurityDeltaFinding,
    SecurityDeltaNotFoundError,
    SecurityDeltaState,
    TrustedBaseline,
    TrustedBaselineConflictError,
    TrustedBaselineHistoryPage,
    TrustedBaselineState,
)

_PROJECT = UUID("77777777-7777-4777-8777-777777777771")
_LINEAGE = UUID("77777777-7777-4777-8777-777777777772")
_RUN = UUID("77777777-7777-4777-8777-777777777773")
_NOW = datetime(2026, 10, 2, tzinfo=UTC)


def _baseline() -> TrustedBaseline:
    return TrustedBaseline(
        baseline_id="77777777-7777-4777-8777-777777777774",
        lineage_id=str(_LINEAGE),
        run_id=str(_RUN),
        run_sequence_number=1,
        revision=1,
        actor_type="LOCAL_OPERATOR",
        promoted_at=_NOW,
    )


def test_baseline_api_serializes_empty_current_promotion_and_history() -> None:
    baseline = _baseline()
    service = SimpleNamespace(
        get_current=lambda **_kwargs: TrustedBaselineState(
            lineage_id=str(_LINEAGE), revision=0, baseline=None
        ),
        promote=lambda **_kwargs: baseline,
        list_history=lambda **_kwargs: TrustedBaselineHistoryPage(
            items=(baseline,), total=1, limit=50, offset=0
        ),
    )
    current = get_current_trusted_baseline(_PROJECT, _LINEAGE, service)
    promoted = promote_trusted_baseline(
        _PROJECT,
        _LINEAGE,
        TrustedBaselinePromotionRequest(run_id=str(_RUN), expected_revision=0),
        service,
    )
    history = list_trusted_baseline_history(_PROJECT, _LINEAGE, service)
    assert current.revision == 0 and current.baseline is None
    assert promoted.baseline_id == baseline.baseline_id
    assert history.items[0].run_id == str(_RUN)


def test_delta_api_serializes_exact_baseline_identity_and_states() -> None:
    delta = SecurityDelta(
        baseline_id=_baseline().baseline_id,
        baseline_run_id=str(_RUN),
        baseline_revision=1,
        baseline_sequence_number=1,
        candidate_run_id=str(_RUN),
        candidate_sequence_number=1,
        comparison_status=SecurityDeltaComparisonStatus.COMPLETE,
        authority_summaries=(
            SecurityDeltaAuthoritySummary(
                authority="gitleaks",
                comparison_status=SecurityDeltaComparisonStatus.COMPLETE,
                introduced_count=0,
                present_count=1,
                removed_count=0,
                not_comparable_count=0,
                reason_codes=(),
            ),
        ),
        findings=(
            SecurityDeltaFinding(
                finding_id="a" * 64,
                authority="gitleaks",
                category="SECRET_EXPOSURE",
                state=SecurityDeltaState.PRESENT,
                reason_codes=("EXACT_FINDING_OBSERVED_BOTH",),
            ),
        ),
    )
    response = get_security_delta(
        _PROJECT,
        _LINEAGE,
        _RUN,
        SimpleNamespace(evaluate=lambda **_kwargs: delta),
    )
    assert response.baseline_id == delta.baseline_id
    assert response.findings[0].state is SecurityDeltaState.PRESENT


def test_api_errors_are_stable_and_candidate_cannot_supply_baseline() -> None:
    def conflict(**_kwargs):
        raise TrustedBaselineConflictError

    with pytest.raises(HTTPException) as baseline_error:
        promote_trusted_baseline(
            _PROJECT,
            _LINEAGE,
            TrustedBaselinePromotionRequest(run_id=str(_RUN), expected_revision=0),
            SimpleNamespace(promote=conflict),
        )
    assert baseline_error.value.status_code == 409
    assert baseline_error.value.detail["code"] == "TRUSTED_BASELINE_REVISION_CONFLICT"

    def missing(**_kwargs):
        raise SecurityDeltaNotFoundError

    with pytest.raises(HTTPException) as delta_error:
        get_security_delta(_PROJECT, _LINEAGE, _RUN, SimpleNamespace(evaluate=missing))
    assert delta_error.value.status_code == 404
    assert delta_error.value.detail["code"] == "SECURITY_DELTA_NOT_FOUND"

    with pytest.raises(ValidationError):
        TrustedBaselinePromotionRequest.model_validate(
            {
                "run_id": str(_RUN),
                "expected_revision": 0,
                "repository_baseline_id": "untrusted",
            }
        )


def test_openapi_freezes_operator_mutation_and_read_only_delta() -> None:
    document = app.openapi()
    baseline_path = "/v1/projects/{project_id}/lineages/{lineage_id}/baseline"
    history_path = baseline_path + "/history"
    delta_path = (
        "/v1/projects/{project_id}/lineages/{lineage_id}/runs/{candidate_run_id}/security-delta"
    )
    assert set(document["paths"][baseline_path]) == {"get", "put"}
    assert set(document["paths"][history_path]) == {"get"}
    assert set(document["paths"][delta_path]) == {"get"}
    request_schema = document["components"]["schemas"]["TrustedBaselinePromotionRequest"]
    assert set(request_schema["properties"]) == {"run_id", "expected_revision"}

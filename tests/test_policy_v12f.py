from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from securescan.product_core import (
    DEFAULT_POLICY,
    AnalystDisposition,
    CandidateFindingFact,
    EffectiveGovernance,
    FindingLifecycleState,
    PolicyDecisionKind,
    PolicyResult,
    PolicySpec,
    PriorityBand,
    SecurityDelta,
    SecurityDeltaAuthoritySummary,
    SecurityDeltaComparisonStatus,
    SecurityDeltaFinding,
    SecurityDeltaState,
    SourcePolicyService,
)
from securescan.product_core.policy import _digest

_NOW = datetime(2026, 10, 3, tzinfo=UTC)
_FINDING = "a" * 64


def _spec(*, required=("gitleaks",), **changes) -> PolicySpec:
    data = DEFAULT_POLICY.model_dump(mode="json")
    data["required_authorities"] = list(required)
    data.update(changes)
    return PolicySpec.model_validate(data)


def _facts(priority: PriorityBand, lifecycle: FindingLifecycleState, *, category="SECRET_EXPOSURE"):
    return (
        CandidateFindingFact(
            finding_id=_FINDING,
            authority="gitleaks",
            category=category,
            priority_band=priority,
            priority_reason_codes=("SCANNER_NORMALIZED_SEVERITY",),
            lifecycle_state=lifecycle,
            lifecycle_transition_version=1,
        ),
    )


def _effective(**changes) -> tuple[EffectiveGovernance, ...]:
    base = EffectiveGovernance(
        lineage_id="11111111-1111-4111-8111-111111111111",
        finding_id=_FINDING,
        lifecycle_state=FindingLifecycleState.NEW,
        current_episode_transition_version=1,
        disposition=AnalystDisposition.UNREVIEWED,
        disposition_revision=0,
        governance_lifecycle_transition_version=None,
        false_positive_effective=False,
        accepted_risk_effective=False,
        accepted_risk_expires_at=None,
        governance_last_changed_at=None,
        suppression_present=False,
        suppression_effective=False,
        suppression_id=None,
        suppression_revision=0,
        suppression_lifecycle_transition_version=None,
        suppression_expires_at=None,
        suppression_revoked_at=None,
        suppression_last_changed_at=None,
        review_required=False,
        reason_codes=(),
        evaluated_at=_NOW,
    )
    return (replace(base, **changes),)


def _delta(
    state: SecurityDeltaState,
    *,
    status=SecurityDeltaComparisonStatus.COMPLETE,
    category="SECRET_EXPOSURE",
    reasons=(),
    other_status=None,
) -> SecurityDelta:
    summaries = [
        SecurityDeltaAuthoritySummary(
            authority="gitleaks",
            comparison_status=status,
            introduced_count=int(state is SecurityDeltaState.INTRODUCED),
            present_count=int(state is SecurityDeltaState.PRESENT),
            removed_count=int(state is SecurityDeltaState.REMOVED),
            not_comparable_count=int(state is SecurityDeltaState.NOT_COMPARABLE),
            reason_codes=reasons,
        )
    ]
    if other_status is not None:
        summaries.append(
            SecurityDeltaAuthoritySummary(
                authority="checkov",
                comparison_status=other_status,
                introduced_count=0,
                present_count=0,
                removed_count=0,
                not_comparable_count=0,
                reason_codes=("CANDIDATE_NODE_FAILED",),
            )
        )
    return SecurityDelta(
        baseline_id="22222222-2222-4222-8222-222222222222",
        baseline_run_id="33333333-3333-4333-8333-333333333333",
        baseline_revision=1,
        baseline_sequence_number=1,
        candidate_run_id="44444444-4444-4444-8444-444444444444",
        candidate_sequence_number=2,
        comparison_status=status,
        authority_summaries=tuple(summaries),
        findings=(
            SecurityDeltaFinding(
                finding_id=_FINDING,
                authority="gitleaks",
                category=category,
                state=state,
                reason_codes=reasons,
            ),
        ),
    )


def _result(decisions) -> PolicyResult:
    if any(item.kind is PolicyDecisionKind.ERROR for item in decisions):
        return PolicyResult.ERROR
    if any(item.kind is PolicyDecisionKind.VIOLATION for item in decisions):
        return PolicyResult.FAIL
    return PolicyResult.PASS


@pytest.mark.parametrize(
    ("state", "priority", "lifecycle", "expected"),
    (
        (
            SecurityDeltaState.INTRODUCED,
            PriorityBand.CRITICAL,
            FindingLifecycleState.NEW,
            PolicyResult.FAIL,
        ),
        (
            SecurityDeltaState.INTRODUCED,
            PriorityBand.HIGH,
            FindingLifecycleState.NEW,
            PolicyResult.FAIL,
        ),
        (
            SecurityDeltaState.INTRODUCED,
            PriorityBand.MEDIUM,
            FindingLifecycleState.NEW,
            PolicyResult.PASS,
        ),
        (
            SecurityDeltaState.PRESENT,
            PriorityBand.HIGH,
            FindingLifecycleState.EXISTING,
            PolicyResult.PASS,
        ),
        (
            SecurityDeltaState.REMOVED,
            PriorityBand.HIGH,
            FindingLifecycleState.RESOLVED,
            PolicyResult.PASS,
        ),
        (
            SecurityDeltaState.PRESENT,
            PriorityBand.HIGH,
            FindingLifecycleState.REOPENED,
            PolicyResult.FAIL,
        ),
    ),
)
def test_delta_priority_and_candidate_lifecycle_rules(state, priority, lifecycle, expected):
    spec = _spec(secret_introduced_fail=False)
    decisions = SourcePolicyService._decide(
        spec, _delta(state), _facts(priority, lifecycle), _effective()
    )
    assert _result(decisions) is expected
    if state is SecurityDeltaState.INTRODUCED and priority is PriorityBand.MEDIUM:
        assert [item.kind for item in decisions] == [PolicyDecisionKind.WARNING]


def test_present_is_explicitly_configurable_and_secret_category_is_enforced():
    spec = _spec()
    secret = SourcePolicyService._decide(
        spec,
        _delta(SecurityDeltaState.INTRODUCED),
        _facts(PriorityBand.INFO, FindingLifecycleState.NEW),
        _effective(),
    )
    assert _result(secret) is PolicyResult.FAIL
    assert secret[0].rule_id == "SECRET_INTRODUCED"

    data = spec.model_dump(mode="json")
    data["present"]["HIGH"] = "FAIL"
    data["secret_introduced_fail"] = False
    configured = PolicySpec.model_validate(data)
    present = SourcePolicyService._decide(
        configured,
        _delta(SecurityDeltaState.PRESENT),
        _facts(PriorityBand.HIGH, FindingLifecycleState.EXISTING),
        _effective(),
    )
    assert _result(present) is PolicyResult.FAIL
    assert present[0].rule_id == "PRESENT_HIGH"


@pytest.mark.parametrize(
    ("change", "code"),
    (
        ({"false_positive_effective": True}, "EXCLUDED_EFFECTIVE_FALSE_POSITIVE"),
        ({"accepted_risk_effective": True}, "EXCLUDED_EFFECTIVE_ACCEPTED_RISK"),
        ({"suppression_effective": True}, "EXCLUDED_EFFECTIVE_SUPPRESSION"),
    ),
)
def test_only_effective_governance_excludes_failure(change, code):
    source = _delta(SecurityDeltaState.INTRODUCED)
    before = source.findings
    decisions = SourcePolicyService._decide(
        _spec(secret_introduced_fail=False),
        source,
        _facts(PriorityBand.HIGH, FindingLifecycleState.NEW),
        _effective(**change),
    )
    assert _result(decisions) is PolicyResult.PASS
    assert decisions[0].reason_code == code
    assert source.findings == before


@pytest.mark.parametrize(
    "change",
    (
        {"disposition": AnalystDisposition.FALSE_POSITIVE, "review_required": True},
        {"disposition": AnalystDisposition.ACCEPTED_RISK, "accepted_risk_expires_at": _NOW},
        {"suppression_present": True, "suppression_revoked_at": _NOW},
    ),
)
def test_dormant_expired_or_revoked_state_does_not_exclude(change):
    decisions = SourcePolicyService._decide(
        _spec(secret_introduced_fail=False),
        _delta(SecurityDeltaState.INTRODUCED),
        _facts(PriorityBand.HIGH, FindingLifecycleState.REOPENED),
        _effective(**change),
    )
    assert _result(decisions) is PolicyResult.FAIL
    assert not any(item.kind is PolicyDecisionKind.EXCLUSION for item in decisions)


def test_required_unknown_is_error_but_unrelated_authority_is_isolated():
    unknown = SourcePolicyService._decide(
        _spec(secret_introduced_fail=False),
        _delta(
            SecurityDeltaState.NOT_COMPARABLE,
            status=SecurityDeltaComparisonStatus.NOT_COMPARABLE,
            reasons=("CANDIDATE_NODE_FAILED",),
        ),
        (),
        (),
    )
    assert _result(unknown) is PolicyResult.ERROR
    assert {item.reason_code for item in unknown} >= {
        "REQUIRED_AUTHORITY_NOT_COMPARABLE",
        "REQUIRED_FINDING_NOT_COMPARABLE",
    }
    partial = SourcePolicyService._decide(
        _spec(secret_introduced_fail=False),
        _delta(
            SecurityDeltaState.PRESENT,
            status=SecurityDeltaComparisonStatus.PARTIAL,
            reasons=("CANDIDATE_AUTHORITY_GAPS_PRESENT",),
        ),
        _facts(PriorityBand.HIGH, FindingLifecycleState.EXISTING),
        _effective(),
    )
    assert _result(partial) is PolicyResult.ERROR
    assert any(item.reason_code == "REQUIRED_COVERAGE_INCOMPLETE" for item in partial)

    unrelated = SourcePolicyService._decide(
        _spec(secret_introduced_fail=False),
        _delta(
            SecurityDeltaState.PRESENT, other_status=SecurityDeltaComparisonStatus.NOT_COMPARABLE
        ),
        _facts(PriorityBand.HIGH, FindingLifecycleState.EXISTING),
        _effective(),
    )
    assert _result(unrelated) is PolicyResult.PASS


def test_policy_digest_is_canonical_and_schema_is_closed():
    first = DEFAULT_POLICY.model_dump(mode="json")
    second = DEFAULT_POLICY.model_dump(mode="json")
    second["required_authorities"].reverse()
    assert _digest(PolicySpec.model_validate(first)) == _digest(PolicySpec.model_validate(second))
    first["arbitrary_expression"] = "true"
    with pytest.raises(ValidationError):
        PolicySpec.model_validate(first)

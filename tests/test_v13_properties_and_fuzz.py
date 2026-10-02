from __future__ import annotations

import copy
import hashlib
import random
import string
from dataclasses import asdict, replace
from datetime import timedelta

import pytest
from unified_evidence_fixtures import RUN_ID

from securescan.evidence import (
    ComponentKind,
    PackageComponentPayload,
    SecureScanComponent,
    build_component_ref,
)
from securescan.product_core import AnalystDisposition, FindingLifecycleState
from securescan.product_core.component_identity import package_identity
from securescan.product_core.effective_governance import EffectiveGovernanceReasonCode
from securescan.product_core.interoperability import (
    _cyclonedx_document,
    canonical_export_json,
)
from securescan.product_core.policy import (
    DEFAULT_POLICY,
    PolicyDecisionKind,
    PolicyValidationError,
    SourcePolicyService,
)
from securescan.product_core.security_delta import (
    SecurityDelta,
    SecurityDeltaAuthoritySummary,
    SecurityDeltaComparisonStatus,
)
from securescan.product_core.verified_read import VerifiedPublishedRun
from securescan.scanners.semgrep.source_execution import (
    InvalidSourceSemgrepExecutionRequestError,
    SourceExecutionEnvelope,
    SourceProjectionExecutionReference,
)
from tests.test_effective_governance_v12d import (
    _NOW,
    _govern,
    _read,
    _resolve_and_reopen,
    _suppress,
)
from tests.test_trusted_baseline_delta_v12e import (
    _BASELINE_RUN,
    _CANDIDATE_RUNS,
    _promote,
)
from tests.test_unified_evidence_models import _report

pytest_plugins = (
    "tests.test_effective_governance_v12d",
    "tests.test_trusted_baseline_delta_v12e",
)

PROPERTY_SEEDS = tuple(range(16))


def _package(seed: int) -> SecureScanComponent:
    rng = random.Random(seed)
    name = "pkg-" + "".join(rng.choice(string.ascii_lowercase) for _ in range(12))
    version = f"{rng.randrange(0, 10)}.{rng.randrange(0, 30)}.{rng.randrange(0, 100)}"
    package_key = hashlib.sha256(f"{name}\0{version}".encode()).hexdigest()
    return SecureScanComponent(
        component_ref=build_component_ref(ComponentKind.PACKAGE, package_key),
        component_kind=ComponentKind.PACKAGE,
        native_component_identity=package_key,
        payload=PackageComponentPayload(
            package_key=package_key,
            package_name=name,
            package_version=version,
            package_type="python",
            purl=None,
        ),
    )


@pytest.mark.parametrize("seed", PROPERTY_SEEDS)
def test_property_component_and_purl_serialization_is_deterministic(seed: int) -> None:
    component = _package(seed)
    first = package_identity(component)
    second = package_identity(replace(component))

    assert first == second
    assert first.purl is not None and first.purl.startswith("pkg:pypi/")
    assert canonical_export_json(asdict(first)) == canonical_export_json(asdict(second))


@pytest.mark.parametrize("seed", PROPERTY_SEEDS)
def test_property_cyclonedx_is_order_independent_and_deterministic(seed: int) -> None:
    report = _report()
    components = list(report.components)
    random.Random(seed).shuffle(components)
    shuffled = replace(
        report,
        components=tuple(sorted(components, key=lambda item: item.component_ref)),
    )
    verified = VerifiedPublishedRun(
        run_id=RUN_ID,
        target_id="00000000-0000-4000-8000-00000000b001",
        project_id="00000000-0000-4000-8000-00000000b002",
        lineage_id=None,
        report_artifact_sha256="a" * 64,
        report_artifact_size_bytes=len(shuffled.canonical_json()),
        report=shuffled,
    )

    assert canonical_export_json(_cyclonedx_document(verified)) == canonical_export_json(
        _cyclonedx_document(verified)
    )


@pytest.mark.parametrize(
    "status",
    (
        SecurityDeltaComparisonStatus.PARTIAL,
        SecurityDeltaComparisonStatus.NOT_COMPARABLE,
    ),
)
def test_property_required_unknown_or_not_comparable_truth_never_passes(
    status: SecurityDeltaComparisonStatus,
) -> None:
    summaries = tuple(
        SecurityDeltaAuthoritySummary(
            authority=authority,
            comparison_status=status,
            introduced_count=0,
            present_count=0,
            removed_count=0,
            not_comparable_count=0,
            reason_codes=("GENERATED_INCOMPLETE_EVIDENCE",),
        )
        for authority in DEFAULT_POLICY.required_authorities
    )
    delta = SecurityDelta(
        baseline_id="00000000-0000-4000-8000-000000000001",
        baseline_run_id="00000000-0000-4000-8000-000000000002",
        baseline_revision=1,
        baseline_sequence_number=1,
        candidate_run_id="00000000-0000-4000-8000-000000000003",
        candidate_sequence_number=2,
        comparison_status=status,
        authority_summaries=summaries,
        findings=(),
    )

    decisions = SourcePolicyService._decide(DEFAULT_POLICY, delta, (), ())
    assert decisions
    assert all(decision.kind is PolicyDecisionKind.ERROR for decision in decisions)


def test_property_baseline_revision_is_strictly_monotonic(delta_context) -> None:
    promoted = (
        _promote(delta_context, _BASELINE_RUN, revision=0),
        _promote(delta_context, _CANDIDATE_RUNS[0], revision=1),
        _promote(delta_context, _CANDIDATE_RUNS[1], revision=2),
    )

    assert tuple(item.revision for item in promoted) == (1, 2, 3)
    assert tuple(item.run_sequence_number for item in promoted) == (2, 3, 4)


@pytest.mark.parametrize("seed", tuple(range(9)))
def test_property_pre_reopen_exclusions_are_dormant_until_reaffirmed(
    seed: int,
    effective_context,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    choice = seed % 3
    if choice == 0:
        _govern(
            effective_context,
            AnalystDisposition.FALSE_POSITIVE,
            reason=f"generated false positive {seed}",
        )
    elif choice == 1:
        _govern(
            effective_context,
            AnalystDisposition.ACCEPTED_RISK,
            reason=f"generated accepted risk {seed}",
            expiry=_NOW + timedelta(days=30 + seed),
        )
    else:
        first_suppression = _suppress(
            effective_context,
            reason=f"generated suppression {seed}",
            expiry=_NOW + timedelta(days=30 + seed),
        )

    _resolve_and_reopen(effective_context, monkeypatch)
    reopened = _read(effective_context)
    assert reopened.lifecycle_state is FindingLifecycleState.REOPENED
    assert reopened.false_positive_effective is False
    assert reopened.accepted_risk_effective is False
    assert reopened.suppression_effective is False
    assert reopened.review_required is True
    assert EffectiveGovernanceReasonCode.REOPENED_REVIEW_REQUIRED in reopened.reason_codes

    if choice == 0:
        _govern(
            effective_context,
            AnalystDisposition.FALSE_POSITIVE,
            reason=f"reaffirmed false positive {seed}",
            revision=1,
        )
        assert _read(effective_context).false_positive_effective is True
    elif choice == 1:
        _govern(
            effective_context,
            AnalystDisposition.ACCEPTED_RISK,
            reason=f"reaffirmed accepted risk {seed}",
            expiry=_NOW + timedelta(days=60 + seed),
            revision=1,
        )
        assert _read(effective_context).accepted_risk_effective is True
    else:
        reaffirmed = _suppress(
            effective_context,
            reason=f"reaffirmed suppression {seed}",
            expiry=_NOW + timedelta(days=60 + seed),
            revision=1,
        )
        assert reaffirmed.suppression_id != first_suppression.suppression_id
        assert _read(effective_context).suppression_effective is True
    assert _read(effective_context).review_required is False


@pytest.mark.parametrize("seed", PROPERTY_SEEDS)
def test_fuzz_malformed_execution_envelopes_fail_with_fixed_message(seed: int) -> None:
    reference = SourceProjectionExecutionReference(
        projection_id="securescan-source-projection-" + "1" * 16,
        context_digest="2" * 64,
        projection_digest="3" * 64,
    )
    payload = SourceExecutionEnvelope(
        artifact_sha256="4" * 64,
        artifact_size_bytes=100,
        context_digest="2" * 64,
        projection_reference=reference,
    ).payload_json()
    malformed = copy.deepcopy(payload)
    body = next(iter(malformed.values()))
    mutation = seed % 8
    if mutation == 0:
        body["artifact_sha256"] = "secret-sentinel"
    elif mutation == 1:
        body["artifact_size_bytes"] = -1
    elif mutation == 2:
        body["artifact_sanitized"] = True
    elif mutation == 3:
        body["context_digest"] = "5" * 64
    elif mutation == 4:
        body["projection_reference"]["projection_id"] = "../escape"
    elif mutation == 5:
        body["projection_reference"]["schema_version"] = "future"
    elif mutation == 6:
        body["unexpected"] = seed
    else:
        del body["artifact_kind"]

    with pytest.raises(InvalidSourceSemgrepExecutionRequestError) as error:
        SourceExecutionEnvelope.from_payload_json(malformed)
    assert str(error.value) == "Source Semgrep execution request is invalid"
    assert "secret-sentinel" not in str(error.value)


@pytest.mark.parametrize("seed", PROPERTY_SEEDS)
def test_fuzz_policy_documents_reject_unknown_or_oversized_values(seed: int) -> None:
    document = DEFAULT_POLICY.model_dump(mode="json")
    if seed % 2:
        document["required_authorities"] = ["unknown-" + str(seed)]
    else:
        document["extra_" + str(seed)] = "x" * (seed + 1)

    with pytest.raises(PolicyValidationError) as error:
        SourcePolicyService._parse_spec(document)
    assert "x" * 100 not in str(error.value)


def test_fuzz_canonical_json_rejects_non_finite_numbers() -> None:
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            canonical_export_json({"hostile": value})

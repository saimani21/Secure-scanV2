from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from test_unified_evidence_models import _report
from unified_evidence_fixtures import RUN_ID

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.intelligence import (
    AssuranceService,
    IntelligenceIngestionError,
    IntelligenceService,
    IntelligenceSource,
    ThreatPolicySpec,
    exact_cve_aliases,
    parse_epss_snapshot,
    parse_kev_snapshot,
    parse_nvd_enrichment,
    validate_cve_id,
)
from securescan.intelligence.service import IntelligenceIntegrityError
from securescan.persistence.database import (
    AnalysisRunRow,
    Base,
    ProjectRow,
    SourceIntelligenceSnapshotRow,
    SourceLineageRunRow,
    SourcePolicyDecisionProofRow,
    SourceTargetLineageRow,
    TargetRow,
)
from securescan.product_core import (
    AnalystDisposition,
    CandidateFindingFact,
    EffectiveGovernance,
    FindingLifecycleState,
    PolicySpec,
    PriorityBand,
    SecurityDelta,
    SecurityDeltaAuthoritySummary,
    SecurityDeltaComparisonStatus,
    SecurityDeltaFinding,
    SecurityDeltaState,
    TrustedPolicy,
)
from securescan.product_core.policy import DEFAULT_POLICY, SourcePolicyService, _digest
from securescan.product_core.verified_read import VerifiedPublishedRun

NOW = datetime(2026, 10, 2, 12, tzinfo=UTC)
PROJECT_ID = "00000000-0000-4000-8000-00000000d501"
TARGET_ID = "00000000-0000-4000-8000-00000000d502"
LINEAGE_ID = "00000000-0000-4000-8000-00000000d503"


def kev_payload(*, cve: str = "CVE-2025-12345", count: int = 1) -> bytes:
    return json.dumps(
        {
            "catalogVersion": "2026.10.02",
            "dateReleased": "2026-10-02T10:00:00.000Z",
            "count": count,
            "vulnerabilities": [
                {
                    "cveID": cve,
                    "vendorProject": "Example",
                    "product": "Widget",
                    "vulnerabilityName": "Controlled vulnerability",
                    "dateAdded": "2026-10-01",
                    "shortDescription": "Controlled description",
                    "requiredAction": "Apply the vendor fix",
                    "dueDate": "2026-10-20",
                    "knownRansomwareCampaignUse": "Unknown",
                    "notes": "",
                    "cwes": ["CWE-79"],
                }
            ],
        },
        separators=(",", ":"),
    ).encode()


def epss_payload(
    *,
    cve: str = "CVE-2025-12345",
    score: str = "0.42",
    score_date: str = "2026-10-01",
) -> bytes:
    return gzip.compress(
        (
            f"#model_version:v2025.03.14,score_date:{score_date}\n"
            "cve,epss,percentile\n"
            f"{cve},{score},0.91\n"
        ).encode()
    )


def nvd_payload(*, cve: str = "CVE-2025-12345") -> bytes:
    return json.dumps(
        {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2026-10-02T10:00:00.000",
            "vulnerabilities": [
                {
                    "cve": {
                        "id": cve,
                        "published": "2025-01-01T00:00:00.000",
                        "lastModified": "2026-10-01T00:00:00.000",
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "Controlled NVD text"}],
                        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                    "cvssData": {
                                        "version": "3.1",
                                        "vectorString": (
                                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                        ),
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                    },
                                }
                            ]
                        },
                        "references": [{"url": "https://example.test/advisory", "tags": []}],
                    }
                }
            ],
        },
        separators=(",", ":"),
    ).encode()


@pytest.fixture
def intelligence(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'intel.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    report = _report()
    report_bytes = report.canonical_json()
    with factory.begin() as session:
        session.add(ProjectRow(id=PROJECT_ID, name="controlled", created_at=NOW))
        session.add(
            TargetRow(
                id=TARGET_ID,
                project_id=PROJECT_ID,
                target_type="source_repository",
                content_digest="a" * 64,
                source_path="/controlled",
                metadata_json={},
                created_at=NOW,
            )
        )
        session.add(
            AnalysisRunRow(
                id=RUN_ID,
                target_id=TARGET_ID,
                status="completed",
                report_json={},
                created_at=NOW,
            )
        )
        session.add(
            SourceTargetLineageRow(lineage_id=LINEAGE_ID, project_id=PROJECT_ID, created_at=NOW)
        )
        session.add(
            SourceLineageRunRow(
                run_id=RUN_ID,
                lineage_id=LINEAGE_ID,
                sequence_number=1,
                predecessor_run_id=None,
                predecessor_sequence_number=None,
                report_artifact_sha256="b" * 64,
                report_artifact_size_bytes=len(report_bytes),
                report_schema_version="securescan-unified-evidence-s4-v1",
                indexing_state="ATTACHED",
                indexed_at=None,
                lifecycle_evaluated_at=None,
                lifecycle_evaluation_sha256=None,
                lifecycle_event_count=None,
                created_at=NOW,
            )
        )
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    service = IntelligenceService(factory, store, clock=lambda: NOW)
    service._verified = SimpleNamespace(
        load=lambda **_: VerifiedPublishedRun(
            run_id=RUN_ID,
            target_id=TARGET_ID,
            project_id=PROJECT_ID,
            lineage_id=LINEAGE_ID,
            report_artifact_sha256="b" * 64,
            report_artifact_size_bytes=len(report_bytes),
            report=report,
        )
    )
    try:
        yield service, factory, store, report
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "value",
    ["cve-2025-12345", " CVE-2025-12345", "CVE-25-1234", "CVE-2025-123", "CVE-2025-" + "1" * 20],
)
def test_exact_cve_validator_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(ValueError):
        validate_cve_id(value)


def test_only_exact_osv_aliases_establish_cve_identity() -> None:
    assert exact_cve_aliases(
        (
            "GHSA-9wx4-h78v-vm56",
            "CVE-2025-22222",
            "CVE-2025-11111",
            "CVE-2025-22222",
            "cve-2025-33333",
        )
    ) == ("CVE-2025-11111", "CVE-2025-22222")


def test_kev_parser_preserves_typed_catalog_semantics() -> None:
    parsed = parse_kev_snapshot(kev_payload())
    assert parsed.source is IntelligenceSource.CISA_KEV
    assert parsed.records[0]["known_ransomware_campaign_use"] == "Unknown"
    assert parsed.records[0]["due_date"] == "2026-10-20"


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"<html>unavailable</html>",
        b'{"catalogVersion":"x","catalogVersion":"y"}',
        kev_payload(count=2),
        kev_payload(cve="CVE-2025-123"),
    ],
)
def test_hostile_kev_documents_fail_closed(payload: bytes) -> None:
    with pytest.raises(IntelligenceIngestionError):
        parse_kev_snapshot(payload)


def test_epss_parser_preserves_probability_and_metadata() -> None:
    parsed = parse_epss_snapshot(epss_payload())
    assert parsed.source is IntelligenceSource.FIRST_EPSS
    assert parsed.source_effective_at.isoformat() == "2026-10-01T00:00:00+00:00"
    assert parsed.parser_contract_version == "securescan-first-epss-v1"
    assert parsed.source_metadata == {
        "model_version": "v2025.03.14",
        "score_date": "2026-10-01",
    }
    assert parsed.records[0]["epss"] == 0.42


def test_epss_parser_accepts_rfc3339_score_date() -> None:
    parsed = parse_epss_snapshot(epss_payload(score_date="2026-10-03T12:00:21Z"))

    assert parsed.source_effective_at.isoformat() == "2026-10-03T12:00:21+00:00"
    assert parsed.parser_contract_version == "securescan-first-epss-v1"
    assert parsed.source_metadata["score_date"] == "2026-10-03T12:00:21Z"


@pytest.mark.parametrize(
    "payload",
    [
        b"not-gzip",
        gzip.compress(b"cve,epss,percentile\nCVE-2025-12345,0.1,0.2\n"),
        epss_payload(score="-0.1"),
        epss_payload(score="1.1"),
        epss_payload(score="NaN"),
        epss_payload(cve="CVE-2025-123"),
    ],
)
def test_hostile_epss_documents_fail_closed(payload: bytes) -> None:
    with pytest.raises(IntelligenceIngestionError):
        parse_epss_snapshot(payload)


def test_nvd_requires_exact_requested_cve_and_preserves_all_metrics() -> None:
    parsed = parse_nvd_enrichment(nvd_payload(), expected_cve="CVE-2025-12345")
    assert parsed["cve_id"] == "CVE-2025-12345"
    assert parsed["metrics"][0]["version"] == "3.1"
    with pytest.raises(IntelligenceIngestionError):
        parse_nvd_enrichment(nvd_payload(cve="CVE-2025-99999"), expected_cve="CVE-2025-12345")


def test_snapshot_import_is_immutable_idempotent_and_failed_import_preserves_valid_state(
    intelligence,
) -> None:
    service, factory, _, _ = intelligence
    first = service.import_kev(kev_payload())
    second = service.import_kev(kev_payload(), retrieved_at=NOW.replace(hour=13))
    assert first.snapshot_id == second.snapshot_id
    assert service.list_snapshots() == (first,)
    with pytest.raises(IntelligenceIngestionError):
        service.import_kev(kev_payload(count=2))
    with factory() as session:
        assert len(session.scalars(select(SourceIntelligenceSnapshotRow)).all()) == 1


def test_corrupt_snapshot_artifact_is_never_eligible_for_read(intelligence) -> None:
    service, _, store, _ = intelligence
    snapshot = service.import_kev(kev_payload())
    path = store.root / "sha256" / snapshot.content_sha256[:2] / snapshot.content_sha256
    path.write_bytes(b"corrupt")
    with pytest.raises(IntelligenceIntegrityError):
        service.list_snapshots()


def test_offline_threat_assessment_is_exact_append_only_and_does_not_mutate_finding_identity(
    intelligence,
) -> None:
    service, _, _, report = intelligence
    original_ids = tuple(item.finding_id for item in report.findings)
    kev = service.import_kev(kev_payload())
    epss = service.import_epss(epss_payload())
    nvd = service.import_nvd(nvd_payload(), expected_cve="CVE-2025-12345")
    first_bundle = service.create_bundle(
        kev_snapshot_id=kev.snapshot_id,
        epss_snapshot_id=epss.snapshot_id,
        nvd_enrichment_ids=(nvd.enrichment_id,),
    )
    first = service.evaluate_run(
        project_id=PROJECT_ID,
        lineage_id=LINEAGE_ID,
        run_id=RUN_ID,
        bundle_id=first_bundle.bundle_id,
    )
    replay = service.evaluate_run(
        project_id=PROJECT_ID,
        lineage_id=LINEAGE_ID,
        run_id=RUN_ID,
        bundle_id=first_bundle.bundle_id,
        evaluated_at=NOW.replace(hour=14),
    )
    assert first == replay
    assert len(first) == 1
    assert first[0].cve_id == "CVE-2025-12345"
    assert first[0].kev_evidence["state"] == "LISTED"
    assert first[0].epss_evidence["record"]["epss"] == 0.42
    assert tuple(item.finding_id for item in report.findings) == original_ids

    later_epss = service.import_epss(epss_payload(score="0.73"))
    second_bundle = service.create_bundle(
        kev_snapshot_id=kev.snapshot_id,
        epss_snapshot_id=later_epss.snapshot_id,
        nvd_enrichment_ids=(nvd.enrichment_id,),
    )
    second = service.evaluate_run(
        project_id=PROJECT_ID,
        lineage_id=LINEAGE_ID,
        run_id=RUN_ID,
        bundle_id=second_bundle.bundle_id,
    )
    history = service.list_assessments(project_id=PROJECT_ID, run_id=RUN_ID)
    assert second[0].assessment_id != first[0].assessment_id
    assert sorted(item.epss_evidence["record"]["epss"] for item in history) == [0.42, 0.73]


def test_threat_policy_proof_is_deterministic_and_evidence_complete(
    intelligence, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, factory, store, report = intelligence
    dependency = next(
        item for item in report.findings if item.category.value == "DEPENDENCY_VULNERABILITY"
    )
    kev = service.import_kev(kev_payload())
    epss = service.import_epss(epss_payload())
    nvd = service.import_nvd(nvd_payload(), expected_cve="CVE-2025-12345")
    bundle = service.create_bundle(
        kev_snapshot_id=kev.snapshot_id,
        epss_snapshot_id=epss.snapshot_id,
        nvd_enrichment_ids=(nvd.enrichment_id,),
    )
    assessments = service.evaluate_run(
        project_id=PROJECT_ID,
        lineage_id=LINEAGE_ID,
        run_id=RUN_ID,
        bundle_id=bundle.bundle_id,
    )
    fact = CandidateFindingFact(
        finding_id=dependency.finding_id,
        authority="osv.dev",
        category="DEPENDENCY_VULNERABILITY",
        priority_band=PriorityBand.HIGH,
        priority_reason_codes=("SCANNER_NORMALIZED_SEVERITY",),
        lifecycle_state=FindingLifecycleState.NEW,
        lifecycle_transition_version=1,
    )
    governance = EffectiveGovernance(
        lineage_id=LINEAGE_ID,
        finding_id=dependency.finding_id,
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
        evaluated_at=NOW,
    )
    delta = SecurityDelta(
        baseline_id="00000000-0000-4000-8000-00000000d510",
        baseline_run_id="00000000-0000-4000-8000-00000000d511",
        baseline_revision=1,
        baseline_sequence_number=1,
        candidate_run_id=RUN_ID,
        candidate_sequence_number=2,
        comparison_status=SecurityDeltaComparisonStatus.COMPLETE,
        authority_summaries=(
            SecurityDeltaAuthoritySummary(
                authority="osv.dev",
                comparison_status=SecurityDeltaComparisonStatus.COMPLETE,
                introduced_count=1,
                present_count=0,
                removed_count=0,
                not_comparable_count=0,
                reason_codes=(),
            ),
        ),
        findings=(
            SecurityDeltaFinding(
                finding_id=dependency.finding_id,
                authority="osv.dev",
                category="DEPENDENCY_VULNERABILITY",
                state=SecurityDeltaState.INTRODUCED,
                reason_codes=(),
            ),
        ),
    )
    policy_data = DEFAULT_POLICY.model_dump(mode="json")
    policy_data["required_authorities"] = ["osv.dev"]
    policy_data["secret_introduced_fail"] = False
    for name in ("introduced", "present", "reopened"):
        policy_data[name] = {band.value: "ALLOW" for band in PriorityBand}
    base_policy = PolicySpec.model_validate(policy_data)
    trusted_policy = TrustedPolicy(
        policy_id="00000000-0000-4000-8000-00000000d512",
        lineage_id=LINEAGE_ID,
        version=1,
        digest=_digest(base_policy),
        definition=base_policy,
        actor_type="BUILTIN",
        created_at=None,
    )

    assurance = AssuranceService(factory, store, clock=lambda: NOW)
    assurance._verified = service._verified
    assurance._intelligence = service
    assurance._delta = SimpleNamespace(evaluate_in_session=lambda *args, **kwargs: delta)
    assurance._lifecycle = SimpleNamespace(
        load_candidate_facts_in_session=lambda *args, **kwargs: (fact,)
    )
    assurance._governance = SimpleNamespace(
        get_many_in_session=lambda *args, **kwargs: (governance,)
    )
    monkeypatch.setattr(
        SourcePolicyService,
        "_current_policy",
        staticmethod(lambda *args, **kwargs: trusted_policy),
    )
    threat_policy = ThreatPolicySpec.model_validate(
        {
            "schema_version": "securescan-threat-policy-v1",
            "kev_introduced": "FAIL",
            "epss_introduced": "FAIL",
            "epss_threshold": 0.4,
            "minimum_priority": "HIGH",
            "require_kev": True,
            "require_epss": True,
            "kev_max_age_seconds": 86_400,
            "epss_max_age_seconds": 172_800,
        }
    )
    first = assurance.evaluate_policy(
        project_id=PROJECT_ID,
        lineage_id=LINEAGE_ID,
        run_id=RUN_ID,
        bundle_id=bundle.bundle_id,
        threat_policy=threat_policy,
        evaluated_at=NOW,
    )
    replay = assurance.evaluate_policy(
        project_id=PROJECT_ID,
        lineage_id=LINEAGE_ID,
        run_id=RUN_ID,
        bundle_id=bundle.bundle_id,
        threat_policy=threat_policy,
        evaluated_at=NOW,
    )
    assert first == replay
    assert first.result == "FAIL"
    assert {item["rule_id"] for item in first.proof["decisions"]} == {
        "INTRODUCED_KEV_LISTED",
        "INTRODUCED_EPSS_THRESHOLD",
    }
    decision = first.proof["decisions"][0]
    assert decision["finding_id"] == dependency.finding_id
    assert decision["cve_id"] == assessments[0].cve_id
    assert decision["assessment_id"] == assessments[0].assessment_id
    assert first.proof["baseline"]["revision"] == 1
    with factory() as session:
        assert len(session.scalars(select(SourcePolicyDecisionProofRow)).all()) == 1

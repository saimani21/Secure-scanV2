from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_unified_evidence_models import _report

from securescan.api.guidance_schemas import FindingGuidanceResponse
from securescan.evidence.models import EvidenceAuthority, UnifiedEvidenceError
from securescan.product_core.guidance import CheckovGuidanceRenderer, GitleaksGuidanceRenderer


def test_gitleaks_renderer_ignores_raw_secret_like_input_and_logs(caplog) -> None:
    report = _report()
    finding = next(item for item in report.findings if item.authority is EvidenceAuthority.GITLEAKS)
    accepted = next(
        item for item in report.evidence if item.evidence_id == finding.primary_evidence_refs[0]
    )
    sentinel = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    hostile = SimpleNamespace(
        authority=EvidenceAuthority.GITLEAKS,
        payload=accepted.payload,
        raw_secret=sentinel,
        raw_match=sentinel,
    )
    guidance = GitleaksGuidanceRenderer().render(
        report.scope.source_run_id, finding, {accepted.evidence_id: hostile}
    )
    body = json.dumps(FindingGuidanceResponse.model_validate(guidance).model_dump(mode="json"))
    assert sentinel not in body
    assert sentinel not in caplog.text


def test_checkov_long_markup_is_data_and_controls_fail_s4_validation() -> None:
    report = _report()
    finding = next(item for item in report.findings if item.authority is EvidenceAuthority.CHECKOV)
    accepted = next(
        item for item in report.evidence if item.evidence_id == finding.primary_evidence_refs[0]
    )
    hostile_name = "<script>alert(1)</script>" * 70
    assert len(hostile_name.encode("utf-8")) <= 2_048
    payload = replace(accepted.payload, check_name=hostile_name)
    guidance = CheckovGuidanceRenderer().render(
        report.scope.source_run_id,
        finding,
        {accepted.evidence_id: replace(accepted, payload=payload)},
    )
    assert guidance.check_name == hostile_name
    assert hostile_name not in guidance.title + guidance.summary
    assert hostile_name not in " ".join(guidance.remediation_steps)
    with pytest.raises(UnifiedEvidenceError):
        replace(accepted.payload, check_name="bad\ncontrol")

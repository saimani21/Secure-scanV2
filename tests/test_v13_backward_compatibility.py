from __future__ import annotations

from securescan.orchestration.models import (
    SourceAuthority,
    SourcePlanningSnapshot,
    TrustedSourceAuthority,
    TrustedSourceAuthorityRoster,
    frozen_source_v1_authority_roster,
)
from securescan.source import (
    AnalysisCapability,
    SourcePlanningPolicy,
    SourceSupportState,
    TrustedSourceAnalyzer,
    TrustedSourceAnalyzerRegistry,
    build_source_analysis_plan,
)
from tests.test_source_planning import _profile_for_capability

_RUN_ID = "78989898-8989-4989-8989-898989898989"


def _v12_roster() -> TrustedSourceAuthorityRoster:
    current = frozen_source_v1_authority_roster()
    values = []
    for authority in current.authorities:
        data = authority.canonical_data()
        if authority.authority is SourceAuthority.SEMGREP:
            data.update(
                analyzer_id="python-semgrep-v1",
                capability=AnalysisCapability.PYTHON_SAST.value,
                contract_digest=(
                    "265fd32e59296d6dc50fd7f8b7558f0e35ead821c4ee689f5ff953bf70393ed2"
                ),
            )
        values.append(
            TrustedSourceAuthority(
                authority=SourceAuthority(data["authority"]),
                capability=AnalysisCapability(data["capability"]),
                analyzer_id=data["analyzer_id"],
                contract_kind=data["contract_kind"],
                contract_digest=data["contract_digest"],
                implementation_version=data["implementation_version"],
            )
        )
    return TrustedSourceAuthorityRoster(tuple(values))


def test_v12_python_sast_planning_snapshot_remains_exactly_decodable() -> None:
    profile = _profile_for_capability(
        AnalysisCapability.PYTHON_SAST,
        SourceSupportState.SCANNABLE,
    )
    plan = build_source_analysis_plan(
        profile,
        TrustedSourceAnalyzerRegistry(
            analyzers=(
                TrustedSourceAnalyzer(
                    "python-semgrep-v1",
                    (AnalysisCapability.PYTHON_SAST,),
                    True,
                ),
            )
        ),
        SourcePlanningPolicy(),
    )
    snapshot = SourcePlanningSnapshot.create(_RUN_ID, profile, plan, _v12_roster())
    encoded = snapshot.canonical_json()

    decoded = SourcePlanningSnapshot.from_json(encoded)

    assert decoded == snapshot
    assert decoded.canonical_json() == encoded
    semgrep = next(node for node in decoded.nodes if node.authority is SourceAuthority.SEMGREP)
    assert semgrep.capability is AnalysisCapability.PYTHON_SAST
    assert semgrep.analyzer_id == "python-semgrep-v1"


def test_v13_current_roster_emits_only_source_sast() -> None:
    roster = frozen_source_v1_authority_roster()
    semgrep = next(
        authority
        for authority in roster.authorities
        if authority.authority is SourceAuthority.SEMGREP
    )

    assert semgrep.capability is AnalysisCapability.SOURCE_SAST
    assert semgrep.analyzer_id == "semgrep-source-v1"
    assert all(
        authority.capability is not AnalysisCapability.PYTHON_SAST
        for authority in roster.authorities
    )

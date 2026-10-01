from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from securescan.api.trusted_baseline_schemas import (
    SecurityDeltaResponse,
    TrustedBaselineStateResponse,
)
from securescan.cli import main as cli_main
from securescan.product_core import (
    SecurityDelta,
    SecurityDeltaAuthoritySummary,
    SecurityDeltaComparisonStatus,
    SecurityDeltaFinding,
    SecurityDeltaState,
    TrustedBaseline,
    TrustedBaselineState,
)

_PROJECT = "11111111-1111-4111-8111-111111111111"
_LINEAGE = "22222222-2222-4222-8222-222222222222"
_RUN = "33333333-3333-4333-8333-333333333333"
_BASELINE = "44444444-4444-4444-8444-444444444444"
_FINDING = "a" * 64


def _state() -> TrustedBaselineState:
    return TrustedBaselineState(
        lineage_id=_LINEAGE,
        revision=1,
        baseline=TrustedBaseline(
            baseline_id=_BASELINE,
            lineage_id=_LINEAGE,
            run_id=_RUN,
            run_sequence_number=1,
            revision=1,
            actor_type="LOCAL_OPERATOR",
            promoted_at=datetime(2026, 10, 1, tzinfo=UTC),
        ),
    )


def _delta() -> SecurityDelta:
    return SecurityDelta(
        baseline_id=_BASELINE,
        baseline_run_id=_RUN,
        baseline_revision=1,
        baseline_sequence_number=1,
        candidate_run_id=_RUN,
        candidate_sequence_number=2,
        comparison_status=SecurityDeltaComparisonStatus.PARTIAL,
        authority_summaries=(
            SecurityDeltaAuthoritySummary(
                authority="osv.dev",
                comparison_status=SecurityDeltaComparisonStatus.NOT_COMPARABLE,
                introduced_count=0,
                present_count=0,
                removed_count=0,
                not_comparable_count=1,
                reason_codes=("AUTHORITY_CONTRACT_MISMATCH",),
            ),
        ),
        findings=(
            SecurityDeltaFinding(
                finding_id=_FINDING,
                authority="osv.dev",
                category="DEPENDENCY_VULNERABILITY",
                state=SecurityDeltaState.NOT_COMPARABLE,
                reason_codes=("AUTHORITY_CONTRACT_MISMATCH",),
            ),
        ),
    )


def test_assurance_cli_json_matches_frozen_api_shapes_and_requires_explicit_promotion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    baseline = SimpleNamespace(
        get_current=lambda **kw: (calls.append(("show", kw)), _state())[1],
        promote=lambda **kw: (calls.append(("promote", kw)), _state().baseline)[1],
    )
    delta = SimpleNamespace(evaluate=lambda **kw: (calls.append(("delta", kw)), _delta())[1])

    @contextmanager
    def factory():
        yield SimpleNamespace(
            queries=SimpleNamespace(
                get_scan=lambda run: SimpleNamespace(
                    run_id=run, project_id=_PROJECT, lineage_id=_LINEAGE
                )
            ),
            baseline=baseline,
            delta=delta,
        )

    monkeypatch.setattr(cli_main, "create_source_cli_services", factory)
    runner = CliRunner()
    shown = runner.invoke(cli_main.app, ["baseline", "show", _RUN, "--json"])
    compared = runner.invoke(cli_main.app, ["delta", _RUN, "--json"])
    assert shown.exit_code == compared.exit_code == 0, (shown.stdout, compared.stdout)
    assert json.loads(shown.stdout) == TrustedBaselineStateResponse.model_validate(
        _state()
    ).model_dump(mode="json")
    assert json.loads(compared.stdout) == SecurityDeltaResponse.model_validate(
        _delta()
    ).model_dump(mode="json")
    assert json.loads(compared.stdout)["findings"][0]["state"] == "NOT_COMPARABLE"
    assert not any(kind == "promote" for kind, _ in calls)
    promoted = runner.invoke(
        cli_main.app,
        ["baseline", "promote", _RUN, "--expected-revision", "0", "--json"],
    )
    assert promoted.exit_code == 0, promoted.stdout
    assert json.loads(promoted.stdout)["baseline_id"] == _BASELINE
    assert calls[-1] == (
        "promote",
        {
            "project_id": _PROJECT,
            "lineage_id": _LINEAGE,
            "run_id": _RUN,
            "expected_revision": 0,
        },
    )


def test_baseline_promotion_requires_revision_option() -> None:
    result = CliRunner().invoke(cli_main.app, ["baseline", "promote", _RUN, "--json"])
    assert result.exit_code == 2

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from securescan.cli import main as cli_main
from securescan.product_core import (
    PolicyDecision,
    PolicyDecisionKind,
    PolicyEvaluation,
    PolicyResult,
)

_RUN = "88888888-8888-4888-8888-888888888881"
_PROJECT = "88888888-8888-4888-8888-888888888882"
_LINEAGE = "88888888-8888-4888-8888-888888888883"


def _evaluation(result: PolicyResult) -> PolicyEvaluation:
    kind = {
        PolicyResult.PASS: PolicyDecisionKind.WARNING,
        PolicyResult.FAIL: PolicyDecisionKind.VIOLATION,
        PolicyResult.ERROR: PolicyDecisionKind.ERROR,
    }[result]
    return PolicyEvaluation(
        evaluation_id="88888888-8888-4888-8888-888888888884",
        lineage_id=_LINEAGE,
        candidate_run_id=_RUN,
        baseline_id=None,
        baseline_revision=None,
        policy_id="88888888-8888-4888-8888-888888888885",
        policy_version=3,
        policy_digest="d" * 64,
        result=result,
        decisions=(
            PolicyDecision(
                kind=kind,
                rule_id="TEST_RULE",
                reason_code="TEST_REASON",
            ),
        ),
        evaluated_at=datetime(2026, 10, 1, tzinfo=UTC),
    )


@pytest.mark.parametrize(
    ("policy_result", "exit_code"),
    [
        (PolicyResult.PASS, 0),
        (PolicyResult.FAIL, 1),
        (PolicyResult.ERROR, 5),
    ],
)
def test_explicit_policy_cli_uses_frozen_decision_and_exit_contract(
    monkeypatch: pytest.MonkeyPatch, policy_result: PolicyResult, exit_code: int
) -> None:
    calls: list[dict[str, str]] = []

    @contextmanager
    def factory():
        yield SimpleNamespace(
            queries=SimpleNamespace(
                get_scan=lambda run_id: SimpleNamespace(
                    run_id=run_id, project_id=_PROJECT, lineage_id=_LINEAGE
                )
            ),
            policy=SimpleNamespace(
                evaluate=lambda **kwargs: (
                    calls.append(kwargs), _evaluation(policy_result)
                )[1]
            ),
        )

    monkeypatch.setattr(cli_main, "create_source_cli_services", factory)
    result = CliRunner().invoke(cli_main.app, ["policy", "evaluate", _RUN, "--json"])
    assert result.exit_code == exit_code
    assert calls == [
        {
            "project_id": _PROJECT,
            "lineage_id": _LINEAGE,
            "candidate_run_id": _RUN,
        }
    ]
    payload = json.loads(result.stdout)
    assert payload["result"] == policy_result.value
    assert payload["candidate_run_id"] == _RUN
    assert payload["decisions"][0]["kind"] == _evaluation(policy_result).decisions[0].kind.value
    assert payload["baseline_id"] is None


def test_policy_cli_rejects_invalid_run_before_evaluation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextmanager
    def factory():
        yield SimpleNamespace(queries=SimpleNamespace(get_scan=lambda _run: pytest.fail("queried")))

    monkeypatch.setattr(cli_main, "create_source_cli_services", factory)
    result = CliRunner().invoke(cli_main.app, ["policy", "evaluate", "../../etc", "--json"])
    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "SCAN_NOT_FOUND"

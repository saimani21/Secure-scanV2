from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from securescan.cli import main as cli_main
from securescan.product_core.guidance import FindingGuidance, GuidanceBasis

_RUN = "99999999-9999-4999-8999-999999999991"
_PROJECT = "99999999-9999-4999-8999-999999999992"
_LINEAGE = "99999999-9999-4999-8999-999999999993"
_FINDING = "a" * 64


def _guidance() -> FindingGuidance:
    return FindingGuidance(
        run_id=_RUN,
        finding_id=_FINDING,
        authority="gitleaks",
        basis_level=GuidanceBasis.FAMILY,
        title="Secret <script> alert",
        summary="Accepted evidence only; no credential validity claim.",
        remediation_steps=("Review source exposure.",),
        verification_steps=("Rerun Gitleaks with comparable coverage.",),
        limitations=("Source absence does not prove external revocation.",),
        evidence_refs=("b" * 64,),
        locations=({"kind": "REPOSITORY_PATH", "path": "src/<script>.txt"},),
    )


def test_guidance_cli_exact_run_json_and_human_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, str]] = []

    @contextmanager
    def factory():
        yield SimpleNamespace(
            queries=SimpleNamespace(
                get_scan=lambda run_id: SimpleNamespace(
                    run_id=run_id, project_id=_PROJECT, lineage_id=_LINEAGE
                )
            ),
            guidance=SimpleNamespace(
                get_for_run=lambda **kwargs: (calls.append(kwargs), _guidance())[1]
            ),
        )

    monkeypatch.setattr(cli_main, "create_source_cli_services", factory)
    runner = CliRunner()
    machine = runner.invoke(cli_main.app, ["finding", "guidance", _RUN, _FINDING, "--json"])
    human = runner.invoke(cli_main.app, ["finding", "guidance", _RUN, _FINDING])
    assert machine.exit_code == 0
    assert human.exit_code == 0
    assert calls == [
        dict(project_id=_PROJECT, lineage_id=_LINEAGE, run_id=_RUN, finding_id=_FINDING)
    ] * 2
    payload = json.loads(machine.stdout)
    assert payload["basis_level"] == "FAMILY"
    assert payload["locations"][0]["path"] == "src/<script>.txt"
    assert "FAMILY" in human.stdout
    assert "Source absence does not prove external revocation." in human.stdout


def test_guidance_cli_rejects_malformed_finding_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "create_source_cli_services",
        lambda: pytest.fail("service context must not open"),
    )
    result = CliRunner().invoke(
        cli_main.app, ["finding", "guidance", _RUN, "../../etc", "--json"]
    )
    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "INVALID_FINDING_ID"

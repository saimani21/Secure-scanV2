from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from securescan.cli import ci as ci_module
from securescan.cli import main as cli_main
from securescan.product_core import SourceProductStatus

PROJECT_ID = "00000000-0000-4000-8000-00000000c501"
LINEAGE_ID = "00000000-0000-4000-8000-00000000c502"
RUN_ID = "00000000-0000-4000-8000-00000000c503"


def _files() -> dict[str, bytes]:
    return {
        "assessment.html": b"assessment",
        "ci-result.json": b"{}\n",
        "decision-proof.json": b"{}\n",
        "results.sarif": b"{}\n",
        "sbom.cdx.json": b"{}\n",
        "summary.md": b"summary\n",
    }


def _install_controlled_flow(monkeypatch: pytest.MonkeyPatch, decision: str, exit_code: int):
    services = SimpleNamespace(
        default_deadline_seconds=1_800,
        clock=lambda: datetime(2026, 10, 3, tzinfo=UTC),
    )

    @contextmanager
    def factory():
        yield services

    monkeypatch.setattr(cli_main, "create_source_cli_services", factory)
    monkeypatch.setattr(
        ci_module,
        "submit_local_scan",
        lambda *_args, **_kwargs: SimpleNamespace(submission=SimpleNamespace(run_id=RUN_ID)),
    )
    monkeypatch.setattr(
        ci_module,
        "wait_for_scan",
        lambda *_args, **_kwargs: SimpleNamespace(
            project_id=PROJECT_ID,
            lineage_id=LINEAGE_ID,
            run_id=RUN_ID,
            product_status=SourceProductStatus.COMPLETED,
        ),
    )
    monkeypatch.setattr(
        ci_module,
        "build_ci_artifacts",
        lambda *_args, **_kwargs: (
            _files(),
            {
                "decision": decision,
                "exit_code": exit_code,
                "candidate_run_id": RUN_ID,
                "project_id": PROJECT_ID,
            },
        ),
    )


@pytest.mark.parametrize("decision,exit_code", [("PASS", 0), ("FAIL", 1), ("ERROR", 2)])
def test_ci_command_preserves_decision_exit_and_atomic_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    decision: str,
    exit_code: int,
) -> None:
    _install_controlled_flow(monkeypatch, decision, exit_code)
    repository = tmp_path / "repository with spaces Ω"
    repository.mkdir()
    policy = tmp_path / "policy.json"
    policy.write_text('{"schema_version":"securescan-threat-policy-v1"}', encoding="utf-8")
    output = tmp_path / "result"
    result = CliRunner().invoke(
        cli_main.app,
        [
            "ci",
            str(repository),
            "--project-id",
            PROJECT_ID,
            "--bundle-id",
            "a" * 64,
            "--policy",
            str(policy),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == exit_code, result.output
    payload = json.loads(result.stdout)
    assert payload["decision"] == decision
    assert payload["exit_code"] == exit_code
    assert set(item.name for item in output.iterdir()) == set(_files())


def test_ci_command_interrupt_does_not_emit_false_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_controlled_flow(monkeypatch, "PASS", 0)
    monkeypatch.setattr(
        ci_module,
        "wait_for_scan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt),
    )
    repository = tmp_path / "repository"
    repository.mkdir()
    policy = tmp_path / "policy.json"
    policy.write_text('{"schema_version":"securescan-threat-policy-v1"}', encoding="utf-8")
    output = tmp_path / "result"
    result = CliRunner().invoke(
        cli_main.app,
        [
            "ci",
            str(repository),
            "--project-id",
            PROJECT_ID,
            "--bundle-id",
            "a" * 64,
            "--policy",
            str(policy),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 130
    assert "CI_INTERRUPTED" in result.stderr
    assert not output.exists()

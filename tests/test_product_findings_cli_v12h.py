from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace
from uuid import UUID

import pytest
from typer.testing import CliRunner

from securescan.api.product_view_routes import list_run_product_findings
from securescan.cli import main as cli_main
from securescan.product_core.product_view import FindingProductPage, FindingProductView

_PROJECT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
_LINEAGE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"
_RUN = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3"
_FINDING = "b" * 64


def _page() -> FindingProductPage:
    return FindingProductPage(
        items=(
            FindingProductView(
                project_id=_PROJECT,
                lineage_id=_LINEAGE,
                run_id=_RUN,
                finding_id=_FINDING,
                authority="gitleaks",
                category="SECRET_EXPOSURE",
                severity=None,
                priority_band="HIGH",
                priority_reason_codes=("SECRET_EXPOSURE",),
                subject={"kind": "SECRET_EXPOSURE", "rule_id": "<script>"},
                primary_location={"kind": "REPOSITORY_PATH", "path": "src/x.py"},
                lifecycle_state_at_run="REOPENED",
                lifecycle_event_kind="TRANSITION",
                lifecycle_transition_version=3,
                lifecycle_reason_codes=("REAPPEARED",),
            ),
        ),
        total=1,
        limit=50,
        offset=0,
    )


def test_explicit_cli_api_exact_run_finding_truth_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def list_for_run(**kwargs):
        calls.append(kwargs)
        return _page()

    @contextmanager
    def factory():
        yield SimpleNamespace(
            queries=SimpleNamespace(
                get_scan=lambda run_id: SimpleNamespace(
                    run_id=run_id, project_id=_PROJECT, lineage_id=_LINEAGE
                )
            ),
            product_findings=SimpleNamespace(list_for_run=list_for_run),
        )

    monkeypatch.setattr(cli_main, "create_source_cli_services", factory)
    cli = CliRunner().invoke(cli_main.app, ["findings", _RUN, "--exact-run", "--json"])
    assert cli.exit_code == 0
    api = list_run_product_findings(
        UUID(_PROJECT), UUID(_LINEAGE), UUID(_RUN), SimpleNamespace(list_for_run=list_for_run)
    )
    cli_item = json.loads(cli.stdout)["items"][0]
    api_item = api.model_dump(mode="json")["items"][0]
    assert cli_item == api_item
    assert cli_item["lifecycle_state_at_run"] == "REOPENED"
    assert cli_item["priority_band"] == "HIGH"
    assert cli_item["subject"]["rule_id"] == "<script>"
    assert len(calls) == 2
    assert all(call["project_id"] == _PROJECT and call["lineage_id"] == _LINEAGE for call in calls)

"""Cross-layer hostile acceptance probes for published Source product truth."""

from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from securescan.api.product_view_routes import router as product_view_router
from securescan.api.source_scan_routes import router as source_scan_router
from securescan.cli import main as cli_main
from securescan.cli.sarif import build_sarif_bytes
from securescan.cli.source import SourceCliError
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceFindingLifecycleRow,
    SourceLineageRunRow,
    SourceScanSubmissionRow,
    TargetRow,
)
from securescan.product_core.product_view import (
    ProductViewUnavailableError,
    SourceFindingProductViewService,
)
from securescan.product_core.query import SourceScanQueryService
from tests.test_source_orchestration_s6b import _CONTROLLED_SECRET, _RUN_ID
from tests.test_source_product_core_pc2 import _RUN_IDS, _add_run

pytest_plugins = ("test_source_governance_v12b", "test_source_product_core_pc2")


@pytest.mark.parametrize("attack", ("missing", "truncated", "digest-mismatch"))
def test_exact_run_product_view_rejects_published_s4_artifact_tampering(
    governance_context, attack: str
) -> None:
    environment, _governance, project_id, lineage_id, finding_id = governance_context
    with environment.factory() as session:
        lifecycle = session.get(SourceFindingLifecycleRow, (lineage_id, finding_id))
        assert lifecycle is not None
        run_id = lifecycle.first_seen_run_id
        membership = session.get(SourceLineageRunRow, run_id)
        assert membership is not None
        digest = membership.report_artifact_sha256
        assert digest is not None
    artifact = environment.store.root / "sha256" / digest[:2] / digest
    original = artifact.read_bytes()

    assert len(original) > 2
    service = SourceFindingProductViewService(environment.factory, environment.store)
    assert (
        service.list_for_run(project_id=project_id, lineage_id=lineage_id, run_id=run_id).total == 1
    )
    if attack == "missing":
        artifact.unlink()
    elif attack == "truncated":
        artifact.write_bytes(original[: len(original) // 2])
    else:
        artifact.write_bytes(b"x" * len(original))

    with pytest.raises(ProductViewUnavailableError):
        service.list_for_run(project_id=project_id, lineage_id=lineage_id, run_id=run_id)


@pytest.mark.parametrize(
    "attack", ("missing", "truncated", "digest-mismatch", "unreadable", "schema-invalid")
)
def test_published_s4_tampering_fails_closed_on_public_finding_and_export_surfaces(
    governance_context, monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    environment, _governance, project_id, lineage_id, finding_id = governance_context
    with environment.factory() as session:
        lifecycle = session.get(SourceFindingLifecycleRow, (lineage_id, finding_id))
        assert lifecycle is not None
        run_id = lifecycle.first_seen_run_id
        membership = session.get(SourceLineageRunRow, run_id)
        assert membership is not None and membership.report_artifact_sha256 is not None
        digest = membership.report_artifact_sha256
    artifact = environment.store.root / "sha256" / digest[:2] / digest
    original = artifact.read_bytes()

    # The Product Core fixture predates the scan-submission/query transport.
    # Complete only that transport metadata for these public-surface probes.
    with environment.factory.begin() as session:
        run = session.get(AnalysisRunRow, run_id)
        assert run is not None
        target = session.get(TargetRow, run.target_id)
        assert target is not None
        target.source_path = f"securescan-workspace-{run_id}"
        session.add(
            SourceScanSubmissionRow(
                run_id=run_id,
                lineage_id=lineage_id,
                submission_sequence_number=1,
                predecessor_run_id=None,
                predecessor_sequence_number=None,
                intake_kind="MANAGED_WORKSPACE_V1",
                intake_ref=target.source_path,
                created_at=run.created_at,
                finalized_at=membership.lifecycle_evaluated_at,
            )
        )

    queries = SourceScanQueryService(environment.factory, environment.store)
    product_findings = SourceFindingProductViewService(environment.factory, environment.store)
    services = SimpleNamespace(queries=queries, product_findings=product_findings)
    assert queries.list_findings(run_id).total == 1
    assert queries.get_report(run_id).run_id == run_id
    assert (
        product_findings.list_for_run(
            project_id=project_id, lineage_id=lineage_id, run_id=run_id
        ).total
        == 1
    )

    app = FastAPI()
    app.include_router(product_view_router)
    app.include_router(source_scan_router)
    app.state.source_finding_product_view_service = product_findings
    app.state.source_scan_query_service = queries
    client = TestClient(app)

    @contextmanager
    def service_factory():
        yield services

    monkeypatch.setattr(cli_main, "create_source_cli_services", service_factory)
    if attack == "missing":
        artifact.unlink()
    elif attack == "truncated":
        artifact.write_bytes(original[: len(original) // 2])
    elif attack == "unreadable":
        artifact.unlink()
        artifact.mkdir()
    elif attack == "schema-invalid":
        artifact.write_bytes(b"{" + b" " * (len(original) - 1))
    else:
        artifact.write_bytes(b"x" * len(original))

    scoped_path = f"/v1/projects/{project_id}/lineages/{lineage_id}/runs/{run_id}/findings"
    for path, code in (
        (scoped_path, "PRODUCT_VIEW_UNAVAILABLE"),
        (f"/v1/scans/{run_id}/findings", "QUERY_UNAVAILABLE"),
        (f"/v1/scans/{run_id}/report", "QUERY_UNAVAILABLE"),
    ):
        response = client.get(path)
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == code
        assert "items" not in response.json()
        assert "traceback" not in response.text.lower()
        assert _CONTROLLED_SECRET.decode() not in response.text

    for arguments, code in (
        # CLI first loads scan status, which itself verifies the published S4.
        (["findings", run_id, "--exact-run", "--json"], "QUERY_UNAVAILABLE"),
        (["findings", run_id, "--json"], "QUERY_UNAVAILABLE"),
        (["report", run_id, "--json"], "QUERY_UNAVAILABLE"),
    ):
        result = CliRunner().invoke(cli_main.app, arguments)
        assert result.exit_code == 5
        assert json.loads(result.stderr)["error"]["code"] == code
        assert "items" not in result.stdout
        assert "traceback" not in result.output.lower()
        assert _CONTROLLED_SECRET.decode() not in result.output

    with pytest.raises(SourceCliError) as sarif_error:
        build_sarif_bytes(services, run_id)
    assert sarif_error.value.exit_code == 5
    assert sarif_error.value.code in {"QUERY_UNAVAILABLE", "SARIF_INTEGRITY_FAILURE"}
    sarif_cli = CliRunner().invoke(cli_main.app, ["sarif", run_id, "--output", "-"])
    assert sarif_cli.exit_code == 5
    assert sarif_cli.stdout == ""
    assert json.loads(sarif_cli.stderr)["error"]["code"] == "QUERY_UNAVAILABLE"
    assert "traceback" not in sarif_cli.output.lower()
    assert _CONTROLLED_SECRET.decode() not in sarif_cli.output


def test_valid_empty_published_s4_has_zero_exact_run_findings(
    pc2_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment, _index, lifecycle, lineage, reports = pc2_context
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    empty_run = _RUN_IDS[0]
    empty_report = _add_run(pc2_context, monkeypatch, empty_run, present=False, ordinal=2)
    assert empty_report.findings == ()
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=empty_run)
    service = SourceFindingProductViewService(environment.factory, environment.store)
    # This historical fixture clones a published run and supplies its trusted
    # report through the same test override used at indexing time.
    monkeypatch.setattr(service._index, "_rebuild_trusted_report", reports.__getitem__)
    page = service.list_for_run(
        project_id=lineage.project_id, lineage_id=lineage.lineage_id, run_id=empty_run
    )
    assert page.total == 0
    assert page.items == ()


def test_later_valid_run_cannot_substitute_for_corrupted_historical_s4(
    pc2_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment, _index, lifecycle, lineage, reports = pc2_context
    first_run = str(_RUN_ID)
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=first_run)
    later_run = _RUN_IDS[0]
    _add_run(pc2_context, monkeypatch, later_run, present=True, ordinal=2)
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=later_run)
    service = SourceFindingProductViewService(environment.factory, environment.store)
    monkeypatch.setattr(service._index, "_rebuild_trusted_report", reports.__getitem__)
    assert (
        service.list_for_run(
            project_id=lineage.project_id, lineage_id=lineage.lineage_id, run_id=first_run
        ).total
        == 1
    )
    assert (
        service.list_for_run(
            project_id=lineage.project_id, lineage_id=lineage.lineage_id, run_id=later_run
        ).total
        == 1
    )
    with environment.factory() as session:
        membership = session.get(SourceLineageRunRow, first_run)
        assert membership is not None and membership.report_artifact_sha256 is not None
        digest = membership.report_artifact_sha256
    artifact = environment.store.root / "sha256" / digest[:2] / digest
    artifact.unlink()
    with pytest.raises(ProductViewUnavailableError):
        service.list_for_run(
            project_id=lineage.project_id, lineage_id=lineage.lineage_id, run_id=first_run
        )
    assert (
        service.list_for_run(
            project_id=lineage.project_id, lineage_id=lineage.lineage_id, run_id=later_run
        ).total
        == 1
    )

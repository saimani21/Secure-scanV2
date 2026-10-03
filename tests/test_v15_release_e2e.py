from __future__ import annotations

import json
import shutil
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from sqlalchemy import func, select
from typer.testing import CliRunner

from securescan import source_runtime
from securescan.cli import ci as ci_module
from securescan.cli import main as cli_main
from securescan.cli.source import create_source_cli_services
from securescan.config import get_settings
from securescan.orchestration.osv_runtime import (
    SourceOsvHelperExecutionService as ProductionOsvHelper,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceFindingLifecycleRow,
    SourcePolicyDecisionProofRow,
    SourceThreatAssessmentRow,
)
from securescan.product_core import SourceProductStatus
from securescan.product_core.policy import DEFAULT_POLICY
from tests.test_intelligence_v15 import epss_payload, kev_payload, nvd_payload

ROOT = Path(__file__).resolve().parents[1]
CVE = "CVE-2025-12345"


def _json_command(runner: CliRunner, arguments: list[str], *allowed: int) -> dict:
    result = runner.invoke(cli_main.app, arguments)
    assert result.exit_code in (allowed or (0,)), result.output
    return json.loads(result.stdout)


def _repository(root: Path) -> Path:
    repository = root / "controlled release repository Ω"
    (repository / "infra").mkdir(parents=True)
    (repository / "app.py").write_text("def add(left, right):\n    return left + right\n")
    (repository / "requirements.txt").write_text("requests==2.31.0\n")
    shutil.copyfile(
        ROOT / "benchmarks/checkov/corpus/terraform/pass/main.tf",
        repository / "infra/main.tf",
    )
    return repository


@contextmanager
def _controlled_osv():
    modified = "2026-10-02T00:00:00Z"

    class Handler(BaseHTTPRequestHandler):
        def _send(self, document: object) -> None:
            payload = json.dumps(document, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:  # noqa: N802
            assert self.path == "/v1/querybatch"
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            results = []
            for query in body["queries"]:
                package = query.get("package", {})
                name = str(package.get("name", "")).casefold()
                purl = str(package.get("purl", "")).casefold()
                vulnerable = name == "pyyaml" or "/pyyaml@5.3.1" in purl
                results.append(
                    {"vulns": [{"id": "PYSEC-2025-1", "modified": modified}]} if vulnerable else {}
                )
            self._send({"results": results})

        def do_GET(self) -> None:  # noqa: N802
            assert self.path == "/v1/vulns/PYSEC-2025-1"
            self._send(
                {
                    "schema_version": "1.7.3",
                    "id": "PYSEC-2025-1",
                    "modified": modified,
                    "aliases": [CVE],
                    "summary": "Controlled exact-pinned dependency vulnerability",
                    "affected": [
                        {
                            "package": {
                                "ecosystem": "PyPI",
                                "name": "pyyaml",
                                "purl": "pkg:pypi/pyyaml",
                            },
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "6.0.2"},
                                    ],
                                }
                            ],
                        }
                    ],
                }
            )

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _complete(runner: CliRunner, run_id: str) -> dict:
    for _ in range(12):
        _json_command(runner, ["worker", "--once", "--json"])
        status = _json_command(runner, ["status", run_id, "--json"])
        if status["product_status"] == "COMPLETED":
            return status
    raise AssertionError("scan did not complete in 12 bounded cycles")


def _inline_worker_wait(services, run_id: str, **_kwargs):
    for _ in range(12):
        with source_runtime.create_source_runtime() as composition:
            composition.runtime.run_once()
        summary = services.queries.get_scan(run_id)
        if summary.product_status is SourceProductStatus.COMPLETED:
            return summary
    raise AssertionError("CI scan did not complete in 12 bounded cycles")


def test_v15_real_scanner_ci_remediation_and_intelligence_only_reassessment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _repository(tmp_path)
    data = tmp_path / "data"
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(tmp_path / "no-profile.json"))
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", f"sqlite:///{data / 'securescan.db'}")
    monkeypatch.setenv("SECURESCAN_ARTIFACT_ROOT", str(data / "artifacts"))
    monkeypatch.setenv("SECURESCAN_SOURCE_WORKSPACE_ROOT", str(data / "workspaces"))
    monkeypatch.setenv("SECURESCAN_SOURCE_PROJECTION_ROOT", str(data / "projections"))
    monkeypatch.setenv("SECURESCAN_SOURCE_RUNTIME_RECEIPT_ROOT", str(data / "receipts"))
    monkeypatch.setenv("SECURESCAN_ALLOW_SQLITE_SCHEMA_BOOTSTRAP", "true")
    get_settings.cache_clear()

    runner = CliRunner()
    initialized = runner.invoke(cli_main.app, ["init"])
    assert initialized.exit_code == 0, initialized.output

    with _controlled_osv() as base_url:

        def controlled_helper(*args, **kwargs):
            kwargs["loopback_test_base_url"] = base_url
            return ProductionOsvHelper(*args, **kwargs)

        monkeypatch.setattr(source_runtime, "SourceOsvHelperExecutionService", controlled_helper)
        project = _json_command(runner, ["project", "create", "v15-release-e2e", "--json"])

        baseline = _json_command(
            runner,
            ["scan", str(repository), "--project-id", project["project_id"], "--json"],
        )
        baseline_status = _complete(runner, baseline["run_id"])
        assert baseline_status["coverage_complete"] is True
        promoted = _json_command(
            runner,
            [
                "baseline",
                "promote",
                baseline["run_id"],
                "--expected-revision",
                "0",
                "--json",
            ],
        )

        with create_source_cli_services() as services:
            assert services.intelligence is not None
            assert services.policy is not None
            base_policy = DEFAULT_POLICY.model_dump(mode="json")
            base_policy["required_authorities"] = ["gitleaks", "osv.dev", "semgrep-ce"]
            services.policy.update_policy(
                project_id=project["project_id"],
                lineage_id=baseline["lineage_id"],
                expected_version=1,
                definition=base_policy,
            )
            kev = services.intelligence.import_kev(kev_payload())
            epss = services.intelligence.import_epss(epss_payload())
            nvd = services.intelligence.import_nvd(nvd_payload(), expected_cve=CVE)
            bundle = services.intelligence.create_bundle(
                kev_snapshot_id=kev.snapshot_id,
                epss_snapshot_id=epss.snapshot_id,
                nvd_enrichment_ids=(nvd.enrichment_id,),
            )

        policy = tmp_path / "threat-policy.json"
        policy.write_text(
            json.dumps(
                {
                    "schema_version": "securescan-threat-policy-v1",
                    "kev_introduced": "FAIL",
                    "epss_introduced": "FAIL",
                    "epss_threshold": 0.4,
                    "minimum_priority": "UNRANKED",
                    "require_kev": True,
                    "require_epss": True,
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(ci_module, "wait_for_scan", _inline_worker_wait)

        with (repository / "requirements.txt").open("a", encoding="utf-8") as stream:
            stream.write("PyYAML==5.3.1\n")
        fail_output = tmp_path / "candidate-fail"
        failed = runner.invoke(
            cli_main.app,
            [
                "ci",
                str(repository),
                "--project-id",
                project["project_id"],
                "--lineage-id",
                baseline["lineage_id"],
                "--bundle-id",
                bundle.bundle_id,
                "--policy",
                str(policy),
                "--output",
                str(fail_output),
                "--poll-seconds",
                "0.1",
            ],
        )
        assert failed.exit_code == 1, failed.output
        fail_result = json.loads(failed.stdout)
        assert fail_result["decision"] == "FAIL" and fail_result["exit_code"] == 1
        assert fail_result["baseline_id"] == promoted["baseline_id"]
        assert fail_result["delta_summary"]["INTRODUCED"] >= 1
        assert fail_result["threat_summary"]["kev_listed"] >= 1
        assert set(path.name for path in fail_output.iterdir()) == {
            "assessment.html",
            "ci-result.json",
            "decision-proof.json",
            "results.sarif",
            "sbom.cdx.json",
            "summary.md",
        }
        assert json.loads((fail_output / "ci-result.json").read_text())["decision"] == "FAIL"
        assert json.loads((fail_output / "decision-proof.json").read_text())["result"] == "FAIL"
        sarif = json.loads((fail_output / "results.sarif").read_text())
        assert sarif["version"] == "2.1.0" and sarif["runs"]
        sbom = json.loads((fail_output / "sbom.cdx.json").read_text())
        assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.7"
        assert "SecureScan Security Assessment" in (fail_output / "assessment.html").read_text()

        candidate_run_id = fail_result["candidate_run_id"]
        before_reassessment = _json_command(runner, ["status", candidate_run_id, "--json"])
        first_assessments = _json_command(
            runner,
            [
                "intel",
                "evaluate",
                candidate_run_id,
                "--project",
                project["project_id"],
                "--lineage",
                baseline["lineage_id"],
                "--bundle",
                bundle.bundle_id,
            ],
        )
        (repository / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
        pass_output = tmp_path / "candidate-pass"
        passed = runner.invoke(
            cli_main.app,
            [
                "ci",
                str(repository),
                "--project-id",
                project["project_id"],
                "--lineage-id",
                baseline["lineage_id"],
                "--bundle-id",
                bundle.bundle_id,
                "--policy",
                str(policy),
                "--output",
                str(pass_output),
                "--poll-seconds",
                "0.1",
            ],
        )
        assert passed.exit_code == 0, passed.output
        pass_result = json.loads(passed.stdout)
        assert pass_result["decision"] == "PASS" and pass_result["exit_code"] == 0
        assert pass_result["delta_summary"]["INTRODUCED"] == 0
        assert pass_result["delta_summary"]["REMOVED"] == 0
        baseline_after = _json_command(
            runner, ["baseline", "show", pass_result["candidate_run_id"], "--json"]
        )
        assert baseline_after["revision"] == 1
        assert baseline_after["baseline"]["run_id"] == baseline["run_id"]

        with create_source_cli_services() as services:
            assert services.intelligence is not None
            later_epss = services.intelligence.import_epss(epss_payload(score="0.73"))
            newer_bundle = services.intelligence.create_bundle(
                kev_snapshot_id=kev.snapshot_id,
                epss_snapshot_id=later_epss.snapshot_id,
                nvd_enrichment_ids=(nvd.enrichment_id,),
            )
        second_assessments = _json_command(
            runner,
            [
                "intel",
                "evaluate",
                candidate_run_id,
                "--project",
                project["project_id"],
                "--lineage",
                baseline["lineage_id"],
                "--bundle",
                newer_bundle.bundle_id,
            ],
        )
        second_proof = _json_command(
            runner,
            [
                "intel",
                "policy-proof",
                candidate_run_id,
                "--project",
                project["project_id"],
                "--lineage",
                baseline["lineage_id"],
                "--bundle",
                newer_bundle.bundle_id,
                "--policy",
                str(policy),
            ],
        )
        after_reassessment = _json_command(runner, ["status", candidate_run_id, "--json"])
        assert after_reassessment == before_reassessment
        assert first_assessments[0]["finding_id"] == second_assessments[0]["finding_id"]
        assert first_assessments[0]["assessment_id"] != second_assessments[0]["assessment_id"]
        assert fail_result["policy_decision_proof_id"] != second_proof["proof_id"]

        with create_source_cli_services() as services:
            session_factory = services.intelligence._sessions
            with session_factory() as session:
                run_count = session.scalar(select(func.count()).select_from(AnalysisRunRow))
                assessment_count = session.scalar(
                    select(func.count()).select_from(SourceThreatAssessmentRow)
                )
                proof_count = session.scalar(
                    select(func.count()).select_from(SourcePolicyDecisionProofRow)
                )
                lifecycle = session.get(
                    SourceFindingLifecycleRow,
                    (baseline["lineage_id"], first_assessments[0]["finding_id"]),
                )
        assert run_count == 3
        assert assessment_count >= 2
        assert proof_count >= 3
        assert lifecycle is not None
        assert lifecycle.current_state == "RESOLVED"
        assert lifecycle.resolved_run_id == pass_result["candidate_run_id"]

    shutil.rmtree(data, ignore_errors=True)
    get_settings.cache_clear()

from __future__ import annotations

import json
import shutil
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from securescan import source_runtime
from securescan.api.main import app
from securescan.cli import main as cli_main
from securescan.config import get_settings
from securescan.orchestration.osv_runtime import (
    SourceOsvHelperExecutionService as ProductionOsvHelper,
)

ROOT = Path(__file__).resolve().parents[1]


def _json_command(runner: CliRunner, arguments: list[str], *allowed: int) -> dict:
    result = runner.invoke(cli_main.app, arguments)
    assert result.exit_code in (allowed or (0,)), result.output
    assert "ghp_" not in result.output.lower()
    return json.loads(result.stdout)


def _prepare_repository(root: Path) -> Path:
    repository = root / "mixed-repository"
    (repository / "app").mkdir(parents=True)
    (repository / "frontend").mkdir()
    (repository / "infra").mkdir()
    (repository / "config").mkdir()
    shutil.copyfile(
        ROOT / "tests/fixtures/semgrep/rules/python/dangerous-eval/vulnerable.py",
        repository / "app/insecure_eval.py",
    )
    shutil.copyfile(
        ROOT / "tests/fixtures/source_v1_acceptance/Pipfile.lock",
        repository / "Pipfile.lock",
    )
    shutil.copyfile(
        ROOT / "benchmarks/checkov/corpus/terraform/fail/main.tf",
        repository / "infra/main.tf",
    )
    shutil.copyfile(
        ROOT / "benchmarks/gitleaks/corpus/github-pat/positive-01.txt",
        repository / "config/release-sentinel.txt",
    )
    (repository / "frontend/app.js").write_text(
        "export function execute(value) { return eval(value); }\n",
        encoding="utf-8",
    )
    (repository / "frontend/worker.ts").write_text(
        'const child_process = require("node:child_process");\n'
        "export function run(command: string) { child_process.exec(command); }\n",
        encoding="utf-8",
    )
    return repository


@contextmanager
def _controlled_osv():
    class Handler(BaseHTTPRequestHandler):
        request_count = 0

        def do_POST(self) -> None:  # noqa: N802
            assert self.path == "/v1/querybatch"
            self.rfile.read(int(self.headers["Content-Length"]))
            type(self).request_count += 1
            payload = b'{"results":[{}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", Handler
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
        assert status["product_status"] in {"QUEUED", "RUNNING"}
    raise AssertionError("fresh mixed-repository scan did not complete in 12 bounded cycles")


def test_fresh_mixed_repository_reaches_every_v13_product_surface(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _prepare_repository(tmp_path)
    data = tmp_path / "data"
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(tmp_path / "no-profile.json"))
    monkeypatch.delenv("SECURESCAN_DEPLOY_DATA_ROOT", raising=False)
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", f"sqlite:///{data / 'securescan.db'}")
    monkeypatch.setenv("SECURESCAN_ARTIFACT_ROOT", str(data / "artifacts"))
    monkeypatch.setenv("SECURESCAN_SOURCE_WORKSPACE_ROOT", str(data / "source-workspaces"))
    monkeypatch.setenv("SECURESCAN_SOURCE_PROJECTION_ROOT", str(data / "source-projections"))
    monkeypatch.setenv(
        "SECURESCAN_SOURCE_RUNTIME_RECEIPT_ROOT",
        str(data / "source-runtime-receipts"),
    )
    monkeypatch.setenv("SECURESCAN_ALLOW_SQLITE_SCHEMA_BOOTSTRAP", "true")
    get_settings.cache_clear()

    runner = CliRunner()
    initialized = runner.invoke(cli_main.app, ["init"])
    assert initialized.exit_code == 0, initialized.output

    with _controlled_osv() as (base_url, handler):

        def controlled_helper(*args, **kwargs):
            kwargs["loopback_test_base_url"] = base_url
            return ProductionOsvHelper(*args, **kwargs)

        monkeypatch.setattr(
            source_runtime,
            "SourceOsvHelperExecutionService",
            controlled_helper,
        )
        project = _json_command(runner, ["project", "create", "v13-e2e", "--json"])
        first = _json_command(
            runner,
            ["scan", str(repository), "--project-id", project["project_id"], "--json"],
        )
        first_status = _complete(runner, first["run_id"])
        assert first_status["coverage_complete"] is True
        assert handler.request_count == 1

        first_findings = _json_command(
            runner,
            ["findings", first["run_id"], "--exact-run", "--json"],
        )
        rules = {
            item["subject"].get("rule_id")
            for item in first_findings["items"]
            if item["authority"] == "semgrep-ce"
        }
        assert {
            "securescan.python.dangerous-eval",
            "securescan.javascript.dynamic-eval",
            "securescan.javascript.child-process-exec",
        } <= rules
        finding = next(
            item
            for item in first_findings["items"]
            if item["subject"].get("rule_id") == "securescan.javascript.dynamic-eval"
        )
        finding_id = finding["finding_id"]

        report = _json_command(runner, ["report", first["run_id"], "--json"])
        assert report["report"]["schema_version"] == "securescan-unified-evidence-s4-v1"
        assert _json_command(runner, ["coverage", first["run_id"], "--json"])["outcomes"]
        _json_command(runner, ["gaps", first["run_id"], "--json"])
        guidance = _json_command(
            runner,
            ["finding", "guidance", first["run_id"], finding_id, "--json"],
        )
        assert guidance["finding_id"] == finding_id

        with TestClient(app) as client:
            api_findings = client.get(
                f"/v1/scans/{first['run_id']}/findings", params={"exact_run": "true"}
            )
            assert api_findings.status_code == 200
            assert api_findings.json()["total"] == first_findings["total"]
            governance = client.put(
                f"/v1/projects/{project['project_id']}/lineages/{first['lineage_id']}"
                f"/findings/{finding_id}/governance",
                json={
                    "disposition": "FALSE_POSITIVE",
                    "reason": "V1.3 disposable acceptance review",
                    "expires_at": None,
                    "expected_revision": 0,
                },
            )
            assert governance.status_code == 200
            suppression = client.put(
                f"/v1/projects/{project['project_id']}/lineages/{first['lineage_id']}"
                f"/findings/{finding_id}/suppression",
                json={
                    "reason": "V1.3 bounded disposable suppression",
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                    "expected_revision": 0,
                },
            )
            assert suppression.status_code == 200
            assert client.get(f"/scans/{first['run_id']}/assurance").status_code == 200

        effective = _json_command(
            runner,
            [
                "governance",
                "effective",
                first["run_id"],
                finding_id,
                "--json",
            ],
        )
        assert effective["finding_id"] == finding_id
        assert effective["false_positive_effective"] is True
        assert effective["suppression_effective"] is True

        baseline = _json_command(
            runner,
            [
                "baseline",
                "promote",
                first["run_id"],
                "--expected-revision",
                "0",
                "--json",
            ],
        )
        assert baseline["run_id"] == first["run_id"]
        first_policy = _json_command(
            runner,
            ["policy", "evaluate", first["run_id"], "--json"],
            0,
            1,
            5,
        )
        assert first_policy["result"] in {"PASS", "FAIL", "ERROR"}

        (repository / "frontend/app.js").write_text(
            'export function execute() { return eval("2 + 2"); }\n', encoding="utf-8"
        )
        (repository / "frontend/worker.ts").write_text(
            "export function run(command: string) { return command.length; }\n",
            encoding="utf-8",
        )
        second = _json_command(
            runner,
            [
                "scan",
                str(repository),
                "--project-id",
                project["project_id"],
                "--lineage-id",
                first["lineage_id"],
                "--json",
            ],
        )
        _complete(runner, second["run_id"])
        assert handler.request_count == 2

        delta = _json_command(runner, ["delta", second["run_id"], "--json"])
        removed = {item["finding_id"] for item in delta["findings"] if item["state"] == "REMOVED"}
        assert finding_id in removed
        second_policy = _json_command(
            runner,
            ["policy", "evaluate", second["run_id"], "--json"],
            0,
            1,
            5,
        )
        assert second_policy["candidate_run_id"] == second["run_id"]

        sbom = runner.invoke(cli_main.app, ["sbom", second["run_id"]])
        assert sbom.exit_code == 0, sbom.output
        bom = json.loads(sbom.stdout)
        assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.7"
        toolchain = _json_command(runner, ["toolchain", second["run_id"], "--json"])
        assert toolchain["run_id"] == second["run_id"]
        assert any(item["capability"] == "source_sast" for item in toolchain["planned_nodes"])

        sarif_path = tmp_path / "result.sarif"
        sarif = runner.invoke(
            cli_main.app,
            ["sarif", second["run_id"], "--output", str(sarif_path)],
        )
        assert sarif.exit_code == 0, sarif.output
        assert json.loads(sarif_path.read_text("utf-8"))["version"] == "2.1.0"
        current_baseline = _json_command(
            runner,
            ["baseline", "show", second["run_id"], "--json"],
        )
        assert current_baseline["baseline"]["run_id"] == first["run_id"]
        assert current_baseline["revision"] == 1

    get_settings.cache_clear()

"""One real-data REST/CLI/browser truth bridge for H's shared read paths."""

from __future__ import annotations

# ruff: noqa: E501 -- JavaScript fixture stays readable as source.
import json
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from securescan.api.effective_governance_routes import router as effective_router
from securescan.api.policy_routes import router as policy_router
from securescan.api.product_view_routes import router as product_router
from securescan.api.trusted_baseline_routes import router as baseline_router
from securescan.cli import main as cli_main
from securescan.product_core import (
    EffectiveGovernanceService,
    SourcePolicyService,
    SourceSecurityDeltaService,
)
from securescan.product_core.product_view import SourceFindingProductViewService
from tests.test_postgres_trusted_baseline_v12e import _promote
from tests.test_source_orchestration_s6b import _RUN_ID

pytest_plugins = ("tests.test_postgres_trusted_baseline_v12e",)
pytestmark = pytest.mark.postgres
_WEB = Path(__file__).resolve().parents[1] / "src" / "securescan" / "web"
_NODE = Path("/mnt/c/Program Files/nodejs/node.exe")


def test_real_postgres_exact_facts_match_http_cli_json_and_browser(
    postgres_baseline, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if not _NODE.is_file() or shutil.which("wslpath") is None:
        pytest.skip("Windows Node/WSL bridge is unavailable")
    environment, baseline, project_id, lineage_id = postgres_baseline
    run_id = str(_RUN_ID)
    product = SourceFindingProductViewService(environment.factory, environment.store)
    delta = SourceSecurityDeltaService(environment.factory, environment.store)
    policy = SourcePolicyService(environment.factory, environment.store)
    effective = EffectiveGovernanceService(environment.factory)

    app = FastAPI()
    for router in (product_router, baseline_router, policy_router, effective_router):
        app.include_router(router)
    app.state.source_finding_product_view_service = product
    app.state.source_trusted_baseline_service = baseline
    app.state.source_security_delta_service = delta
    app.state.source_policy_service = policy
    app.state.effective_governance_service = effective
    client = TestClient(app)
    root = f"/v1/projects/{project_id}/lineages/{lineage_id}"
    findings_response = client.get(f"{root}/runs/{run_id}/findings")
    assert findings_response.status_code == 200
    findings = findings_response.json()
    assert findings["total"] >= 1
    finding = findings["items"][0]
    finding_id = finding["finding_id"]
    assert finding["lifecycle_state_at_run"] == "NEW"
    assert client.get(f"{root}/baseline").json()["baseline"] is None
    promoted = _promote(postgres_baseline, 0)
    baseline_response = client.get(f"{root}/baseline")
    delta_response = client.get(f"{root}/runs/{run_id}/security-delta")
    policy_response = client.post(f"{root}/runs/{run_id}/policy-evaluations", json={})
    effective_response = client.get(f"{root}/findings/{finding_id}/effective-governance")
    for response in (baseline_response, delta_response, policy_response, effective_response):
        assert response.status_code == 200, response.text
    baseline_json = baseline_response.json()
    delta_json = delta_response.json()
    policy_json = policy_response.json()
    effective_json = effective_response.json()
    assert baseline_json["baseline"]["baseline_id"] == promoted.baseline_id
    assert delta_json["baseline_id"] == policy_json["baseline_id"] == promoted.baseline_id
    assert delta_json["candidate_run_id"] == policy_json["candidate_run_id"] == run_id
    assert delta_json["comparison_status"] in {"COMPLETE", "PARTIAL", "NOT_COMPARABLE"}

    @contextmanager
    def services():
        yield SimpleNamespace(
            queries=SimpleNamespace(
                get_scan=lambda requested: SimpleNamespace(
                    run_id=requested, project_id=project_id, lineage_id=lineage_id
                )
            ),
            product_findings=product,
            baseline=baseline,
            delta=delta,
            policy=policy,
            effective_governance=effective,
        )

    monkeypatch.setattr(cli_main, "create_source_cli_services", services)
    runner = CliRunner()
    commands = {
        "findings": ["findings", run_id, "--exact-run", "--json"],
        "baseline": ["baseline", "show", run_id, "--json"],
        "delta": ["delta", run_id, "--json"],
        "governance": ["governance", "effective", run_id, finding_id, "--json"],
        "policy": ["policy", "evaluate", run_id, "--json"],
    }
    cli_json = {}
    for name, args in commands.items():
        result = runner.invoke(cli_main.app, args)
        assert result.exit_code in ({0, 1, 5} if name == "policy" else {0}), (name, result.stdout)
        cli_json[name] = json.loads(result.stdout)
    assert cli_json["findings"] == findings
    assert cli_json["baseline"] == baseline_json
    assert cli_json["delta"] == delta_json
    # Current/evaluation-time reads have their own wall-clock instant; all
    # durable and derived security facts must still agree exactly.
    assert {
        key: value for key, value in cli_json["governance"].items() if key != "evaluated_at"
    } == {key: value for key, value in effective_json.items() if key != "evaluated_at"}
    for key in (
        "candidate_run_id",
        "baseline_id",
        "baseline_revision",
        "policy_id",
        "policy_version",
        "policy_digest",
        "result",
        "decisions",
    ):
        assert cli_json["policy"][key] == policy_json[key], key

    for name in (
        "api.js",
        "assurance.js",
        "assurance_api.js",
        "components.js",
        "format.js",
        "product_release.js",
        "product_release_api.js",
        "router.js",
        "state.js",
    ):
        source = (_WEB / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(source.replace('"/assets/', '"./'), encoding="utf-8")
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    (tmp_path / "facts.json").write_text(
        json.dumps(
            {
                "scope": {"projectId": project_id, "lineageId": lineage_id, "runId": run_id},
                "baseline": baseline_json,
                "delta": delta_json,
                "policy": policy_json,
                "finding": finding,
                "effective": effective_json,
            }
        ),
        encoding="utf-8",
    )
    harness = r"""
import { readFileSync } from "node:fs";
import { beginRoute } from "./state.js";
import { renderAssurancePage } from "./assurance.js";
class NodeStub {
  constructor(tag = "#fragment") { this.tagName = tag.toUpperCase(); this.children = []; this.attributes = new Map(); this.listeners = new Map(); this.className = ""; this._text = ""; this.open = false; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((x) => x.textContent || "").join(""); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this._text = ""; this.children = [...items]; }
  setAttribute(k,v) { this.attributes.set(k,String(v)); }
  addEventListener(k,v) { this.listeners.set(k,v); }
  showModal() { this.open = true; }
  close() { this.open = false; }
}
globalThis.Node = NodeStub;
globalThis.document = {createElement: (tag) => new NodeStub(tag), createTextNode: (value) => {const n = new NodeStub("#text"); n.textContent = value; return n;}};
const facts = JSON.parse(readFileSync(new URL("./facts.json", import.meta.url), "utf8"));
const calls = [];
const services = {
  runScope: async (runId) => { calls.push("scope"); if (runId !== facts.scope.runId) throw Error("wrong run"); return facts.scope; },
  getBaseline: async () => facts.baseline,
  getBaselineHistory: async () => ({items: [], total: 0}),
  getSecurityDelta: async () => facts.delta,
  getTrustedPolicy: async () => ({lineage_id: facts.scope.lineageId, policy_id: facts.policy.policy_id, version: facts.policy.policy_version, digest: facts.policy.policy_digest}),
  getCoverage: async () => ({complete: false, counts_by_state: {INCOMPLETE: 1}}),
  getGaps: async () => ({total: 1}),
  evaluatePolicy: async () => {calls.push("evaluate"); return facts.policy;},
  promoteBaseline: async () => {calls.push("promote"); throw Error("unexpected promotion");},
};
beginRoute({name: "assurance", runId: facts.scope.runId});
const region = new NodeStub("main");
const page = renderAssurancePage({region, route: {name: "assurance", runId: facts.scope.runId}, services});
await page.settled;
if (calls.includes("evaluate") || calls.includes("promote")) throw Error("implicit state mutation");
for (const truth of [facts.baseline.baseline.baseline_id, facts.delta.candidate_run_id, facts.delta.comparison_status, facts.finding.finding_id]) {
  if (!region.textContent.includes(truth) && truth !== facts.finding.finding_id) throw Error(`missing browser truth: ${truth}`);
}
const buttons = (node) => [ ...(node.tagName === "BUTTON" ? [node] : []), ...node.children.flatMap(buttons) ];
const evaluate = buttons(region).find((node) => node.textContent === "Evaluate policy for this run");
if (!evaluate) throw Error("missing explicit evaluate action");
evaluate.listeners.get("click")({});
await new Promise((resolve) => setTimeout(resolve, 0));
for (const truth of [facts.policy.result, facts.policy.policy_id, facts.policy.baseline_id, facts.policy.candidate_run_id]) {
  if (!region.textContent.includes(truth)) throw Error(`missing browser policy truth: ${truth}`);
}
if (calls.filter((call) => call === "evaluate").length !== 1 || calls.includes("promote")) throw Error("wrong browser mutation count");
page.dispose();
"""
    harness_path = tmp_path / "postgres-parity.mjs"
    harness_path.write_text(harness, encoding="utf-8")
    windows_harness = subprocess.run(
        ["wslpath", "-w", str(harness_path)], check=True, capture_output=True, text=True
    ).stdout.strip()
    result = subprocess.run(
        [str(_NODE), windows_harness], check=False, capture_output=True, text=True, timeout=40
    )
    assert result.returncode == 0, result.stderr

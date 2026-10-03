"""Deterministic B-F fact-to-presentation parity cases, without a second policy engine."""

from __future__ import annotations

# ruff: noqa: E501 -- JavaScript fixture stays readable as source.
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from securescan.api.policy_schemas import PolicyEvaluationResponse
from securescan.api.trusted_baseline_schemas import SecurityDeltaResponse
from securescan.cli.product_policy import policy_evaluation_data
from securescan.product_core import (
    AnalystDisposition,
    FindingLifecycleState,
    PolicyDecisionKind,
    PolicyEvaluation,
    PolicyResult,
    PriorityBand,
    SecurityDeltaComparisonStatus,
    SecurityDeltaState,
    SourcePolicyService,
)
from tests.test_policy_v12f import _delta, _effective, _facts, _spec

_WEB = Path(__file__).resolve().parents[1] / "src" / "securescan" / "web"
_NODE = Path("/mnt/c/Program Files/nodejs/node.exe")
_NOW = datetime(2026, 10, 3, tzinfo=UTC)


def _case(name: str):
    spec = _spec(secret_introduced_fail=False)
    high = PriorityBand.HIGH
    if name == "high_introduced_existing":
        delta = _delta(SecurityDeltaState.INTRODUCED)
        facts = _facts(high, FindingLifecycleState.EXISTING)
        effective = _effective()
        expected = PolicyResult.FAIL
    elif name == "effective_false_positive":
        delta = _delta(SecurityDeltaState.INTRODUCED)
        facts = _facts(high, FindingLifecycleState.EXISTING)
        effective = _effective(
            false_positive_effective=True, disposition=AnalystDisposition.FALSE_POSITIVE
        )
        expected = PolicyResult.PASS
    elif name == "expired_accepted_risk":
        delta = _delta(SecurityDeltaState.INTRODUCED)
        facts = _facts(high, FindingLifecycleState.EXISTING)
        effective = _effective(
            disposition=AnalystDisposition.ACCEPTED_RISK, accepted_risk_expires_at=_NOW
        )
        expected = PolicyResult.FAIL
    elif name == "reopened_old_suppression":
        delta = _delta(SecurityDeltaState.INTRODUCED)
        facts = _facts(high, FindingLifecycleState.REOPENED)
        effective = _effective(
            lifecycle_state=FindingLifecycleState.REOPENED,
            suppression_present=True,
            review_required=True,
        )
        expected = PolicyResult.FAIL
    elif name == "not_comparable":
        delta = _delta(
            SecurityDeltaState.NOT_COMPARABLE,
            status=SecurityDeltaComparisonStatus.NOT_COMPARABLE,
            reasons=("CANDIDATE_NODE_FAILED",),
        )
        facts = ()
        effective = ()
        expected = PolicyResult.ERROR
    elif name == "removed":
        delta = _delta(SecurityDeltaState.REMOVED)
        facts = _facts(high, FindingLifecycleState.RESOLVED)
        effective = _effective()
        expected = PolicyResult.PASS
    else:
        raise AssertionError(name)
    decisions = SourcePolicyService._decide(spec, delta, facts, effective)
    result = (
        PolicyResult.ERROR
        if any(item.kind is PolicyDecisionKind.ERROR for item in decisions)
        else PolicyResult.FAIL
        if any(item.kind is PolicyDecisionKind.VIOLATION for item in decisions)
        else PolicyResult.PASS
    )
    assert result is expected, name
    evaluation = PolicyEvaluation(
        evaluation_id="55555555-5555-4555-8555-555555555555",
        lineage_id="11111111-1111-4111-8111-111111111111",
        candidate_run_id=delta.candidate_run_id,
        baseline_id=delta.baseline_id,
        baseline_revision=delta.baseline_revision,
        policy_id="66666666-6666-4666-8666-666666666666",
        policy_version=1,
        policy_digest="d" * 64,
        result=result,
        decisions=decisions,
        evaluated_at=_NOW,
    )
    api = PolicyEvaluationResponse.model_validate(evaluation).model_dump(mode="json")
    cli = policy_evaluation_data(evaluation)
    assert {key: value for key, value in api.items() if key != "evaluated_at"} == {
        key: value for key, value in cli.items() if key != "evaluated_at"
    }
    assert datetime.fromisoformat(
        api["evaluated_at"].replace("Z", "+00:00")
    ) == datetime.fromisoformat(cli["evaluated_at"])
    return {
        "name": name,
        "delta": SecurityDeltaResponse.model_validate(delta).model_dump(mode="json"),
        "evaluation": api,
        "expected": expected.value,
    }


def test_frozen_policy_cases_have_matching_api_cli_and_web_presentation(tmp_path: Path) -> None:
    if not _NODE.is_file() or shutil.which("wslpath") is None:
        pytest.skip("Windows Node/WSL bridge is unavailable")
    cases = [
        _case(name)
        for name in (
            "high_introduced_existing",
            "effective_false_positive",
            "expired_accepted_risk",
            "reopened_old_suppression",
            "not_comparable",
            "removed",
        )
    ]
    assert [item["expected"] for item in cases] == ["FAIL", "PASS", "FAIL", "FAIL", "ERROR", "PASS"]
    assert cases[1]["evaluation"]["decisions"][0]["kind"] == "EXCLUSION"
    assert not any(item["kind"] == "EXCLUSION" for item in cases[3]["evaluation"]["decisions"])
    assert not any(item["kind"] == "VIOLATION" for item in cases[5]["evaluation"]["decisions"])
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
    (tmp_path / "facts.json").write_text(json.dumps(cases), encoding="utf-8")
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
const cases = JSON.parse(readFileSync(new URL("./facts.json", import.meta.url), "utf8"));
const buttons = (node) => [ ...(node.tagName === "BUTTON" ? [node] : []), ...node.children.flatMap(buttons) ];
for (const item of cases) {
  const runId = item.delta.candidate_run_id;
  const lineageId = item.evaluation.lineage_id;
  beginRoute({name: "assurance", runId});
  const region = new NodeStub("main");
  let writes = 0;
  const scope = {projectId: "77777777-7777-4777-8777-777777777777", lineageId, runId};
  const services = {
    runScope: async () => scope,
    getBaseline: async () => ({lineage_id: lineageId, revision: 1, baseline: {baseline_id: item.delta.baseline_id, run_id: item.delta.baseline_run_id, promoted_at: "2026-10-01T00:00:00Z", actor_type: "LOCAL_OPERATOR"}}),
    getBaselineHistory: async () => ({items: [], total: 0}),
    getSecurityDelta: async () => item.delta,
    getTrustedPolicy: async () => ({lineage_id: lineageId, policy_id: item.evaluation.policy_id, version: 1, digest: item.evaluation.policy_digest}),
    getCoverage: async () => ({complete: item.delta.comparison_status === "COMPLETE", counts_by_state: {COMPLETE: 1}}),
    getGaps: async () => ({total: item.delta.comparison_status === "COMPLETE" ? 0 : 1}),
    evaluatePolicy: async () => {writes++; return item.evaluation;},
    promoteBaseline: async () => {throw Error("implicit baseline promotion");},
  };
  const page = renderAssurancePage({region, route: {name: "assurance", runId}, services});
  await page.settled;
  if (writes || !region.textContent.includes(item.delta.comparison_status)) throw Error(`${item.name}: initial state lied`);
  buttons(region).find((node) => node.textContent === "Evaluate policy for this run").listeners.get("click")({});
  await new Promise((resolve) => setTimeout(resolve, 0));
  if (writes !== 1 || !region.textContent.includes(item.expected)) throw Error(`${item.name}: policy state differs`);
  for (const decision of item.evaluation.decisions) {
    if (!region.textContent.includes(decision.reason_code)) throw Error(`${item.name}: reason code differs`);
  }
  if (item.name === "not_comparable" && !region.textContent.includes("Missing evidence must not be read as zero findings")) throw Error("not comparable looks clean");
  if (item.name === "effective_false_positive" && !region.textContent.includes("Excluded by effective governance")) throw Error("exclusion hidden");
  page.dispose();
}
"""
    harness_path = tmp_path / "parity-matrix.mjs"
    harness_path.write_text(harness, encoding="utf-8")
    windows_harness = subprocess.run(
        ["wslpath", "-w", str(harness_path)], check=True, capture_output=True, text=True
    ).stdout.strip()
    result = subprocess.run(
        [str(_NODE), windows_harness], check=False, capture_output=True, text=True, timeout=40
    )
    assert result.returncode == 0, result.stderr

from __future__ import annotations

# ruff: noqa: E501 -- executable JavaScript fixture stays readable as source.
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1] / "src" / "securescan" / "web"
_NODE = Path("/mnt/c/Program Files/nodejs/node.exe")


def test_assurance_is_explicit_scoped_and_does_not_turn_unknown_into_clean(tmp_path: Path) -> None:
    if not _NODE.is_file() or shutil.which("wslpath") is None:
        pytest.skip("Windows Node/WSL bridge is unavailable")
    for name in ("api.js", "assurance.js", "assurance_api.js", "components.js", "format.js", "router.js", "state.js"):
        source = (_ROOT / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(source.replace('"/assets/', '"./'), encoding="utf-8")
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    harness = r'''
import { beginRoute } from "./state.js";
import { renderAssurancePage } from "./assurance.js";

class FakeNode {
  constructor(tag = "#fragment") {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.attributes = new Map();
    this.listeners = new Map();
    this.className = "";
    this._text = "";
    this.isConnected = true;
    this.open = false;
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent || "").join(""); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this._text = ""; this.children = [...children]; }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  addEventListener(name, listener) { this.listeners.set(name, listener); }
  showModal() { this.open = true; }
  close() { this.open = false; }
}
globalThis.Node = FakeNode;
globalThis.document = {
  createElement: (tag) => new FakeNode(tag),
  createTextNode: (value) => { const node = new FakeNode("#text"); node.textContent = value; return node; },
};

const projectId = "11111111-1111-4111-8111-111111111111";
const lineageId = "22222222-2222-4222-8222-222222222222";
const runId = "33333333-3333-4333-8333-333333333333";
const findingId = "a".repeat(64);
const scope = { projectId, lineageId, runId };
const calls = [];
let revision = 0;
let policyResult = "ERROR";
const services = {
  runScope: async (id) => { calls.push("runScope"); if (id !== runId) throw Error("wrong run"); return scope; },
  getBaseline: async (s) => { calls.push("getBaseline"); if (s !== scope) throw Error("wrong scope"); return {lineage_id: lineageId, revision, baseline: revision ? {baseline_id: "b".repeat(64), run_id: runId, promoted_at: "2026-10-01T00:00:00Z", actor_type: "operator"} : null}; },
  getBaselineHistory: async () => { calls.push("getBaselineHistory"); return {items: [], total: 0}; },
  getSecurityDelta: async () => { calls.push("getSecurityDelta"); return { baseline_id: "b".repeat(64), baseline_run_id: runId, baseline_revision: revision, candidate_run_id: runId, comparison_status: "NOT_COMPARABLE", authority_summaries: [{authority: "osv.dev", comparison_status: "NOT_COMPARABLE", introduced_count: 0, present_count: 0, removed_count: 0, not_comparable_count: 1, reason_codes: ["MISSING_EVIDENCE"]}], findings: [{finding_id: findingId, authority: "osv.dev", state: "NOT_COMPARABLE", reason_codes: ["MISSING_EVIDENCE"]}]}; },
  getTrustedPolicy: async () => { calls.push("getTrustedPolicy"); return {policy_id: "c".repeat(64), lineage_id: lineageId, version: 2, digest: "d".repeat(64)}; },
  getCoverage: async () => { calls.push("getCoverage"); throw Error("coverage unavailable"); },
  getGaps: async () => { calls.push("getGaps"); throw Error("gaps unavailable"); },
  promoteBaseline: async (s, expected, options) => { calls.push("promoteBaseline"); if (s !== scope || expected !== 0 || !options.signal) throw Error("not revision scoped"); revision++; return {}; },
  evaluatePolicy: async (s, options) => { calls.push("evaluatePolicy"); if (s !== scope || !options.signal) throw Error("not run scoped"); return {evaluation_id: "e".repeat(64), candidate_run_id: runId, result: policyResult, policy_id: "c".repeat(64), policy_version: 2, policy_digest: "d".repeat(64), baseline_id: null, baseline_revision: null, evaluated_at: "2026-10-01T00:00:00Z", decisions: [{kind: "ERROR", reason_code: "MISSING_EVIDENCE", finding_id: findingId, rule_id: "required-coverage"}]}; },
};
const nodes = (node, predicate) => [ ...(predicate(node) ? [node] : []), ...node.children.flatMap((child) => nodes(child, predicate)) ];
const button = (root, label) => nodes(root, (node) => node.tagName === "BUTTON" && node.textContent === label)[0];
const click = (node) => { if (!node) throw Error("missing button"); node.listeners.get("click")({}); };
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

beginRoute({name: "assurance", runId});
const region = new FakeNode("main");
const controller = renderAssurancePage({region, route: {name: "assurance", runId}, services});
await controller.settled;
if (calls.includes("promoteBaseline") || calls.includes("evaluatePolicy")) throw Error("implicit mutation");
if (!region.textContent.includes("Coverage unavailable") || !region.textContent.includes("Gaps unavailable") ||
    !region.textContent.includes("NOT_COMPARABLE") || !region.textContent.includes("Missing evidence must not be read as zero findings")) throw Error("unknown evidence rendered clean");
if (!region.textContent.includes("No trusted baseline") || !region.textContent.includes("Not evaluated in this view")) throw Error("absence misrepresented");
click(button(region, "Promote this run as trusted baseline"));
const dialog = nodes(region, (node) => node.tagName === "DIALOG")[0];
if (!dialog.open || calls.includes("promoteBaseline")) throw Error("promotion lacked confirmation");
click(button(region, "Confirm promotion"));
await tick(); await tick();
if (calls.filter((call) => call === "promoteBaseline").length !== 1 || !region.textContent.includes("Revision1")) throw Error("promotion did not reread authoritative revision");
click(button(region, "Evaluate policy for this run"));
await tick();
if (!region.textContent.includes("SecureScan could not safely determine policy compliance") || !region.textContent.includes("MISSING_EVIDENCE")) throw Error("ERROR policy outcome masked");
if (!nodes(region, (node) => node.className.includes("status-error") && node.textContent.includes("ERROR")).length) throw Error("ERROR policy outcome lacks distinct visual state");
policyResult = "FAIL";
click(button(region, "Evaluate policy for this run"));
await tick();
if (!region.textContent.includes("a configured rule was violated")) throw Error("FAIL policy outcome masked");
policyResult = "PASS";
click(button(region, "Evaluate policy for this run"));
await tick();
if (!region.textContent.includes("no configured blocking rule was violated")) throw Error("PASS policy outcome masked");
if (calls.filter((call) => call === "evaluatePolicy").length !== 3) throw Error("evaluation was not explicit per click");
controller.dispose();
'''
    harness_path = tmp_path / "assurance-runtime.mjs"
    harness_path.write_text(harness, encoding="utf-8")
    windows_harness = subprocess.run(
        ["wslpath", "-w", str(harness_path)], check=True, capture_output=True, text=True
    ).stdout.strip()
    result = subprocess.run(
        [str(_NODE), windows_harness], check=False, capture_output=True, text=True, timeout=40
    )
    assert result.returncode == 0, result.stderr
    renderer = (_ROOT / "assurance.js").read_text(encoding="utf-8")
    assert "innerHTML" not in renderer
    assert "textContent" in renderer

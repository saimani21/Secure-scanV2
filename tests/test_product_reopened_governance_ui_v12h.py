from __future__ import annotations

# ruff: noqa: E501 -- executable JavaScript fixture stays readable as source.
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1] / "src" / "securescan" / "web"
_NODE = Path("/mnt/c/Program Files/nodejs/node.exe")


def test_reopened_governance_is_visibly_dormant_and_review_required(tmp_path: Path) -> None:
    if not _NODE.is_file() or shutil.which("wslpath") is None:
        pytest.skip("Windows Node/WSL bridge is unavailable")
    for name in ("api.js", "components.js", "format.js", "governance.js", "governance_api.js", "router.js", "state.js"):
        source = (_ROOT / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(source.replace('"/assets/', '"./'), encoding="utf-8")
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    harness = r'''
import { renderGovernance } from "./governance.js";
class NodeStub {
  constructor(tag = "#fragment") {this.tagName = tag.toUpperCase(); this.children = []; this.attributes = new Map(); this.listeners = new Map(); this.className = ""; this._text = ""; this.value = ""; this.disabled = false;}
  set textContent(v) {this._text = String(v); this.children = [];}
  get textContent() {return this._text + this.children.map((x) => x.textContent || "").join("");}
  append(...items) {this.children.push(...items);}
  setAttribute(k,v) {this.attributes.set(k,String(v));}
  addEventListener(k,v) {this.listeners.set(k,v);}
}
globalThis.Node = NodeStub;
globalThis.document = {createElement: (tag) => new NodeStub(tag), createTextNode: (value) => {const n = new NodeStub("#text"); n.textContent = value; return n;}};
const finding_id = "a".repeat(64);
const state = {
  loading: false, busy: false, error: null,
  governance: {lineage_id: "11111111-1111-4111-8111-111111111111", finding_id, disposition: "FALSE_POSITIVE", reason: "Old review", revision: 1},
  suppression: {lineage_id: "11111111-1111-4111-8111-111111111111", finding_id, suppression_id: "22222222-2222-4222-8222-222222222222", reason: "Old suppression", revision: 1, active: true, expires_at: "2026-11-01T00:00:00Z"},
  effective: {lineage_id: "11111111-1111-4111-8111-111111111111", finding_id, lifecycle_state: "REOPENED", review_required: true, false_positive_effective: false, accepted_risk_effective: false, suppression_effective: false, reason_codes: ["PRE_REOPEN_GOVERNANCE_DORMANT", "PRE_REOPEN_SUPPRESSION_DORMANT", "REOPENED_REVIEW_REQUIRED"], evaluated_at: "2026-10-01T00:00:00Z"},
};
const page = renderGovernance(state, () => {}, () => {});
if (!page) throw Error("governance missing");
for (const truth of ["Review required", "reopened", "dormant until explicitly reaffirmed", "False positive effectivefalse", "Suppression effectivefalse", "PRE_REOPEN_SUPPRESSION_DORMANT"]) {
  if (!page.textContent.includes(truth)) throw Error(`missing reopened truth: ${truth}`);
}
if (!page.textContent.includes("Current/evaluation-time state")) throw Error("current state unlabeled");
'''
    harness_path = tmp_path / "reopened-governance.mjs"
    harness_path.write_text(harness, encoding="utf-8")
    windows_harness = subprocess.run(["wslpath", "-w", str(harness_path)], check=True, capture_output=True, text=True).stdout.strip()
    result = subprocess.run([str(_NODE), windows_harness], check=False, capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, result.stderr

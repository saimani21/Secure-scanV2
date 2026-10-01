from __future__ import annotations

# ruff: noqa: E501 -- executable JavaScript fixture stays readable as source.
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1] / "src" / "securescan" / "web"
_NODE = Path("/mnt/c/Program Files/nodejs/node.exe")


def test_governance_browser_read_is_selected_only_revision_checked_and_stale_safe(
    tmp_path: Path,
) -> None:
    if not _NODE.is_file() or shutil.which("wslpath") is None:
        pytest.skip("Windows Node/WSL bridge is unavailable")
    for name in (
        "api.js", "components.js", "format.js", "governance.js", "governance_api.js",
        "router.js", "state.js",
    ):
        source = (_ROOT / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(source.replace('"/assets/', '"./'), encoding="utf-8")
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    harness = r'''
import { beginRoute } from "./state.js";
import { createGovernanceController } from "./governance.js";

const project = "11111111-1111-4111-8111-111111111111";
const lineage = "22222222-2222-4222-8222-222222222222";
const first = "a".repeat(64);
const second = "b".repeat(64);
const a = { project_id: project, lineage_id: lineage, finding_id: first };
const b = { project_id: project, lineage_id: lineage, finding_id: second };
const calls = [];
const deferred = [];
let revision = 0;
function read(kind, p, l, f, options) {
  if (p !== project || l !== lineage || !options.signal) throw new Error("unscoped read");
  calls.push([kind, f]);
  const value = { lineage_id: l, finding_id: f, revision,
    disposition: "UNREVIEWED", reason: null, active: false,
    reviewed_at: null, review_required: false, reason_codes: [] };
  if (f === first) return new Promise((resolve) => deferred.push(() => resolve(value)));
  return Promise.resolve(value);
}
const services = {
  getFindingGovernance: (p,l,f,o) => read("governance",p,l,f,o),
  getFindingSuppression: (p,l,f,o) => read("suppression",p,l,f,o),
  getEffectiveGovernance: (p,l,f,o) => read("effective",p,l,f,o),
  putFindingGovernance: async (p,l,f,body,o) => {
    if (p !== project || l !== lineage || f !== second || !o.signal ||
        body.expected_revision !== 0 || body.disposition !== "FALSE_POSITIVE") {
      throw new Error("mutation lost frozen revision scope");
    }
    revision = 1;
    return { lineage_id: l, finding_id: f, revision };
  },
};
beginRoute({ name: "findings" });
const controller = createGovernanceController({ services, onChange: () => {} });
controller.select(a);
if (deferred.length !== 3) throw new Error("selected reads missing");
controller.select(b);
await new Promise(setImmediate);
if (controller.stateFor(b)?.loading || controller.stateFor(b)?.governance?.revision !== 0) {
  throw new Error("second selected finding was not loaded");
}
for (const resolve of deferred) resolve();
await new Promise(setImmediate);
if (controller.stateFor(a) !== null || controller.stateFor(b)?.governance?.revision !== 0) {
  throw new Error("stale first finding overwrote selection");
}
await controller.mutate("governance", {disposition: "FALSE_POSITIVE", reason: "tested", expires_at: null, expected_revision: 0});
if (controller.stateFor(b)?.governance?.revision !== 1) throw new Error("authoritative reread missing");
if (calls.length !== 9) throw new Error("governance request fanout changed");
controller.select(null);
if (controller.stateFor(b) !== null) throw new Error("cleared selection kept governance");
controller.dispose();
'''
    harness_path = tmp_path / "governance-runtime.mjs"
    harness_path.write_text(harness, encoding="utf-8")
    windows_harness = subprocess.run(
        ["wslpath", "-w", str(harness_path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    result = subprocess.run(
        [str(_NODE), windows_harness],
        check=False,
        capture_output=True,
        text=True,
        timeout=40,
    )
    assert result.returncode == 0, result.stderr
    renderer = (_ROOT / "governance.js").read_text(encoding="utf-8")
    assert "The finding has reopened after a prior exclusionary decision" in renderer
    assert "Current/evaluation-time state" in renderer
    assert "textContent" in renderer
    assert "innerHTML" not in renderer

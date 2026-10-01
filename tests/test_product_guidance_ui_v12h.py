from __future__ import annotations

# ruff: noqa: E501 -- executable JavaScript fixture stays readable as source.
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1] / "src" / "securescan" / "web"
_NODE = Path("/mnt/c/Program Files/nodejs/node.exe")


def test_guidance_browser_read_is_selected_scoped_abortable_and_text_only(tmp_path: Path) -> None:
    if not _NODE.is_file() or shutil.which("wslpath") is None:
        pytest.skip("Windows Node/WSL bridge is unavailable")
    for name in ("state.js", "finding_guidance_state.js"):
        source = (_ROOT / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(source.replace('"/assets/', '"./'), encoding="utf-8")
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    harness = r'''
import { beginRoute } from "./state.js";
import { createGuidanceController } from "./finding_guidance_state.js";

const run = "99999999-9999-4999-8999-999999999991";
const project = "99999999-9999-4999-8999-999999999992";
const lineage = "99999999-9999-4999-8999-999999999993";
const first = "a".repeat(64);
const second = "b".repeat(64);
const calls = [];
let resolveFirst;
beginRoute({ name: "findings", runId: run });
const services = {
  getScanSummary: async (value) => {
    if (value !== run) throw new Error("wrong run scope");
    return { run_id: run, project_id: project, lineage_id: lineage };
  },
  getFindingGuidance: async (p, l, r, f, options) => {
    calls.push([p, l, r, f]);
    if (p !== project || l !== lineage || r !== run || !options.signal) {
      throw new Error("scope mismatch");
    }
    if (f === first) return new Promise((resolve) => { resolveFirst = resolve; });
    return { run_id: run, finding_id: f, authority: "semgrep-ce", basis_level: "FAMILY" };
  },
};
let updates = 0;
const controller = createGuidanceController({ runId: run, services, onChange: () => updates++ });
const pending = controller.select(first, "gitleaks");
await Promise.resolve(); await Promise.resolve();
if (!resolveFirst) throw new Error("first selected read did not begin");
const next = controller.select(second, "semgrep-ce");
resolveFirst({ run_id: run, finding_id: first, authority: "gitleaks", basis_level: "FAMILY" });
await Promise.all([pending, next]);
if (controller.stateFor(first) !== null) throw new Error("stale finding remained selected");
if (controller.stateFor(second)?.payload?.finding_id !== second) throw new Error("wrong selected guidance");
if (controller.stateFor(second)?.loading) throw new Error("selected read did not settle");
if (calls.length !== 2 || updates < 2) throw new Error("selected read count changed");
controller.dispose();
'''
    harness_path = tmp_path / "guidance-runtime.mjs"
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
    renderer = (_ROOT / "guidance.js").read_text(encoding="utf-8")
    assert "textContent:" in renderer
    assert "innerHTML" not in renderer
    assert "dangerouslySetInnerHTML" not in renderer

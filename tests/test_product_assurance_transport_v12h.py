from __future__ import annotations

# ruff: noqa: E501 -- executable JavaScript fixture stays readable as source.
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1] / "src" / "securescan" / "web"
_NODE = Path("/mnt/c/Program Files/nodejs/node.exe")


def test_assurance_browser_transport_uses_only_known_scoped_json_routes(tmp_path: Path) -> None:
    if not _NODE.is_file() or shutil.which("wslpath") is None:
        pytest.skip("Windows Node/WSL bridge is unavailable")
    for name in ("api.js", "assurance_api.js", "router.js"):
        source = (_ROOT / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(source.replace('"/assets/', '"./'), encoding="utf-8")
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    harness = r'''
import { getBaseline, getSecurityDelta, getTrustedPolicy, promoteBaseline, evaluatePolicy } from "./assurance_api.js";
globalThis.window = { location: { origin: "http://securescan.local" } };
const p = "11111111-1111-4111-8111-111111111111";
const l = "22222222-2222-4222-8222-222222222222";
const r = "33333333-3333-4333-8333-333333333333";
const scope = {projectId: p, lineageId: l, runId: r};
const calls = [];
globalThis.fetch = async (path, options) => {
  calls.push([path, options]);
  return {ok: true, status: 200, json: async () => ({ok: true})};
};
await getBaseline(scope);
await getSecurityDelta(scope);
await getTrustedPolicy(scope);
await promoteBaseline(scope, 4);
await evaluatePolicy(scope);
const root = `/v1/projects/${p}/lineages/${l}`;
const expected = [
  [`${root}/baseline`, "GET"],
  [`${root}/runs/${r}/security-delta`, "GET"],
  [`${root}/policy`, "GET"],
  [`${root}/baseline`, "PUT"],
  [`${root}/runs/${r}/policy-evaluations`, "POST"],
];
if (JSON.stringify(calls.map(([path, options]) => [path, options.method])) !== JSON.stringify(expected)) throw Error("wrong assurance route or verb");
if (calls.some(([, options]) => options.credentials !== "same-origin")) throw Error("cross-origin request");
if (JSON.stringify(JSON.parse(calls[3][1].body)) !== JSON.stringify({run_id: r, expected_revision: 4})) throw Error("promotion lost revision or run");
let rejected = false;
try { await promoteBaseline({...scope, runId: "../../etc"}, 4); } catch (error) { rejected = error instanceof TypeError; }
if (!rejected || calls.length !== 5) throw Error("browser path injection accepted");
'''
    harness_path = tmp_path / "assurance-transport.mjs"
    harness_path.write_text(harness, encoding="utf-8")
    windows_harness = subprocess.run(
        ["wslpath", "-w", str(harness_path)], check=True, capture_output=True, text=True
    ).stdout.strip()
    result = subprocess.run(
        [str(_NODE), windows_harness], check=False, capture_output=True, text=True, timeout=40
    )
    assert result.returncode == 0, result.stderr

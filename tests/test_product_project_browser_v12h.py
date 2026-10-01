from __future__ import annotations

# ruff: noqa: E501 -- executable JavaScript fixture stays readable as source.
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1] / "src" / "securescan" / "web"
_NODE = Path("/mnt/c/Program Files/nodejs/node.exe")


def test_project_mutation_is_exact_same_origin_json_and_rejects_bad_responses(
    tmp_path: Path,
) -> None:
    if not _NODE.is_file() or shutil.which("wslpath") is None:
        pytest.skip("Windows Node/WSL bridge is unavailable")
    for name in ("api.js", "router.js", "project_mutations.js"):
        source = (_ROOT / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(source.replace('"/assets/', '"./'), encoding="utf-8")
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    harness = r"""
import { createProject } from "./project_mutations.js";

const id = "11111111-1111-4111-8111-111111111111";
const hostile = "<script>alert(1)</script>";
const calls = [];
globalThis.fetch = async (path, options) => {
  calls.push([path, options]);
  return { ok: true, status: 201, json: async () => ({project_id: id, name: hostile}) };
};
const project = await createProject(hostile);
if (project.project_id !== id || project.name !== hostile) throw new Error("response changed");
if (calls.length !== 1 || calls[0][0] !== "/v1/projects") throw new Error("wrong route");
if (calls[0][1].method !== "POST" || calls[0][1].credentials !== "same-origin") throw new Error("wrong request");
if (JSON.stringify(JSON.parse(calls[0][1].body)) !== JSON.stringify({name: hostile})) throw new Error("unexpected request fields");
if (calls[0][1].headers["Content-Type"] !== "application/json") throw new Error("wrong content type");

globalThis.fetch = async () => ({ok: true, status: 201, json: async () => ({project_id: "../etc", name: hostile})});
let rejected = false;
try { await createProject(hostile); } catch (error) { rejected = error.code === "INVALID_RESPONSE"; }
if (!rejected) throw new Error("invalid project identity accepted");

rejected = false;
try { await createProject(" unsafe "); } catch (error) { rejected = error instanceof TypeError; }
if (!rejected) throw new Error("invalid name accepted");
"""
    harness_path = tmp_path / "project-runtime.mjs"
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

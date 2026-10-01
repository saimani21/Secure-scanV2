"""Actual frozen G evidence rendered consistently for three scanner authorities."""

from __future__ import annotations

# ruff: noqa: E501 -- JavaScript fixture stays readable as source.
import json
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from securescan.api.guidance_schemas import FindingGuidanceResponse
from securescan.cli import main as cli_main
from securescan.evidence.models import EvidenceAuthority
from securescan.product_core.guidance import (
    CheckovGuidanceRenderer,
    GitleaksGuidanceRenderer,
    OsvGuidanceRenderer,
)
from tests.test_guidance_v12g import _finding_and_evidence

_WEB = Path(__file__).resolve().parents[1] / "src" / "securescan" / "web"
_NODE = Path("/mnt/c/Program Files/nodejs/node.exe")
_PROJECT = "11111111-1111-4111-8111-111111111111"
_LINEAGE = "22222222-2222-4222-8222-222222222222"


def test_gitleaks_osv_checkov_actual_guidance_matches_api_cli_json_and_web(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if not _NODE.is_file() or shutil.which("wslpath") is None:
        pytest.skip("Windows Node/WSL bridge is unavailable")
    cases = []
    for authority, renderer in (
        (EvidenceAuthority.GITLEAKS, GitleaksGuidanceRenderer()),
        (EvidenceAuthority.OSV, OsvGuidanceRenderer()),
        (EvidenceAuthority.CHECKOV, CheckovGuidanceRenderer()),
    ):
        report, finding, evidence = _finding_and_evidence(authority)
        run_id = report.scope.source_run_id
        guidance = (
            renderer.render(run_id, finding, evidence, report)
            if authority is EvidenceAuthority.OSV
            else renderer.render(run_id, finding, evidence)
        )

        @contextmanager
        def factory(bound_guidance=guidance):
            yield SimpleNamespace(
                queries=SimpleNamespace(
                    get_scan=lambda requested: SimpleNamespace(
                        run_id=requested, project_id=_PROJECT, lineage_id=_LINEAGE
                    )
                ),
                guidance=SimpleNamespace(get_for_run=lambda **_kwargs: bound_guidance),
            )

        monkeypatch.setattr(cli_main, "create_source_cli_services", factory)
        result = CliRunner().invoke(
            cli_main.app, ["finding", "guidance", run_id, finding.finding_id, "--json"]
        )
        assert result.exit_code == 0, result.stdout
        cli = json.loads(result.stdout)
        api = FindingGuidanceResponse.model_validate(guidance).model_dump(mode="json")
        assert cli == api
        assert cli["authority"] == authority.value
        assert cli["run_id"] == run_id and cli["finding_id"] == finding.finding_id
        if authority is EvidenceAuthority.GITLEAKS:
            assert cli["basis_level"] == "FAMILY"
            assert "SECRET_SENTINEL_4d8b38f1" not in result.stdout
        elif authority is EvidenceAuthority.OSV:
            assert cli["basis_level"] == "EXACT_EVIDENCE"
            assert cli["advisory_id"] and cli["package_name"] == "requests"
        else:
            assert cli["basis_level"] == "EXACT_EVIDENCE"
            assert cli["check_id"] and "live cloud state" in " ".join(cli["limitations"])
        cases.append(api)

    for name in ("components.js", "format.js", "guidance.js"):
        source = (_WEB / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(source.replace('"/assets/', '"./'), encoding="utf-8")
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    (tmp_path / "facts.json").write_text(json.dumps(cases), encoding="utf-8")
    harness = r"""
import { readFileSync } from "node:fs";
import { renderGuidance } from "./guidance.js";
class NodeStub {
  constructor(tag = "#fragment") { this.tagName = tag.toUpperCase(); this.children = []; this.attributes = new Map(); this.className = ""; this._text = ""; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((x) => x.textContent || "").join(""); }
  append(...items) { this.children.push(...items); }
  setAttribute(k,v) { this.attributes.set(k,String(v)); }
}
globalThis.Node = NodeStub;
globalThis.document = {createElement: (tag) => new NodeStub(tag), createTextNode: (value) => {const n = new NodeStub("#text"); n.textContent = value; return n;}};
for (const fact of JSON.parse(readFileSync(new URL("./facts.json", import.meta.url), "utf8"))) {
  const page = renderGuidance({attempted: true, loading: false, failed: false, payload: fact});
  if (!page || !page.textContent.includes(`Guidance basis: ${fact.basis_level}`)) throw Error("basis differs");
  for (const value of [...fact.remediation_steps, ...fact.verification_steps, ...fact.limitations]) {
    if (!page.textContent.includes(value)) throw Error(`missing exact guidance text: ${fact.authority}`);
  }
  if (page.textContent.includes("SECRET_SENTINEL_4d8b38f1")) throw Error("raw secret exposed");
}
"""
    harness_path = tmp_path / "guidance-parity.mjs"
    harness_path.write_text(harness, encoding="utf-8")
    windows_harness = subprocess.run(
        ["wslpath", "-w", str(harness_path)], check=True, capture_output=True, text=True
    ).stdout.strip()
    result = subprocess.run(
        [str(_NODE), windows_harness], check=False, capture_output=True, text=True, timeout=40
    )
    assert result.returncode == 0, result.stderr

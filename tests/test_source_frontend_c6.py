# ruff: noqa: E501 -- executable JavaScript fixture stays readable as source.

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_WEB = _ROOT / "src" / "securescan" / "web"
_SOURCES = {path.name: path.read_text(encoding="utf-8") for path in sorted(_WEB.glob("*.js"))}
_STYLES = "\n".join(path.read_text(encoding="utf-8") for path in sorted(_WEB.glob("*.css")))


def _node() -> Path | None:
    value = Path("/mnt/c/Program Files/nodejs/node.exe")
    return value if value.is_file() else None


def test_c6_all_placeholder_routes_are_real_and_use_only_frozen_reads() -> None:
    app = _SOURCES["app.js"]
    api = _SOURCES["api.js"]
    for route, renderer in (("coverage", "renderCoveragePage"), ("gaps", "renderGapsPage"), ("report", "renderReportPage")):
        assert f"{route}: {renderer}" in app
    for endpoint in ("/coverage", "/gaps?", "/report"):
        assert endpoint in api
    for module in ("coverage.js", "gaps.js", "report.js"):
        for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "unsafe-inline", "api.osv.dev"):
            assert forbidden not in _SOURCES[module]


def test_c6_semantics_raw_report_export_and_print_are_explicit() -> None:
    coverage = _SOURCES["coverage.js"]
    gaps = _SOURCES["gaps.js"]
    report = _SOURCES["report.js"]
    for value in ("COMPLETE", "COMPLETE_WITH_FINDINGS", "COMPLETE_WITH_SUPPRESSIONS", "PARTIAL", "FAILED", "NOT_APPLICABLE"):
        assert value in coverage or value in _SOURCES["format.js"]
    assert "percentage" not in coverage.lower()
    assert 'textContent: "Technical scope"' in coverage
    assert 'emptyState("No published gaps"' in gaps
    assert "Full security coverage" not in gaps
    assert 'textContent: "Raw evidence report"' in report
    assert "JSON.stringify" in report and 'createElement("pre", { textContent: rawReport })' in report
    assert "new Blob" in report and 'type: "application/json"' in report
    assert "window.print()" in report
    assert "@media print" in _STYLES


def test_c6_runtime_coverage_gaps_report_failure_isolation_and_hostile_text(tmp_path: Path) -> None:
    node = _node()
    if node is None:
        pytest.skip("Node is not available for executable C6 module tests")
    for name, source in _SOURCES.items():
        (tmp_path / name).write_text(source.replace('"/assets/', '"./'), encoding="utf-8")
    harness = r'''
import { pathToFileURL } from "node:url";
class FakeNode {
  constructor(tag = "#fragment") { this.tagName = tag.toUpperCase(); this.children = []; this.attributes = new Map(); this.dataset = {}; this.className = ""; this.disabled = false; this.listeners = new Map(); this._text = ""; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent || "").join(""); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this._text = ""; this.children = [...children]; }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  addEventListener(name, listener) { this.listeners.set(name, listener); }
  click() { const listener = this.listeners.get("click"); if (listener) return listener({ preventDefault() {} }); }
  remove() {}
}
globalThis.Node = FakeNode; globalThis.HTMLElement = FakeNode;
globalThis.document = { body: new FakeNode("body"), createElement: (tag) => new FakeNode(tag), createTextNode: (value) => { const node = new FakeNode("#text"); node.textContent = value; return node; }, createDocumentFragment: () => new FakeNode() };
Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async () => {} } }, configurable: true });
globalThis.Blob = class { constructor(parts, options) { this.parts = parts; this.type = options.type; } };
globalThis.URL.createObjectURL = () => "blob:controlled"; globalThis.URL.revokeObjectURL = () => {};
const root = process.argv[2]; const load = async (name) => import(pathToFileURL(`${root}\\${name}`));
const coverageModule = await load("coverage.js"); const gapsModule = await load("gaps.js"); const reportModule = await load("report.js"); const routeState = await load("state.js");
const runId = "11111111-1111-4111-8111-111111111111"; const region = () => new FakeNode("section");
const nodes = (rootNode, predicate, found = []) => { if (predicate(rootNode)) found.push(rootNode); for (const child of rootNode.children) nodes(child, predicate, found); return found; };
const byText = (rootNode, tag, value) => nodes(rootNode, (node) => node.tagName === tag && node.textContent === value);
const expect = (rootNode, value) => { if (!rootNode.textContent.includes(value)) throw new Error(`Missing text: ${value}`); };
const stages = { run_id: runId, product_status: "COMPLETED", stages: [
  { authority: "semgrep-ce", capability: "python_sast", progress_state: "COMPLETE", coverage_states: ["COMPLETE_WITH_FINDINGS"], reason_code: null },
  { authority: "gitleaks", capability: "secret_detection", progress_state: "FAILED", coverage_states: ["FAILED"], reason_code: "TOOL_FAILED" },
  { authority: "syft", capability: "package_inventory", progress_state: "COMPLETE", coverage_states: ["COMPLETE"], reason_code: null },
  { authority: "osv.dev", capability: "dependency_advisory_matching", progress_state: "NOT_APPLICABLE", coverage_states: ["NOT_APPLICABLE"], reason_code: "NO_EXACT_PINS" },
  { authority: "checkov", capability: "configuration_security", progress_state: "PARTIAL", coverage_states: ["PARTIAL", "COMPLETE_WITH_SUPPRESSIONS"], reason_code: "CHECKOV_PARSE_GAP" },
] };
const coverage = { complete: false, counts_by_state: { COMPLETE: 1, FAILED: 1, PARTIAL: 1 }, outcomes: [
  { authority: "semgrep-ce", capability: "python_sast", state: "COMPLETE_WITH_FINDINGS", framework: null, selected_scope: [{ kind: "REPOSITORY_PATH", path: "<script>src/app.py</script>" }], finding_count: 1, suppression_count: 0, gap_count: 0, reason_code: null },
  { authority: "gitleaks", capability: "secret_detection", state: "FAILED", framework: null, selected_scope: [{ kind: "REPOSITORY_SCOPE" }], finding_count: 0, suppression_count: 0, gap_count: 1, reason_code: "SCANNER_FAILED" },
  { authority: "syft", capability: "package_inventory", state: "COMPLETE", framework: null, selected_scope: [{ kind: "REPOSITORY_PATH", path: "requirements.txt" }], finding_count: 0, suppression_count: 0, gap_count: 0, reason_code: null },
  { authority: "osv.dev", capability: "dependency_advisory_matching", state: "NOT_APPLICABLE", framework: null, selected_scope: [{ kind: "REPOSITORY_PATH", path: "requirements.txt" }], finding_count: 0, suppression_count: 0, gap_count: 0, reason_code: "NO_EXACT_PINS" },
  { authority: "checkov", capability: "configuration_security", state: "PARTIAL", framework: "terraform", selected_scope: [{ kind: "REPOSITORY_PATH", path: "x".repeat(1100) + "\u202Efdp.exe" }], finding_count: 1, suppression_count: 1, gap_count: 1, reason_code: "CHECKOV_PARSE_GAP" },
] };
const gapPage = { items: [{ gap_id: "a".repeat(64), authority: "checkov", code: "CHECKOV_PARSE_GAP", scope: { kind: "PATH", value: "infra/<script>bad.tf</script>", framework: "terraform", component_ref: null }, message: '"><img src=x onerror=alert(1)>' }, { gap_id: "b".repeat(64), authority: "osv.dev", code: "NO_SUPPORTED_COORDINATE", scope: { kind: "PACKAGE", value: "local-package", framework: null, component_ref: "c".repeat(64) }, message: null }], total: 52, limit: 50, offset: 0 };
const summary = { run_id: runId, project_id: "22222222-2222-4222-8222-222222222222", product_status: "COMPLETED", finalized_at: "2026-09-25T20:00:00Z", finding_count: 3, priority_counts: { HIGH: 2, UNRANKED: 1 }, coverage_complete: false, gap_count: 2 };
const verified = { run_id: runId, report: { schema_version: "securescan-unified-evidence-s4-v1", scope: { source_run_id: runId, repository_digest: "d".repeat(64), profile_digest: "e".repeat(64), plan_digest: "f".repeat(64) }, findings: [{ message: "<script>alert(1)</script>" }], coverage_outcomes: coverage.outcomes, gaps: gapPage.items } };

let target = region(); routeState.beginRoute({ name: "coverage", runId });
let result = coverageModule.renderCoveragePage({ region: target, route: { runId }, services: { getScanStages: async () => stages, getCoverage: async () => coverage } }); await result.settled;
for (const value of ["SAST", "Secrets", "Package inventory", "Dependency vulnerabilities", "Configuration security", "Execution", "Coverage", "Complete with findings", "Failed", "Not applicable", "Partial", "Technical scope", "<script>src/app.py</script>"]) expect(target, value);
if (target.textContent.includes("%") || nodes(target, (node) => node.tagName === "SCRIPT").length) throw new Error("Coverage fabricated percentage or parsed markup");

target = region(); routeState.beginRoute({ name: "coverage", runId });
const pendingError = new Error("not ready"); pendingError.status = 409;
result = coverageModule.renderCoveragePage({ region: target, route: { runId }, services: { getScanStages: async () => stages, getCoverage: async () => { throw pendingError; } } }); await result.settled;
expect(target, "Coverage is pending publication"); expect(target, "Execution");

target = region(); routeState.beginRoute({ name: "gaps", runId }); const gapCalls = [];
const nav = { search: () => "", urls: [], push(url) { this.urls.push(url); } };
result = gapsModule.renderGapsPage({ region: target, route: { runId }, navigation: nav, services: { getGaps: async (_run, options) => { gapCalls.push(options); return { ...gapPage, offset: options.offset }; } } }); await result.settled;
for (const value of ["2 gaps", "Configuration security", "Checkov", "CHECKOV_PARSE_GAP", "infra/<script>bad.tf</script>", '"><img src=x onerror=alert(1)>', "Technical scope"]) expect(target, value);
if (nodes(target, (node) => node.tagName === "SCRIPT" || node.tagName === "IMG").length) throw new Error("Gap hostile text became markup");
byText(target, "BUTTON", "Next")[0].click(); await new Promise((resolve) => setTimeout(resolve, 0));
if (gapCalls.at(-1).offset !== 50 || !nav.urls.at(-1).includes("offset=50")) throw new Error("Gap pagination changed");

target = region(); routeState.beginRoute({ name: "report", runId }); let prints = 0;
const reportServices = { getScanSummary: async () => summary, getScanStages: async () => stages, getCoverage: async () => coverage, getGaps: async () => gapPage, getScanReport: async () => verified, getDependencies: async () => ({ items: [], total: 8, limit: 1, offset: 0 }) };
result = reportModule.renderReportPage({ region: target, route: { runId }, services: reportServices, print: () => { prints += 1; } }); await result.settled;
for (const value of ["Security scan report", "Summary", "Analysis coverage", "Findings", "Dependencies", "Analysis gaps", "Provenance", "Raw evidence report", "Repository digest", "8 packages observed", "Known vulnerability totals are not inferred here.", "<script>alert(1)</script>"]) expect(target, value);
if (nodes(target, (node) => node.tagName === "SCRIPT").length) throw new Error("Raw report became markup");
byText(target, "BUTTON", "Print")[0].click(); if (prints !== 1) throw new Error("Print action changed");
if (!byText(target, "BUTTON", "Copy JSON").length || !byText(target, "BUTTON", "Download JSON").length) throw new Error("Report exports missing");

target = region(); routeState.beginRoute({ name: "report", runId });
result = reportModule.renderReportPage({ region: target, route: { runId }, services: { ...reportServices, getScanReport: async () => { throw new Error("private raw body"); } } }); await result.settled;
expect(target, "Verified report unavailable"); expect(target, "Summary"); expect(target, "Analysis coverage"); if (target.textContent.includes("private raw body")) throw new Error("Raw report error leaked");
'''
    harness_path = tmp_path / "c6-runtime.mjs"
    harness_path.write_text(harness, encoding="utf-8")
    windows_root = subprocess.run(["wslpath", "-w", str(tmp_path)], check=True, capture_output=True, text=True).stdout.strip()
    windows_harness = subprocess.run(["wslpath", "-w", str(harness_path)], check=True, capture_output=True, text=True).stdout.strip()
    result = subprocess.run([str(node), windows_harness, windows_root], check=False, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr

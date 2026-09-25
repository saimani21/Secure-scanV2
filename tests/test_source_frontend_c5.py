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
    path = Path("/mnt/c/Program Files/nodejs/node.exe")
    return path if path.is_file() else None


def test_c5_uses_only_frozen_dependency_api_and_authoritative_pagination() -> None:
    api = _SOURCES["api.js"]
    module = _SOURCES["dependencies.js"]
    assert '`/v1/scans/${segment}/dependencies?${pageQuery(limit, offset)}`' in api
    assert "services.getDependencies(runId" in module
    assert "limit: DEPENDENCY_PAGE_LIMIT" in module
    assert "offset: state.offset" in module
    for forbidden in ("api.osv.dev", "fetch(", "getScanReport", "getComponents", "resolveDependencies"):
        assert forbidden not in module


def test_c5_truth_table_and_advisory_wording_are_explicit() -> None:
    formatting = _SOURCES["format.js"]
    module = _SOURCES["dependencies.js"]
    for value in ("COMPLETE", "PARTIAL", "FAILED", "NOT_APPLICABLE"):
        assert value in formatting
    assert 'result: "Unknown"' in formatting
    assert 'result: "N/A"' in formatting
    assert "known ${count === 1" in formatting
    assert '"vulnerability" : "vulnerabilities"' in formatting
    assert "Observed advisories" in module
    assert "Fixed versions reported by advisory" in module
    for forbidden in ("Recommended upgrade", "Safe version", "Upgrade to", "Risk"):
        assert forbidden not in module


def test_c5_security_responsive_and_route_contracts_are_explicit() -> None:
    module = _SOURCES["dependencies.js"]
    for marker in (
        'createElement("ol"',
        'createElement("a"',
        'createElement("dialog"',
        'role: "dialog"',
        '"aria-modal": "true"',
        'textContent: "Search this page"',
        'textContent: "Filters only the currently loaded page."',
        'textContent: "Back to dependencies"',
        'createElement("details"',
        "COMPONENT_REF_PATTERN = /^[0-9a-f]{64}$/",
    ):
        assert marker in module
    assert "innerHTML" not in module
    assert "JSON.stringify" not in module
    assert "unicode-bidi: isolate" in _STYLES
    assert ".dependencies-has-selection .dependency-list-pane" in _STYLES
    assert "@media (min-width: 768px) and (max-width: 1199px)" in _STYLES
    assert "@media (max-width: 767px)" in _STYLES


def test_c5_runtime_truth_search_pagination_detail_errors_and_responsiveness(tmp_path: Path) -> None:
    node = _node()
    if node is None:
        pytest.skip("Node is not available for executable C5 module tests")
    for name, source in _SOURCES.items():
        (tmp_path / name).write_text(source.replace('"/assets/', '"./'), encoding="utf-8")

    harness = r'''
import { pathToFileURL } from "node:url";

class FakeNode {
  constructor(tagName = "#fragment") {
    this.tagName = tagName.toUpperCase(); this.children = []; this.attributes = new Map();
    this.dataset = {}; this.className = ""; this.disabled = false; this.isConnected = true;
    this.listeners = new Map(); this._text = ""; this.value = ""; this.open = false;
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent || "").join(""); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this._text = ""; this.children = [...children]; }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  addEventListener(name, listener) { this.listeners.set(name, listener); }
  querySelector(selector) {
    const data = /^\[data-component-ref="([0-9a-f]+)"\]$/.exec(selector);
    if (data && this.dataset.componentRef === data[1]) return this;
    for (const child of this.children) { const found = child.querySelector ? child.querySelector(selector) : null; if (found) return found; }
    return null;
  }
  focus() { document.activeElement = this; }
  showModal() { this.open = true; }
  close() { this.open = false; const listener = this.listeners.get("close"); if (listener) listener({ target: this }); }
}
globalThis.Node = FakeNode; globalThis.HTMLElement = FakeNode;
globalThis.document = {
  activeElement: null,
  createElement: (tag) => new FakeNode(tag),
  createTextNode: (value) => { const node = new FakeNode("#text"); node.textContent = value; return node; },
  createDocumentFragment: () => new FakeNode(),
};
Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async () => {} } }, configurable: true });

const root = process.argv[2];
const load = async (name) => import(pathToFileURL(`${root}\\${name}`));
const dependencies = await load("dependencies.js");
const formatting = await load("format.js");
const routeState = await load("state.js");
const runId = "11111111-1111-4111-8111-111111111111";
const id = (digit) => digit.repeat(64);
const advisory = (key, priority = "HIGH") => ({
  canonical_advisory_id: key, finding_id: id(key === "CVE-2020-14343" ? "a" : "b"),
  osv_record_ids: ["OSV-2020-1", "GHSA-aaaa-bbbb-cccc"], aliases: [key, "OTHER-1"],
  cve_aliases: key.startsWith("CVE") ? [key] : [], ghsa_aliases: ["GHSA-aaaa-bbbb-cccc"],
  fixed_versions: ["5.4"], priority_band: priority,
});
const item = (component_ref, name, evaluation, count, advisories = [], extras = {}) => ({
  component_ref, name, version: "5.3.1", package_type: "python", purl: `pkg:pypi/${name}@5.3.1`,
  locations: [{ kind: "REPOSITORY_PATH", path: "requirements.txt" }, { kind: "REPOSITORY_PATH", path: "services/api/requirements.lock" }],
  vulnerability_evaluation: evaluation, vulnerability_evaluation_reason: evaluation === "PARTIAL" ? "SYFT_PREREQUISITE_PARTIAL" : null,
  known_vulnerability_count: count, advisories, advisory_aliases: [], fixed_versions: [], priority_bands: [], ...extras,
});
const items = [
  item(id("1"), "<script>PyYAML</script>", "COMPLETE", 1, [advisory("CVE-2020-14343", "UNRANKED")], { purl: "pkg:pypi/" + "x".repeat(700) + "\u202Efdp.exe" }),
  item(id("2"), "requests", "COMPLETE", 0),
  item(id("3"), "partial-observed", "PARTIAL", null, [advisory("CVE-1"), advisory("GHSA-2")]),
  item(id("4"), "partial-empty", "PARTIAL", null),
  item(id("5"), "failed-package", "FAILED", null),
  item(id("6"), "not-applicable", "NOT_APPLICABLE", null, [], { version: null, purl: null, locations: [] }),
];
const page = (values = items, total = 120, offset = 0) => ({ items: values, total, limit: 50, offset });
const region = () => new FakeNode("section");
const nodes = (rootNode, predicate, found = []) => { if (predicate(rootNode)) found.push(rootNode); for (const child of rootNode.children) nodes(child, predicate, found); return found; };
const byClass = (rootNode, name) => nodes(rootNode, (node) => String(node.className).split(" ").includes(name));
const byAttr = (rootNode, name, value) => nodes(rootNode, (node) => node.attributes.get(name) === value);
const byText = (rootNode, tag, value) => nodes(rootNode, (node) => node.tagName === tag && node.textContent === value);
const expect = (rootNode, value) => { if (!rootNode.textContent.includes(value)) throw new Error(`Missing text: ${value}`); };
const deferred = () => { let resolve; const promise = new Promise((yes) => { resolve = yes; }); return { promise, resolve }; };
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const media = (matches) => ({ matches, listeners: new Set(), addEventListener(_name, fn) { this.listeners.add(fn); }, removeEventListener(_name, fn) { this.listeners.delete(fn); } });
const responsive = (mode) => ({ desktop: media(mode === "desktop"), mobile: media(mode === "mobile") });
const navigation = (initial = "") => { let search = initial; const urls = []; const push = (url) => { urls.push(url); search = new URL(url, "http://local").search; }; return { search: () => search, push, urls }; };
const click = (node) => node.listeners.get("click")({ defaultPrevented: false, button: 0, metaKey: false, ctrlKey: false, shiftKey: false, altKey: false, preventDefault() {} });
const render = (target, services, options = {}) => { routeState.beginRoute({ name: "dependencies", runId }); const nav = navigation(options.search || ""); const controller = dependencies.renderDependenciesPage({ region: target, route: { name: "dependencies", runId }, services, navigation: nav, responsive: responsive(options.mode || "desktop") }); return { controller, nav }; };

const complete = formatting.dependencyEvaluation("COMPLETE", 1, 1);
const clean = formatting.dependencyEvaluation("COMPLETE", 0, 0);
const partial = formatting.dependencyEvaluation("PARTIAL", null, 2);
if (complete.result !== "1 known vulnerability" || clean.result !== "0 known vulnerabilities" || partial.result !== "Unknown" || partial.observed !== "2 observed advisories") throw new Error("Dependency truth table changed");
for (const [state, expected] of [["FAILED", "Unknown"], ["NOT_APPLICABLE", "N/A"], ["FUTURE", "Unknown"]]) if (formatting.dependencyEvaluation(state, null).result !== expected) throw new Error(`Bad ${state} rendering`);
const parsed = dependencies.readDependencyUrlState(`?offset=50&component=${id("1")}`);
if (parsed.offset !== 50 || parsed.component !== id("1")) throw new Error("Dependency query state not restored");
if (dependencies.readDependencyUrlState("?offset=-1&component=bad").component !== null) throw new Error("Unsafe component state accepted");

let target = region(); let calls = [];
let result = render(target, { getDependencies: async (_run, options) => { calls.push(options); return page(); } });
await result.controller.settled;
for (const text of ["120 packages", "1 known vulnerability", "0 known vulnerabilities", "2 observed advisories", "Unknown", "N/A", "Version not reported"]) expect(target, text);
if (nodes(target, (node) => node.tagName === "SCRIPT").length) throw new Error("Hostile package name became markup");

const selected = nodes(target, (node) => node.dataset.componentRef === id("1"))[0];
click(selected); await tick();
const detail = byClass(target, "dependency-detail-region")[0];
for (const text of ["<script>PyYAML</script>", "Vulnerability evaluation", "Complete", "Known vulnerabilities1 known vulnerability", "CVE-2020-14343", "Priority not assigned", "Fixed versions reported by advisory", "5.4", "requirements.txt", "services/api/requirements.lock", "OTHER-1", "OSV-2020-1"]) expect(detail, text);
for (const forbidden of ["Recommended upgrade", "Safe version", "Upgrade to", "Risk"]) if (detail.textContent.includes(forbidden)) throw new Error(`Invented dependency claim: ${forbidden}`);
if (calls.length !== 1) throw new Error("Detail selection called the API");

click(nodes(target, (node) => node.dataset.componentRef === id("3"))[0]); await tick();
expect(byClass(target, "dependency-detail-region")[0], "Known vulnerabilitiesUnknownObserved advisories2");
const search = byAttr(target, "type", "search")[0]; search.value = "requests"; search.listeners.get("input")();
expect(target, "1 match on this page · 120 packages total");
if (calls.length !== 1) throw new Error("Local dependency search called the API");
search.value = ""; search.listeners.get("input")();
click(byText(target, "BUTTON", "Next")[0]); await tick(); await tick();
if (calls.at(-1).offset !== 50 || !result.nav.urls.at(-1).includes("offset=50") || result.nav.urls.at(-1).includes("component=")) throw new Error("Dependency pagination changed");

target = region();
result = render(target, { getDependencies: async () => page() }, { search: `?component=${id("2")}` });
await result.controller.settled; expect(byClass(target, "dependency-detail-region")[0], "0 known vulnerabilities");
target = region();
result = render(target, { getDependencies: async () => page() }, { search: `?component=${id("9")}` });
await result.controller.settled; expect(target, "Package not present in this page");

target = region();
const pending = deferred(); let staleSignal = null;
result = render(target, { getDependencies: async (_run, options) => { staleSignal = options.signal; return pending.promise; } });
routeState.beginRoute({ name: "findings", runId });
if (!staleSignal.aborted) throw new Error("Dependency request not aborted on route change");
pending.resolve(page()); await result.controller.settled;
if (target.textContent.includes("120 packages")) throw new Error("Stale dependency response mutated route");

target = region(); result = render(target, { getDependencies: async () => page([], 0) }); await result.controller.settled;
expect(target, "No package inventory was published for this scan."); expect(target, "Review Coverage");
for (const [status, code, title] of [[409, "PRODUCT_CORE_NOT_READY", "Dependencies not ready"], [503, "QUERY_UNAVAILABLE", "Dependency data unavailable"]]) {
  target = region(); result = render(target, { getDependencies: async () => { const error = new Error("private path"); error.status = status; error.code = code; throw error; } }); await result.controller.settled; expect(target, title); if (target.textContent.includes("private path")) throw new Error("Raw dependency error leaked");
}

target = region(); result = render(target, { getDependencies: async () => page() }, { mode: "tablet" }); await result.controller.settled;
const row = nodes(target, (node) => node.dataset.componentRef === id("1"))[0]; row.focus(); click(row); await tick();
const dialog = nodes(target, (node) => node.tagName === "DIALOG")[0]; if (!dialog.open || document.activeElement.textContent !== "Close") throw new Error("Dependency drawer focus changed");
click(byText(dialog, "BUTTON", "Close")[0]); if (dialog.open || document.activeElement.dataset.componentRef !== id("1")) throw new Error("Dependency drawer focus not restored");

target = region(); result = render(target, { getDependencies: async () => page() }, { mode: "mobile" }); await result.controller.settled;
click(nodes(target, (node) => node.dataset.componentRef === id("6"))[0]); await tick();
if (!byClass(target, "dependencies-workspace")[0].className.includes("dependencies-has-selection")) throw new Error("Mobile dependency detail not activated");
expect(byClass(target, "dependency-mobile-detail")[0], "N/A");
click(byText(target, "BUTTON", "Back to dependencies")[0]);
if (byClass(target, "dependencies-workspace")[0].className.includes("dependencies-has-selection")) throw new Error("Mobile dependency back failed");
'''
    harness_path = tmp_path / "c5-runtime.mjs"
    harness_path.write_text(harness, encoding="utf-8")
    windows_root = subprocess.run(["wslpath", "-w", str(tmp_path)], check=True, capture_output=True, text=True).stdout.strip()
    windows_harness = subprocess.run(["wslpath", "-w", str(harness_path)], check=True, capture_output=True, text=True).stdout.strip()
    result = subprocess.run([str(node), windows_harness, windows_root], check=False, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr

# ruff: noqa: E501 -- executable JavaScript fixture stays readable as source.

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_WEB_ROOT = _REPOSITORY_ROOT / "src" / "securescan" / "web"
_SOURCES = {
    path.name: path.read_text(encoding="utf-8")
    for path in sorted(_WEB_ROOT.glob("*.js"))
}
_STYLES = "\n".join(
    path.read_text(encoding="utf-8") for path in sorted(_WEB_ROOT.glob("*.css"))
)


def _node() -> Path | None:
    windows_node = Path("/mnt/c/Program Files/nodejs/node.exe")
    return windows_node if windows_node.is_file() else None


def test_c4_uses_only_frozen_findings_and_lazy_report_endpoints() -> None:
    api = _SOURCES["api.js"]
    findings = _SOURCES["findings.js"]
    assert 'getJson(`/v1/scans/${segment}/findings?' in api
    assert 'getJson(`/v1/scans/${segment}/report`' in api
    assert "services.getFindings(runId" in findings
    assert "services.getScanReport(runId" in findings
    assert "ensureReport()" in findings
    for forbidden in (
        "getDependencies",
        "getCoverage",
        "getGaps",
        "getComponents",
        "/dependencies",
        "/coverage",
        "/gaps",
        "EPSS",
        "KEV",
        "Accept Risk",
        "False Positive",
        "Suppress",
    ):
        assert forbidden not in findings


def test_filters_ordering_vocabularies_and_query_state_match_product_core() -> None:
    findings = _SOURCES["findings.js"]
    api = _SOURCES["api.js"]
    for name in ("authority", "category", "priority", "lifecycle_state"):
        assert name in findings
        assert name in api
    for value in (
        "semgrep-ce",
        "gitleaks",
        "osv.dev",
        "checkov",
        "CODE_SECURITY",
        "SECRET_EXPOSURE",
        "DEPENDENCY_VULNERABILITY",
        "CONFIGURATION_SECURITY",
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
        "UNRANKED",
        "NEW",
        "EXISTING",
        "RESOLVED",
        "REOPENED",
    ):
        assert value in findings
    assert "FINDING_ID_PATTERN = /^[0-9a-f]{64}$/" in findings
    assert "URLSearchParams" in findings
    assert "state.offset = 0" in findings
    assert "limit: FINDING_PAGE_LIMIT" in findings


def test_detail_correlation_is_exact_and_authority_specific() -> None:
    findings = _SOURCES["findings.js"]
    assert "finding.finding_id === summary.finding_id" in findings
    assert "matches.length !== 1" in findings
    assert "matches[0].authority !== summary.authority" in findings
    assert "matches[0].category !== summary.category" in findings
    assert "primary_evidence_refs" in findings
    assert "evidence.authority !== summary.authority" in findings
    for kind in (
        "SEMGREP_RULE_MATCH",
        "GITLEAKS_SECRET_OBSERVATION",
        "CHECKOV_POLICY_OBSERVATION",
        "OSV_ADVISORY_GROUP",
    ):
        assert kind in findings
    for unsafe_match in ("includes(summary.finding_id", "path-only", "similarity", "fuzzy"):
        assert unsafe_match not in findings.lower()


def test_truthful_detail_omits_unsupported_product_claims() -> None:
    findings = _SOURCES["findings.js"].lower()
    for unsupported in (
        "remediation",
        "exploitability",
        "reachability",
        "business impact",
        "confidence score",
        "risk score",
        "repository secure",
        "all clear",
        "no vulnerabilities found",
        "cvss",
    ):
        assert unsupported not in findings
    assert "priority_reason_codes" in findings
    assert "scanner severity" in findings
    assert "securescan priority" in findings
    assert "review coverage before interpreting this result as clean" in findings
    assert "the system did not substitute an empty result" in findings


def test_split_drawer_mobile_and_accessibility_contract_is_explicit() -> None:
    findings = _SOURCES["findings.js"]
    for marker in (
        'createElement("ol"',
        'createElement("a"',
        'createElement("dialog"',
        'role: "dialog"',
        '"aria-modal": "true"',
        "showModal()",
        "dialogClose.focus()",
        'textContent: "Back to findings"',
        'textContent: "Search this page"',
        'textContent: "Filters only the currently loaded page."',
        'createElement("details"',
    ):
        assert marker in findings
    assert "@media (min-width: 768px) and (max-width: 1199px)" in _STYLES
    assert "@media (max-width: 767px)" in _STYLES
    assert "grid-template-columns: minmax(320px, 0.42fr)" in _STYLES
    assert ".findings-has-selection .finding-list-pane" in _STYLES
    assert "unicode-bidi: isolate" in _STYLES


def test_c4_runtime_filters_search_pagination_details_cache_and_races(
    tmp_path: Path,
) -> None:
    node = _node()
    if node is None:
        pytest.skip("Node is not available for executable C4 module tests")
    for name, source in _SOURCES.items():
        (tmp_path / name).write_text(source.replace('"/assets/', '"./'), encoding="utf-8")

    harness = r'''
import { pathToFileURL } from "node:url";

class FakeNode {
  constructor(tagName = "#fragment") {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.attributes = new Map();
    this.dataset = {};
    this.className = "";
    this.disabled = false;
    this.hidden = false;
    this.inert = false;
    this.isConnected = true;
    this.listeners = new Map();
    this._text = "";
    this.value = "";
    this.selected = false;
    this.open = false;
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent || "").join(""); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) {
    for (const child of this.children) if (child && typeof child === "object") child.isConnected = false;
    this._text = "";
    this.children = [...children];
    for (const child of this.children) if (child && typeof child === "object") child.isConnected = true;
  }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  removeAttribute(name) { this.attributes.delete(name); }
  hasAttribute(name) { return this.attributes.has(name); }
  addEventListener(name, listener) { this.listeners.set(name, listener); }
  contains(node) { return this === node || this.children.some((child) => child.contains && child.contains(node)); }
  querySelector(selector) {
    const data = /^\[data-finding-id="([0-9a-f]+)"\]$/.exec(selector);
    if (data && this.dataset.findingId === data[1]) return this;
    if (selector.startsWith(".") && this.className.split(" ").includes(selector.slice(1))) return this;
    if (selector.toUpperCase() === this.tagName) return this;
    for (const child of this.children) {
      const match = child.querySelector ? child.querySelector(selector) : null;
      if (match) return match;
    }
    return null;
  }
  focus() { document.activeElement = this; }
  showModal() { this.open = true; }
  close() {
    this.open = false;
    const listener = this.listeners.get("close");
    if (listener) listener({ target: this });
  }
}

globalThis.Node = FakeNode;
globalThis.HTMLElement = FakeNode;
globalThis.document = {
  activeElement: null,
  createElement: (tagName) => new FakeNode(tagName),
  createTextNode: (value) => { const node = new FakeNode("#text"); node.textContent = value; return node; },
  createDocumentFragment: () => new FakeNode(),
};
Object.defineProperty(globalThis, "navigator", {
  value: { clipboard: { writeText: async () => {} } }, configurable: true,
});

const root = process.argv[2];
const load = async (name) => import(pathToFileURL(`${root}\\${name}`));
const findings = await load("findings.js");
const state = await load("state.js");
const runId = "11111111-1111-4111-8111-111111111111";
const fid = (digit) => digit.repeat(64);
const ids = { semgrep: fid("a"), gitleaks: fid("b"), checkov: fid("c"), osv: fid("d"), odd: fid("e"), duplicate: fid("f") };
const ref = { semgrep: fid("1"), gitleaks: fid("2"), checkov: fid("3"), osv: fid("4"), revision: fid("5") };
const now = "2026-09-25T10:00:00Z";
const summaries = [
  { finding_id: ids.semgrep, authority: "semgrep-ce", category: "CODE_SECURITY", severity: "HIGH", priority_band: "HIGH", priority_reason_codes: ["SCANNER_NORMALIZED_SEVERITY"], lifecycle_state: "NEW", first_seen_at: now, last_seen_at: now, resolved_at: null, subject: { kind: "SOURCE_CODE", rule_id: "python.lang.security.dangerous-eval" }, primary_location: { kind: "SOURCE_SPAN", path: "src/api/process.py", start_line: 87, end_line: 87 } },
  { finding_id: ids.gitleaks, authority: "gitleaks", category: "SECRET_EXPOSURE", severity: null, priority_band: "CRITICAL", priority_reason_codes: ["SECRET_EXPOSURE"], lifecycle_state: "EXISTING", first_seen_at: now, last_seen_at: now, resolved_at: null, subject: { kind: "SECRET_EXPOSURE", rule_id: "github-pat", detection_kind: "CONTENT" }, primary_location: { kind: "SOURCE_SPAN", path: "config/example.env", start_line: 4, end_line: 4 } },
  { finding_id: ids.checkov, authority: "checkov", category: "CONFIGURATION_SECURITY", severity: "HIGH", priority_band: "UNRANKED", priority_reason_codes: ["SCANNER_SEVERITY_NOT_MAPPED"], lifecycle_state: "REOPENED", first_seen_at: now, last_seen_at: now, resolved_at: null, subject: { kind: "CONFIGURATION_RESOURCE", framework: "dockerfile", resource: "dockerfile.Dockerfile" }, primary_location: { kind: "REPOSITORY_PATH", path: "Dockerfile" } },
  { finding_id: ids.osv, authority: "osv.dev", category: "DEPENDENCY_VULNERABILITY", severity: null, priority_band: "HIGH", priority_reason_codes: ["DEPENDENCY_ADVISORY"], lifecycle_state: "RESOLVED", first_seen_at: now, last_seen_at: now, resolved_at: "2026-09-25T11:00:00Z", subject: { kind: "PACKAGE", component_ref: fid("9") }, primary_location: { kind: "REPOSITORY_PATH", path: "requirements.txt" } },
  { finding_id: ids.odd, authority: "future-authority", category: "FUTURE_CATEGORY", severity: null, priority_band: "UNRANKED", priority_reason_codes: [], lifecycle_state: "FUTURE_STATE", first_seen_at: now, last_seen_at: now, resolved_at: null, subject: { kind: "UNKNOWN", nested: { value: "must-not-stringify" } }, primary_location: null },
  { finding_id: ids.duplicate, authority: "semgrep-ce", category: "CODE_SECURITY", severity: "MEDIUM", priority_band: "MEDIUM", priority_reason_codes: [], lifecycle_state: "NEW", first_seen_at: now, last_seen_at: now, resolved_at: null, subject: { kind: "SOURCE_CODE", rule_id: "python.lang.security.dangerous-eval" }, primary_location: { kind: "REPOSITORY_PATH", path: "x".repeat(500) + "\u202Efdp.exe" } },
];
const report = {
  run_id: runId,
  report: {
    schema_version: "securescan-unified-evidence-s4-v1",
    findings: [
      { finding_id: ids.semgrep, authority: "semgrep-ce", category: "CODE_SECURITY", native_finding_identity: fid("6"), primary_evidence_refs: [ref.semgrep], subject: summaries[0].subject },
      { finding_id: ids.gitleaks, authority: "gitleaks", category: "SECRET_EXPOSURE", native_finding_identity: fid("7"), primary_evidence_refs: [ref.gitleaks], subject: summaries[1].subject },
      { finding_id: ids.checkov, authority: "checkov", category: "CONFIGURATION_SECURITY", native_finding_identity: fid("8"), primary_evidence_refs: [ref.checkov], subject: summaries[2].subject },
      { finding_id: ids.osv, authority: "osv.dev", category: "DEPENDENCY_VULNERABILITY", native_finding_identity: fid("0"), primary_evidence_refs: [ref.revision, ref.osv], subject: summaries[3].subject },
    ],
    evidence: [
      { evidence_id: ref.semgrep, authority: "semgrep-ce", evidence_kind: "SEMGREP_RULE_MATCH", payload: { kind: "SEMGREP_RULE_MATCH", message: "<script>Potential command injection</script>", rule_id: "python.lang.security.dangerous-eval", cwe_ids: ["CWE-78"] } },
      { evidence_id: ref.gitleaks, authority: "gitleaks", evidence_kind: "GITLEAKS_SECRET_OBSERVATION", payload: { kind: "GITLEAKS_SECRET_OBSERVATION", rule_id: "github-pat", detection_kind: "CONTENT", native_occurrence_count: 1 } },
      { evidence_id: ref.checkov, authority: "checkov", evidence_kind: "CHECKOV_POLICY_OBSERVATION", payload: { kind: "CHECKOV_POLICY_OBSERVATION", check_id: "CKV_DOCKER_3", check_name: "Ensure container runs as a non-root user", resource: "dockerfile.Dockerfile", framework: "dockerfile" } },
      { evidence_id: ref.revision, authority: "osv.dev", evidence_kind: "OSV_ADVISORY_REVISION", payload: { kind: "OSV_ADVISORY_REVISION", osv_record_id: "GHSA-test" } },
      { evidence_id: ref.osv, authority: "osv.dev", evidence_kind: "OSV_ADVISORY_GROUP", payload: { kind: "OSV_ADVISORY_GROUP", canonical_advisory_id: "CVE-2020-14343" } },
    ],
    components: [
      { component_ref: fid("9"), component_kind: "PACKAGE", payload: { kind: "PACKAGE_COMPONENT", package_name: "PyYAML", package_version: "5.3.1", package_type: "python", purl: "pkg:pypi/pyyaml@5.3.1" } },
    ],
  },
};

const page = (items = summaries, total = 120, offset = 0) => ({ items, total, limit: 50, offset });
const region = () => new FakeNode("section");
const nodes = (rootNode, predicate, found = []) => {
  if (predicate(rootNode)) found.push(rootNode);
  for (const child of rootNode.children) nodes(child, predicate, found);
  return found;
};
const byClass = (rootNode, className) => nodes(rootNode, (node) => String(node.className).split(" ").includes(className));
const byAttribute = (rootNode, name, value) => nodes(rootNode, (node) => node.attributes.get(name) === value);
const byText = (rootNode, tagName, value) => nodes(rootNode, (node) => node.tagName === tagName && node.textContent === value);
const expectText = (node, value) => { if (!node.textContent.includes(value)) throw new Error(`Missing text: ${value}`); };
const deferred = () => { let resolve; let reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const media = (matches) => ({ matches, listeners: new Set(), addEventListener(_name, fn) { this.listeners.add(fn); }, removeEventListener(_name, fn) { this.listeners.delete(fn); } });
const responsive = (mode) => ({ desktop: media(mode === "desktop"), mobile: media(mode === "mobile") });
const navigation = (initial = "") => {
  let search = initial;
  const urls = [];
  const write = (url) => { urls.push(url); search = new URL(url, "http://securescan.local").search; };
  return { search: () => search, push: write, replace: write, urls };
};
const click = (node) => node.listeners.get("click")({ defaultPrevented: false, button: 0, metaKey: false, ctrlKey: false, shiftKey: false, altKey: false, preventDefault() {} });
const render = (target, services, { mode = "desktop", search = "" } = {}) => {
  state.beginRoute({ name: "findings", runId });
  const nav = navigation(search);
  const controller = findings.renderFindingsPage({ region: target, route: { name: "findings", runId }, services, navigation: nav, responsive: responsive(mode) });
  return { controller, nav };
};

// Query state accepts only exact allowlisted filters, safe offsets, and canonical finding IDs.
const parsedState = findings.readFindingUrlState(`?priority=HIGH&category=CODE_SECURITY&lifecycle_state=NEW&authority=semgrep-ce&offset=50&finding=${ids.semgrep}`);
if (parsedState.priority !== "HIGH" || parsedState.category !== "CODE_SECURITY" || parsedState.lifecycle_state !== "NEW" || parsedState.authority !== "semgrep-ce" || parsedState.offset !== 50 || parsedState.finding !== ids.semgrep) throw new Error("Valid finding query state was not restored");
const rejectedState = findings.readFindingUrlState("?priority=urgent&category=OTHER&lifecycle_state=OPEN&authority=custom&offset=-1&finding=not-an-id");
if (rejectedState.priority || rejectedState.category || rejectedState.lifecycle_state || rejectedState.authority || rejectedState.offset !== 0 || rejectedState.finding) throw new Error("Unsafe finding query state was accepted");
const renderedQuery = findings.findingQuery({ ...parsedState, priority: "urgent", offset: -4 });
if (renderedQuery.includes("urgent") || renderedQuery.includes("offset=") || !renderedQuery.includes(`finding=${ids.semgrep}`)) throw new Error("Finding query rendering was not bounded");

// Populated desktop: report is lazy, every authority/lifecycle is truthful, and hostile text is inert.
let target = region();
let findingCalls = [];
let reportCalls = 0;
let services = {
  getFindings: async (_run, options) => { findingCalls.push(options); return page(); },
  getScanReport: async () => { reportCalls += 1; return report; },
};
let result = render(target, services);
await result.controller.settled;
expectText(target, "120 findings");
for (const text of ["python.lang.security.dangerous-eval", "github-pat", "dockerfile.Dockerfile", "Dependency vulnerability", "New", "Existing", "Reopened", "Resolved", "Unknown lifecycle", "Location unavailable"]) expectText(target, text);
if (reportCalls !== 0) throw new Error("Report loaded before selection");
if (target.textContent.includes("[object Object]")) throw new Error("Structured subject was stringified");

const linkFor = (id) => nodes(target, (node) => node.dataset.findingId === id)[0];
click(linkFor(ids.semgrep));
await tick(); await tick();
if (reportCalls !== 1) throw new Error("First detail did not load exactly one report");
let detail = byClass(target, "finding-detail-region")[0];
for (const text of ["<script>Potential command injection</script>", "Semgrep", "CWE-78", "Scanner severityHIGH", "SecureScan priorityHigh"]) expectText(detail, text);
if (detail.textContent.includes("Remediation") || detail.textContent.includes("risk score")) throw new Error("Unsupported detail invented");

click(linkFor(ids.checkov));
await tick();
detail = byClass(target, "finding-detail-region")[0];
for (const text of ["Ensure container runs as a non-root user", "Priority not assigned", "Reopened", "CKV_DOCKER_3"]) expectText(detail, text);
if (reportCalls !== 1) throw new Error("Report cache was not reused");

click(linkFor(ids.gitleaks));
await tick();
detail = byClass(target, "finding-detail-region")[0];
for (const text of ["github-pat", "Gitleaks", "CONTENT"]) expectText(detail, text);
if (/raw[_ -]?secret|secret value/i.test(detail.textContent)) throw new Error("Secret material field was exposed");

click(linkFor(ids.osv));
await tick();
detail = byClass(target, "finding-detail-region")[0];
for (const text of ["CVE-2020-14343", "PyYAML 5.3.1", "pkg:pypi/pyyaml@5.3.1", "Resolved"]) expectText(detail, text);
if (reportCalls !== 1) throw new Error("Subsequent detail fetched another report");

click(linkFor(ids.odd));
await tick();
detail = byClass(target, "finding-detail-region")[0];
expectText(detail, "No exact report evidence matched this finding ID.");
if (reportCalls !== 1) throw new Error("Missing evidence bypassed the report cache");

// Current-page search never calls the server or changes the authoritative total.
const search = byAttribute(target, "type", "search")[0];
search.value = "example.env";
search.listeners.get("input")();
expectText(target, "1 match on this page · 120 findings for selected server filters");
if (findingCalls.length !== 1) throw new Error("Current-page search called the API");
search.value = "";
search.listeners.get("input")();

// Pagination and exact server filters issue one request and update bounded URL state.
click(byText(target, "BUTTON", "Next")[0]);
await tick(); await tick();
if (findingCalls.at(-1).offset !== 50) throw new Error("Pagination offset changed");
if (!result.nav.urls.at(-1).includes("offset=50") || result.nav.urls.at(-1).includes("finding=")) throw new Error("Pagination URL state changed");
const priority = byAttribute(target, "name", "priority")[0];
priority.value = "HIGH";
priority.listeners.get("change")();
await tick(); await tick();
if (findingCalls.at(-1).priority !== "HIGH" || findingCalls.at(-1).offset !== 0) throw new Error("Server priority filter changed");
if (!result.nav.urls.at(-1).includes("priority=HIGH") || result.nav.urls.at(-1).includes("offset=")) throw new Error("Filter URL state changed");

// A durable deep link restores selection, while an unlisted exact ID stays bounded to this page.
target = region();
reportCalls = 0;
result = render(target, { getFindings: async () => page(), getScanReport: async () => { reportCalls += 1; return report; } }, { search: `?finding=${ids.semgrep}` });
await result.controller.settled;
await tick(); await tick();
expectText(byClass(target, "finding-detail-region")[0], "Potential command injection");
if (reportCalls !== 1) throw new Error("Deep-linked finding did not lazily load one report");

target = region();
reportCalls = 0;
result = render(target, { getFindings: async () => page(), getScanReport: async () => { reportCalls += 1; return report; } }, { search: `?finding=${fid("8")}` });
await result.controller.settled;
expectText(target, "Finding not present in this page");
if (reportCalls !== 0) throw new Error("Unlisted finding ID triggered report or page crawling");

// One in-flight report is shared; selecting B before settlement never reopens A.
target = region();
const pendingReport = deferred();
reportCalls = 0;
services = {
  getFindings: async () => page(),
  getScanReport: async () => { reportCalls += 1; return pendingReport.promise; },
};
result = render(target, services);
await result.controller.settled;
click(nodes(target, (node) => node.dataset.findingId === ids.semgrep)[0]);
click(nodes(target, (node) => node.dataset.findingId === ids.checkov)[0]);
if (reportCalls !== 1) throw new Error("Concurrent selections did not share report request");
pendingReport.resolve(report);
await tick(); await tick();
detail = byClass(target, "finding-detail-region")[0];
expectText(detail, "Ensure container runs as a non-root user");
if (detail.textContent.includes("Potential command injection")) throw new Error("Late detail A replaced detail B");

// Changing page during report load clears selection; settlement cannot reopen it.
target = region();
const pageReport = deferred();
services = { getFindings: async (_run, options) => page(summaries, 120, options.offset), getScanReport: async () => pageReport.promise };
result = render(target, services);
await result.controller.settled;
click(nodes(target, (node) => node.dataset.findingId === ids.semgrep)[0]);
click(byText(target, "BUTTON", "Next")[0]);
await tick(); await tick();
pageReport.resolve(report);
await tick(); await tick();
if (byClass(target, "findings-workspace")[0].className.includes("findings-has-selection")) throw new Error("Old detail reopened after page change");

// Rapid server-filter changes abort and ignore the older request while retaining valid filters.
target = region();
const firstFilter = deferred();
const secondFilter = deferred();
let filterCall = 0;
let firstFilterSignal = null;
services = {
  getFindings: async (_run, options) => {
    filterCall += 1;
    if (filterCall === 1) return page();
    if (filterCall === 2) { firstFilterSignal = options.signal; return firstFilter.promise; }
    return secondFilter.promise;
  },
  getScanReport: async () => report,
};
result = render(target, services);
await result.controller.settled;
const rapidPriority = byAttribute(target, "name", "priority")[0];
rapidPriority.value = "HIGH";
rapidPriority.listeners.get("change")();
const rapidCategory = byAttribute(target, "name", "category")[0];
rapidCategory.value = "CONFIGURATION_SECURITY";
rapidCategory.listeners.get("change")();
if (!firstFilterSignal.aborted) throw new Error("Superseded filter request was not aborted");
firstFilter.resolve(page([summaries[0]], 1));
secondFilter.resolve(page([summaries[2]], 1));
await tick(); await tick();
expectText(target, "dockerfile.Dockerfile");
if (target.textContent.includes("src/api/process.py")) throw new Error("Stale filter response replaced the current result");
if (!result.nav.urls.at(-1).includes("priority=HIGH") || !result.nav.urls.at(-1).includes("category=CONFIGURATION_SECURITY")) throw new Error("Rapid filters did not preserve valid query state");

// A stale findings request is aborted and ignored when navigating to another run/route.
target = region();
const pendingFindings = deferred();
let staleSignal = null;
result = render(target, { getFindings: async (_run, { signal }) => { staleSignal = signal; return pendingFindings.promise; }, getScanReport: async () => report });
state.beginRoute({ name: "scan", runId: "22222222-2222-4222-8222-222222222222" });
if (!staleSignal.aborted) throw new Error("Navigation did not abort findings request");
pendingFindings.resolve(page());
await result.controller.settled;
if (target.textContent.includes("120 findings")) throw new Error("Late run A findings mutated run B route");

// Summary errors, global empty, filtered empty, and report failure stay truthful.
target = region();
result = render(target, { getFindings: async () => page([], 0), getScanReport: async () => report });
await result.controller.settled;
expectText(target, "No findings were reported by the analyses that completed for this scan.");
expectText(target, "Review Coverage before interpreting this result as clean.");

target = region();
result = render(target, { getFindings: async () => page([], 0), getScanReport: async () => report }, { search: "?priority=HIGH" });
await result.controller.settled;
expectText(target, "No matching findings");
expectText(target, "Clear filters");

target = region();
result = render(target, { getFindings: async () => { const error = new Error("database secret"); error.status = 503; throw error; }, getScanReport: async () => report });
await result.controller.settled;
expectText(target, "Findings unavailable");
expectText(target, "The system did not substitute an empty result.");
if (target.textContent.includes("database secret")) throw new Error("Raw findings error leaked");

target = region();
result = render(target, { getFindings: async () => { const error = new Error("not-found secret"); error.status = 404; throw error; }, getScanReport: async () => report });
await result.controller.settled;
expectText(target, "Scan not found");
expectText(target, "SCAN_NOT_FOUND");
if (target.textContent.includes("not-found secret")) throw new Error("Raw 404 error leaked");

target = region();
result = render(target, { getFindings: async () => { const error = new Error("not-ready secret"); error.status = 409; error.code = "PRODUCT_CORE_NOT_READY"; throw error; }, getScanReport: async () => report });
await result.controller.settled;
expectText(target, "Findings not ready");
expectText(target, "PRODUCT_CORE_NOT_READY");
expectText(target, "Open Scan Overview");
if (target.textContent.includes("not-ready secret") || target.textContent.includes("0 findings")) throw new Error("409 was rendered unsafely");

target = region();
result = render(target, { getFindings: async () => page(), getScanReport: async () => { throw new Error("report secret"); } });
await result.controller.settled;
click(nodes(target, (node) => node.dataset.findingId === ids.semgrep)[0]);
await tick(); await tick();
expectText(target, "Technical evidence unavailable");
expectText(target, "SecureScan could not load the verified evidence report.");
expectText(target, "python.lang.security.dangerous-eval");
if (target.textContent.includes("report secret")) throw new Error("Raw report error leaked");

// Exact correlation rejects a category mismatch and never falls back to title/path matching.
const changed = structuredClone(report);
changed.report.findings[0].category = "SECRET_EXPOSURE";
if (findings.correlateFindingEvidence(summaries[0], changed) !== null) throw new Error("Inexact correlation accepted");

// Tablet uses modal detail and restores focus; mobile uses dedicated detail/back state.
target = region();
result = render(target, { getFindings: async () => page(), getScanReport: async () => report }, { mode: "tablet" });
await result.controller.settled;
const tabletRow = nodes(target, (node) => node.dataset.findingId === ids.checkov)[0];
tabletRow.focus();
click(tabletRow);
await tick(); await tick();
const dialog = nodes(target, (node) => node.tagName === "DIALOG")[0];
if (!dialog.open || document.activeElement.textContent !== "Close") throw new Error("Tablet detail dialog did not open accessibly");
click(byText(dialog, "BUTTON", "Close")[0]);
if (dialog.open || document.activeElement.dataset.findingId !== ids.checkov) throw new Error("Tablet focus was not restored to finding row");

target = region();
result = render(target, { getFindings: async () => page(), getScanReport: async () => report }, { mode: "mobile" });
await result.controller.settled;
click(nodes(target, (node) => node.dataset.findingId === ids.osv)[0]);
await tick(); await tick();
if (!byClass(target, "findings-workspace")[0].className.includes("findings-has-selection")) throw new Error("Mobile detail state did not activate");
expectText(byClass(target, "finding-mobile-detail")[0], "CVE-2020-14343");
click(byText(target, "BUTTON", "Back to findings")[0]);
if (byClass(target, "findings-workspace")[0].className.includes("findings-has-selection")) throw new Error("Mobile back did not restore list state");
'''
    harness_path = tmp_path / "c4-runtime.mjs"
    harness_path.write_text(harness, encoding="utf-8")
    windows_root = subprocess.run(
        ["wslpath", "-w", str(tmp_path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    windows_harness = subprocess.run(
        ["wslpath", "-w", str(harness_path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    result = subprocess.run(
        [str(node), windows_harness, windows_root],
        check=False,
        capture_output=True,
        text=True,
        timeout=40,
    )
    assert result.returncode == 0, result.stderr

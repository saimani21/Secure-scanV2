from __future__ import annotations

# ruff: noqa: E501 -- executable JavaScript fixture stays readable as source.
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


def test_scan_route_uses_only_frozen_c3_resources() -> None:
    api = _SOURCES["api.js"]
    scan = _SOURCES["scan.js"]
    assert 'getJson(`/v1/scans/${segment}`' in api
    assert 'getJson(`/v1/scans/${segment}/stages`' in api
    assert "services.getScanSummary(runId" in scan
    assert "services.getScanStages(runId" in scan
    assert "services.getProject(projectId" in scan
    for forbidden in (
        "getFindings",
        "getDependencies",
        "getCoverage",
        "getGaps",
        "getReport",
        "/findings",
        "/dependencies",
        "/coverage",
        "/gaps",
        "/report",
    ):
        assert forbidden not in scan


def test_product_progress_coverage_and_stage_identity_are_fixed_allowlists() -> None:
    format_source = _SOURCES["format.js"]
    scan = _SOURCES["scan.js"]
    for value in (
        "QUEUED",
        "RUNNING",
        "PUBLISHED_PENDING_FINALIZATION",
        "BLOCKED_BY_PREDECESSOR",
        "COMPLETED",
        "CANCELLED",
        "FAILED",
    ):
        assert value in format_source
        assert value in scan
    for value in (
        "PENDING",
        "WAITING",
        "RUNNING",
        "COMPLETE",
        "PARTIAL",
        "FAILED",
        "CANCELLED",
        "NOT_APPLICABLE",
    ):
        assert value in format_source
    for value in (
        "COMPLETE_WITH_FINDINGS",
        "COMPLETE_WITH_SUPPRESSIONS",
        "NOT_APPLICABLE",
    ):
        assert value in format_source
    for identity in (
        "semgrep-ce/python_sast",
        "gitleaks/secret_detection",
        "syft/package_inventory",
        "osv.dev/dependency_advisory_matching",
        "checkov/configuration_security",
    ):
        assert identity in scan
    assert 'label: "Unknown status"' in format_source
    assert 'label: "Unknown state"' in format_source
    assert 'label: "Unknown analysis"' in scan


def test_metrics_never_turn_prepublication_or_unknown_values_into_zero() -> None:
    scan = _SOURCES["scan.js"]
    assert 'metric("Findings", "Pending")' in scan
    assert 'metric("Coverage", "Pending")' in scan
    assert 'metric("Gaps", "Pending")' in scan
    assert "nonnegativeInteger(summary.finding_count)" in scan
    assert 'summary.indexed === true' in scan
    assert "PRIORITY_ORDER" in scan
    for unsupported in ("risk score", "security score", "repository is clean", "safe repository"):
        assert unsupported not in scan.lower()


def test_polling_is_chained_bounded_and_route_owned() -> None:
    scan = _SOURCES["scan.js"]
    state = _SOURCES["state.js"]
    assert "SCAN_POLL_DELAY_MS = 5000" in scan
    assert "scheduler.setTimeout" in scan
    assert "setInterval" not in scan
    assert "refreshPromise" in scan
    assert "registerRouteCleanup(dispose)" in scan
    assert "clearPollTimer()" in scan
    assert "beginRequest()" in scan
    assert "request.isCurrent()" in scan
    assert "runRouteCleanups();" in state
    assert "abortPendingRequests();" in state


def test_scan_markup_is_semantic_responsive_and_keeps_details_stable() -> None:
    scan = _SOURCES["scan.js"]
    assert 'createElement("h1", { textContent: "Security scan" })' in scan
    assert 'createElement("ol"' in scan
    assert 'createElement("li", { className: "stage-row" }' in scan
    assert 'createElement("details", { className: "scan-technical-details" }' in scan
    assert "detailsList.replaceChildren" in scan
    assert "technicalDetails.replaceChildren" not in scan
    assert 'aria-label": "Refresh scan summary and analysis stages"' in scan
    assert "@media (max-width: 767px)" in _STYLES
    assert ".stage-row" in _STYLES
    assert "grid-template-columns: 1fr" in _STYLES
    assert ".topbar-breadcrumb" in _STYLES
    assert "overflow-wrap: anywhere" in _STYLES
    for forbidden in ("scanner-card", "chart", "canvas", "timeline", "glow"):
        assert forbidden not in scan.lower()


def test_scan_runtime_completed_running_failures_polling_and_races(tmp_path: Path) -> None:
    node = _node()
    if node is None:
        pytest.skip("Node is not available for executable C3 module tests")
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
    this.open = false;
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() {
    return this._text + this.children.map((child) => child.textContent || "").join("");
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this._text = ""; this.children = [...children]; }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  removeAttribute(name) { this.attributes.delete(name); }
  hasAttribute(name) { return this.attributes.has(name); }
  addEventListener(name, listener) { this.listeners.set(name, listener); }
  contains(node) {
    return this === node || this.children.some((child) => child.contains && child.contains(node));
  }
  focus() { document.activeElement = this; }
}

globalThis.Node = FakeNode;
globalThis.HTMLElement = FakeNode;
globalThis.document = {
  activeElement: null,
  createElement: (tagName) => new FakeNode(tagName),
  createTextNode: (value) => {
    const node = new FakeNode("#text");
    node.textContent = value;
    return node;
  },
  createDocumentFragment: () => new FakeNode(),
};
Object.defineProperty(globalThis, "navigator", {
  value: { clipboard: { writeText: async () => {} } },
  configurable: true,
});

const root = process.argv[2];
const load = async (name) => import(pathToFileURL(`${root}\\${name}`));
const scan = await load("scan.js");
const state = await load("state.js");

class FakeScheduler {
  constructor() { this.next = 1; this.timers = new Map(); this.delays = []; }
  setTimeout(fn, delay) {
    const id = this.next++;
    this.delays.push(delay);
    this.timers.set(id, fn);
    return id;
  }
  clearTimeout(id) { this.timers.delete(id); }
  fireNext() {
    const item = this.timers.entries().next().value;
    if (!item) throw new Error("No timer available");
    const [id, fn] = item;
    this.timers.delete(id);
    fn();
  }
}

const id = (digit) => `${digit.repeat(8)}-${digit.repeat(4)}-4${digit.repeat(3)}-8${digit.repeat(3)}-${digit.repeat(12)}`;
const runId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const targetId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const lineageId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const region = () => new FakeNode("section");
const nodes = (rootNode, predicate, found = []) => {
  if (predicate(rootNode)) found.push(rootNode);
  for (const child of rootNode.children) nodes(child, predicate, found);
  return found;
};
const byClass = (rootNode, className) => nodes(
  rootNode,
  (node) => String(node.className).split(" ").includes(className),
);
const expectText = (node, value) => {
  if (!node.textContent.includes(value)) throw new Error(`Missing text: ${value}`);
};
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

const summary = (projectId, overrides = {}) => ({
  run_id: runId,
  target_id: targetId,
  project_id: projectId,
  lineage_id: lineageId,
  submission_sequence_number: 7,
  predecessor_run_id: null,
  product_status: "COMPLETED",
  created_at: "2026-09-25T10:00:00Z",
  published_at: "2026-09-25T10:02:00Z",
  finalized_at: "2026-09-25T10:03:00Z",
  indexed: true,
  lifecycle_evaluated: true,
  finding_count: 9,
  priority_counts: { CRITICAL: 1, HIGH: 2, MEDIUM: 3, UNRANKED: 3 },
  category_counts: {},
  coverage_complete: false,
  coverage_counts: {},
  gap_count: 2,
  ...overrides,
});
const stageRoster = (overrides = {}) => ({
  run_id: runId,
  product_status: "COMPLETED",
  published_at: "2026-09-25T10:02:00Z",
  finalized_at: "2026-09-25T10:03:00Z",
  stages: [
    { authority: "semgrep-ce", capability: "python_sast", progress_state: "COMPLETE", coverage_states: ["COMPLETE_WITH_FINDINGS"], reason_code: null },
    { authority: "gitleaks", capability: "secret_detection", progress_state: "COMPLETE", coverage_states: ["COMPLETE"], reason_code: null },
    { authority: "syft", capability: "package_inventory", progress_state: "COMPLETE", coverage_states: ["COMPLETE_WITH_SUPPRESSIONS"], reason_code: null },
    { authority: "osv.dev", capability: "dependency_advisory_matching", progress_state: "NOT_APPLICABLE", coverage_states: ["NOT_APPLICABLE"], reason_code: "NO_EXACT_PINS" },
    { authority: "checkov", capability: "configuration_security", progress_state: "FAILED", coverage_states: ["FAILED", "PARTIAL"], reason_code: "<script>alert(1)</script>" + "X".repeat(300) },
  ],
  ...overrides,
});
const render = (target, projectId, services, scheduler = new FakeScheduler()) => {
  state.beginRoute({ name: "scan", runId });
  let breadcrumbs = [];
  const controller = scan.renderScanPage({
    region: target,
    route: { name: "scan", runId },
    services,
    scheduler,
    setBreadcrumb: (items) => { breadcrumbs = items; },
  });
  return { controller, scheduler, breadcrumbs: () => breadcrumbs };
};

// Completed: authoritative metrics, five semantic rows, exact details, and no polling.
let target = region();
let projectId = id("1");
let projectCalls = 0;
let result = render(target, projectId, {
  getScanSummary: async () => summary(projectId),
  getScanStages: async () => stageRoster(),
  getProject: async () => { projectCalls += 1; return { project_id: projectId, name: "Payments API" }; },
});
await result.controller.settled;
for (const value of (
  ["Security scan", "Payments API", "Completed", "Analysis completed", "Findings9", "CoverageIncomplete", "Gaps2", "Critical1", "High2", "Sequence 7", "SAST", "Secrets", "Package inventory", "Dependency vulnerabilities", "Configuration security", "Not applicable", "Failed", "Partial"]
)) expectText(target, value);
if (byClass(target, "stage-row").length !== 5) throw new Error("Stage roster is not five rows");
if (result.scheduler.timers.size !== 0) throw new Error("Terminal scan polled");
if (projectCalls !== 1) throw new Error("Project lookup was not bounded");
expectText({ textContent: result.breadcrumbs().map((item) => item.label).join("/") }, "Projects/Payments API/Security scan");
const hostileReason = byClass(target, "stage-reason")
  .map((node) => node.textContent)
  .find((value) => value.includes("<script>"));
if (!hostileReason.includes("<script>alert(1)</script>") || hostileReason.length > 180) {
  throw new Error("Hostile reason was not inert and bounded");
}

// Running: prepublication zero remains Pending, all state allowlists render, and polling is bounded.
target = region();
projectId = id("2");
const allStates = ["PENDING", "WAITING", "RUNNING", "COMPLETE", "PARTIAL", "FAILED", "CANCELLED", "NOT_APPLICABLE"];
const allCoverage = [null, [], ["COMPLETE"], ["COMPLETE_WITH_FINDINGS"], ["PARTIAL"], ["FAILED"], ["NOT_APPLICABLE"], ["UNKNOWN_COVERAGE"]];
let summaryCalls = 0;
let stageCalls = 0;
let summaryMode = "running";
let stageMode = "normal";
let pendingSummary = null;
let pendingStages = null;
let lastSummarySignal = null;
let lastStageSignal = null;
const services = {
  getScanSummary: async (_run, { signal }) => {
    summaryCalls += 1;
    lastSummarySignal = signal;
    if (summaryMode === "deferred") return pendingSummary.promise;
    if (summaryMode === "failed") throw new Error("backend detail must not leak");
    if (summaryMode === "completed") return summary(projectId);
    return summary(projectId, {
      product_status: "RUNNING", published_at: null, finalized_at: null,
      indexed: false, finding_count: 0, priority_counts: {},
      coverage_complete: null, gap_count: null,
    });
  },
  getScanStages: async (_run, { signal }) => {
    stageCalls += 1;
    lastStageSignal = signal;
    if (stageMode === "deferred") return pendingStages.promise;
    if (stageMode === "failed") throw new Error("stage secret");
    return stageRoster({
      product_status: "RUNNING", published_at: null, finalized_at: null,
      stages: allStates.map((progress_state, index) => ({
        authority: index === 7 ? "unknown-authority" : "semgrep-ce",
        capability: index === 7 ? "unknown-capability" : "python_sast",
        progress_state,
        coverage_states: allCoverage[index],
        reason_code: null,
      })),
    });
  },
  getProject: async () => { projectCalls += 1; throw new Error("project backend detail"); },
};
result = render(target, projectId, services);
await result.controller.settled;
expectText(target, "Running");
expectText(target, "FindingsPending");
expectText(target, "CoveragePending");
expectText(target, "GapsPending");
expectText(target, "Project unavailable");
for (const value of ["Pending", "Waiting", "Running", "Complete", "Partial", "Failed", "Cancelled", "Not applicable", "Not reported", "Complete with findings", "Unknown state", "Unknown analysis", "Unknown authority"]) expectText(target, value);
if (result.scheduler.timers.size !== 1 || result.scheduler.delays[0] !== 5000) throw new Error("Polling interval changed");

// One refresh promise prevents overlap; focus and open details survive contained updates; terminal stops.
pendingSummary = deferred();
pendingStages = deferred();
summaryMode = "deferred";
stageMode = "deferred";
const refreshButton = byClass(target, "scan-refresh")[0];
const details = byClass(target, "scan-technical-details")[0];
refreshButton.focus();
details.open = true;
const firstRefresh = result.controller.refresh();
const secondRefresh = result.controller.refresh();
if (firstRefresh !== secondRefresh || summaryCalls !== 2 || stageCalls !== 2) {
  throw new Error("Refresh requests overlapped");
}
pendingSummary.resolve(summary(projectId));
pendingStages.resolve(stageRoster());
await firstRefresh;
if (document.activeElement !== refreshButton || !details.open) throw new Error("Polling disturbed focus or details");
if (result.scheduler.timers.size !== 0) throw new Error("Terminal transition did not stop polling");
expectText(target, "Scan updates stopped");

// A transient refresh failure preserves prior data and emits only restrained safe copy.
summaryMode = "failed";
stageMode = "failed";
await result.controller.refresh();
expectText(target, "Analysis completed");
expectText(target, "Scan update delayed");
if (target.textContent.includes("backend detail") || target.textContent.includes("stage secret")) {
  throw new Error("Raw error leaked");
}

// Secondary stage failure is local and project failure does not destroy summary.
target = region();
projectId = id("3");
result = render(target, projectId, {
  getScanSummary: async () => summary(projectId),
  getScanStages: async () => { throw new Error("raw stage error"); },
  getProject: async () => { throw new Error("raw project error"); },
});
await result.controller.settled;
expectText(target, "Analysis completed");
expectText(target, "Project unavailable");
expectText(target, "Analysis unavailable");
if (target.textContent.includes("raw stage") || target.textContent.includes("raw project")) throw new Error("Secondary raw error leaked");

// Whole-route summary errors preserve exact safe classes for 404 and 503-like failure.
for (const [status, expected] of [[404, "Scan not found"], [503, "Scan data unavailable"]]) {
  target = region();
  projectId = status === 404 ? id("4") : id("5");
  result = render(target, projectId, {
    getScanSummary: async () => { const error = new Error("secret body"); error.status = status; throw error; },
    getScanStages: async () => stageRoster(),
    getProject: async () => { throw new Error(); },
  });
  await result.controller.settled;
  expectText(target, expected);
  if (target.textContent.includes("secret body")) throw new Error("Summary raw error leaked");
}

// Invalid fulfilled payload is also a safe whole-route failure.
target = region();
projectId = id("6");
result = render(target, projectId, {
  getScanSummary: async () => null,
  getScanStages: async () => stageRoster(),
  getProject: async () => ({ project_id: projectId, name: "Should not render" }),
});
await result.controller.settled;
expectText(target, "INVALID_RESPONSE");

// Hostile navigation aborts an active poll; its late payload cannot mutate the old route.
target = region();
projectId = id("7");
summaryMode = "running";
stageMode = "normal";
result = render(target, projectId, services);
await result.controller.settled;
pendingSummary = deferred();
pendingStages = deferred();
summaryMode = "deferred";
stageMode = "deferred";
result.scheduler.fireNext();
if (summaryCalls < 4 || stageCalls < 4) throw new Error("Poll did not start");
state.beginRoute({ name: "project", projectId });
if (!lastSummarySignal.aborted || !lastStageSignal.aborted || result.scheduler.timers.size !== 0) {
  throw new Error("Navigation did not cancel active scan work");
}
pendingSummary.resolve(summary(projectId, { product_status: "COMPLETED" }));
pendingStages.resolve(stageRoster());
await tick();
await tick();
if (target.textContent.includes("Analysis completed")) throw new Error("Late scan response mutated route");
'''
    harness_path = tmp_path / "c3-runtime.mjs"
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
        timeout=30,
    )
    assert result.returncode == 0, result.stderr

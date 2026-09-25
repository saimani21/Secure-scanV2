from __future__ import annotations

import base64
import json
import re
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
_HOSTILE_VALUES = (
    "<script>alert(1)</script>",
    '\"><img src=x onerror=alert(1)>',
    "Project ${HOME}",
    "../../etc/passwd",
    "A" * 501,
    "safe\u202Efdp.exe",
)


def _node() -> Path | None:
    windows_node = Path("/mnt/c/Program Files/nodejs/node.exe")
    if windows_node.is_file():
        return windows_node
    return None


def test_overview_uses_authoritative_totals_and_independent_resource_failures() -> None:
    source = _SOURCES["overview.js"]
    assert "page.total" in source
    assert "OVERVIEW_PROJECT_DISPLAY = 5" in source
    assert "OVERVIEW_SCAN_DISPLAY = 6" in source
    assert 'resourceRegion("Recent scans")' in source
    assert 'resourceRegion("Projects")' in source
    assert "projectListError()" in source
    assert "scanListError()" in source
    assert "Promise.allSettled([loadProjects(), loadScans()])" in source
    for unsupported in (
        "finding_count",
        "vulnerability_count",
        "coverage score",
        "risk score",
        "running scan count",
    ):
        assert unsupported not in source.lower()


def test_projects_page_covers_populated_empty_pagination_and_safe_errors() -> None:
    source = _SOURCES["projects.js"]
    assert "projectTable(page.items)" in source
    assert "noProjectsState()" in source
    assert "paginationControls(" in source
    assert "page.offset - page.limit" in source
    assert "page.offset + page.limit" in source
    assert "Project data unavailable" in source
    assert "PROJECT_QUERY_UNAVAILABLE" in source
    assert 'href: `/projects/${project.project_id}`' in source
    assert "isCanonicalUuid(project.project_id)" in source
    assert "boundedDisplayText(project && project.name, 160)" in source


def test_project_detail_keeps_header_and_history_resources_independent() -> None:
    source = _SOURCES["project.js"]
    assert "services.getProject(projectId" in source
    assert "services.getProjectScans(projectId" in source
    assert "Promise.allSettled([loadProject(), loadHistory(0" in source
    assert "page.items.length" in source
    assert "maximum: 1" in source
    assert "No scans yet" in source
    assert "Scan history unavailable" in source
    assert "Project not found" in source
    assert "PROJECT_NOT_FOUND" in source
    assert "Sequence ${scan.submission_sequence_number}" in source
    assert "Scan #" not in source
    assert "repository path" not in source.lower()
    assert "repository url" not in source.lower()


def test_trusted_host_command_is_exact_uuid_only_plain_text() -> None:
    source = _SOURCES["project.js"]
    command_body = source[
        source.index("export function trustedHostScanCommand") : source.index(
            "function commandDrawer"
        )
    ]
    assert "securescan scan /path/to/repository" in command_body
    assert "--project-id ${projectId}" in command_body
    assert "isCanonicalUuid(projectId)" in command_body
    assert "project.name" not in command_body
    assert "showModal()" in source
    assert "dialog.close()" in source
    assert "previousFocus.focus()" in source
    assert "copyButton(command" in source
    assert 'createElement("code", { textContent: command })' in source


def test_global_scans_enrichment_is_bounded_cached_and_failure_tolerant() -> None:
    source = _SOURCES["scans.js"]
    assert "MAX_PROJECT_LOOKUP_PAGES = 4" in source
    assert "PROJECT_LOOKUP_PAGE_LIMIT = 50" in source
    assert "projectNameCache = new Map()" in source
    assert "pagesUsed < MAX_PROJECT_LOOKUP_PAGES" in source
    assert "Project unavailable" in source
    assert "break;" in source
    assert "getProjectScans" not in source
    for forbidden in ("getScan(", "/findings", "/dependencies", "/coverage", "/gaps", "/report"):
        assert forbidden not in source


def test_scan_status_mapping_is_exhaustive_and_never_claims_security() -> None:
    source = _SOURCES["format.js"]
    for exact_status in (
        "QUEUED",
        "RUNNING",
        "PUBLISHED_PENDING_FINALIZATION",
        "BLOCKED_BY_PREDECESSOR",
        "COMPLETED",
        "CANCELLED",
        "FAILED",
    ):
        assert exact_status in source
    for unsupported in ("Healthy", "Risky", "Secure", "Unsafe", "Clean"):
        assert unsupported not in source
    assert 'label: "Unknown status"' in source


def test_tables_use_semantics_native_links_and_responsive_stacked_rows() -> None:
    combined = "\n".join(
        _SOURCES[name] for name in ("projects.js", "project.js", "scans.js")
    )
    assert 'createElement("table"' in combined
    assert 'createElement("caption"' in combined
    assert 'attributes: { scope: "col" }' in combined
    assert 'createElement("a"' in combined
    assert 'href: `/scans/${scan.run_id}`' in combined
    assert 'attributes: { "data-label": "Project" }' in combined
    assert "@media (max-width: 767px)" in _STYLES
    assert "content: attr(data-label)" in _STYLES
    assert "grid-template-columns: minmax(88px" in _STYLES
    assert "@media (min-width: 768px) and (max-width: 1099px)" in _STYLES


def test_local_loading_pagination_and_route_request_guards_remain_explicit() -> None:
    combined = "\n".join(
        _SOURCES[name]
        for name in ("overview.js", "projects.js", "project.js", "scans.js")
    )
    assert combined.count("beginRequest()") >= 6
    assert combined.count("request.isCurrent()") >= 9
    assert combined.count('setAttribute("aria-busy", "true")') >= 4
    assert "loadGeneration" in combined
    assert "historyGeneration" in combined
    assert "paginationLabel(page)" in combined


def test_hostile_values_flow_through_text_content_and_are_length_bounded() -> None:
    all_javascript = "\n".join(_SOURCES.values())
    for sink in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert sink not in all_javascript
    assert "textContent" in _SOURCES["components.js"]
    assert "boundedDisplayText" in _SOURCES["projects.js"]
    assert "boundedDisplayText" in _SOURCES["scans.js"]

    node = _node()
    if node is None:
        pytest.skip("Node is not available for presentation-helper execution")
    encoded_module = base64.b64encode(_SOURCES["format.js"].encode()).decode()
    module_url = f"data:text/javascript;base64,{encoded_module}"
    script = f"""
      const format = await import({json.dumps(module_url)});
      const values = {json.dumps(_HOSTILE_VALUES)};
      for (const value of values) {{
        const rendered = format.boundedDisplayText(value, 160);
        if (typeof rendered !== "string" || rendered.length > 160) process.exit(1);
      }}
      if (format.productStatus("<script>").label !== "Unknown status") process.exit(2);
      const pageLabel = format.paginationLabel({{total: 117, limit: 50, offset: 50}});
      if (pageLabel !== "Showing 51–100 of 117") process.exit(3);
    """
    result = subprocess.run(
        [str(node), "--input-type=module", "--eval", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_c2_api_paths_are_exact_get_only_and_page_bounded() -> None:
    source = _SOURCES["api.js"]
    for path in (
        "/v1/projects?",
        "/v1/projects/${segment}",
        "/v1/projects/${segment}/scans?",
        "/v1/scans?",
    ):
        assert path in source
    assert "limit > 200" in source
    assert "offset < 0" in source
    assert "isCanonicalUuid(value)" in source
    assert 'method: "GET"' in source
    assert re.search(r'method:\s*"(?:POST|PUT|PATCH|DELETE)"', source) is None


def test_c2_page_modules_execute_real_populated_empty_and_failure_states(
    tmp_path: Path,
) -> None:
    node = _node()
    if node is None:
        pytest.skip("Node is not available for executable C2 module tests")
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
  querySelector(selector) {
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
  createTextNode: (value) => {
    const node = new FakeNode("#text");
    node.textContent = value;
    return node;
  },
  createDocumentFragment: () => new FakeNode(),
};
const root = process.argv[2];
const load = async (name) => import(pathToFileURL(`${root}\\${name}`));
const projects = await load("projects.js");
const overview = await load("overview.js");
const project = await load("project.js");
const scans = await load("scans.js");
const id1 = "11111111-1111-4111-8111-111111111111";
const id2 = "22222222-2222-4222-8222-222222222222";
const run1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const expectedCommand = `securescan scan /path/to/repository \\
  --project-id ${id1}`;
if (project.trustedHostScanCommand(id1) !== expectedCommand) {
  throw new Error("Trusted-host command changed");
}
const projectRow = { project_id: id1, name: "Payments API", created_at: "2026-09-14T11:00:00Z" };
const hostileRow = {
  project_id: id2,
  name: "<script>alert(1)</script>" + "A".repeat(501),
  created_at: "2026-09-10T11:00:00Z",
};
const scanRow = {
  run_id: run1,
  project_id: id1,
  product_status: "COMPLETED",
  created_at: "2026-09-25T14:40:00Z",
  published_at: "2026-09-25T14:42:00Z",
  finalized_at: "2026-09-25T14:43:00Z",
  submission_sequence_number: 3,
};
const page = (items, total = items.length) => ({ items, total, limit: 50, offset: 0 });
const region = () => new FakeNode("section");
const expectText = (node, value) => {
  if (!node.textContent.includes(value)) throw new Error(`Missing text: ${value}`);
};
const findNode = (node, predicate) => {
  if (predicate(node)) return node;
  for (const child of node.children) {
    const match = findNode(child, predicate);
    if (match) return match;
  }
  return null;
};

let target = region();
await projects.renderProjectsPage({
  region: target,
  services: { getProjects: async () => page([projectRow, hostileRow]) },
}).settled;
expectText(target, "Payments API");
expectText(target, "<script>alert(1)</script>");
if (target.textContent.includes("No projects yet")) throw new Error("False project empty state");

const projectOffsets = [];
target = region();
await projects.renderProjectsPage({
  region: target,
  services: {
    getProjects: async ({ offset }) => {
      projectOffsets.push(offset);
      return { ...page([projectRow], 117), offset };
    },
  },
}).settled;
const projectNext = findNode(
  target,
  (node) => node.tagName === "BUTTON" && node.textContent === "Next",
);
await projectNext.listeners.get("click")();
if (projectOffsets.join(",") !== "0,50") throw new Error("Project pagination changed");
expectText(target, "Showing 51–100 of 117");

target = region();
await projects.renderProjectsPage({
  region: target,
  services: { getProjects: async () => page([]) },
}).settled;
expectText(target, "No projects yet");

target = region();
await projects.renderProjectsPage({
  region: target,
  services: { getProjects: async () => { throw new Error("database secret"); } },
}).settled;
expectText(target, "Project data unavailable");
if (target.textContent.includes("database secret")) throw new Error("Raw API error leaked");

target = region();
await overview.renderOverviewPage({
  region: target,
  services: {
    getProjects: async () => page([projectRow]),
    getScans: async () => { throw new Error("scan backend detail"); },
  },
}).settled;
expectText(target, "Payments API");
expectText(target, "Scan data unavailable");

target = region();
await overview.renderOverviewPage({
  region: target,
  services: {
    getProjects: async () => page([]),
    getScans: async () => page([]),
  },
}).settled;
expectText(target, "No projects yet");
expectText(target, "No scans yet");

target = region();
await overview.renderOverviewPage({
  region: target,
  services: {
    getProjects: async () => { throw new Error("project backend detail"); },
    getScans: async () => page([]),
  },
}).settled;
expectText(target, "Project data unavailable");
expectText(target, "No scans yet");

target = region();
await project.renderProjectPage({
  region: target,
  route: { projectId: id1 },
  services: {
    getProject: async () => projectRow,
    getProjectScans: async () => page([scanRow]),
  },
}).settled;
expectText(target, "Payments API");
expectText(target, "Latest scan");
expectText(target, "Sequence 3");
expectText(target, `--project-id ${id1}`);

target = region();
await project.renderProjectPage({
  region: target,
  route: { projectId: id1 },
  services: {
    getProject: async () => projectRow,
    getProjectScans: async () => page([]),
  },
}).settled;
expectText(target, "No scans yet");

target = region();
await project.renderProjectPage({
  region: target,
  route: { projectId: id1 },
  services: {
    getProject: async () => { const error = new Error(); error.status = 404; throw error; },
    getProjectScans: async () => { throw new Error(); },
  },
}).settled;
expectText(target, "Project not found");

target = region();
await project.renderProjectPage({
  region: target,
  route: { projectId: id1 },
  services: {
    getProject: async () => projectRow,
    getProjectScans: async () => { throw new Error("history detail"); },
  },
}).settled;
expectText(target, "Payments API");
expectText(target, "Scan history unavailable");

let projectCalls = 0;
target = region();
await scans.renderScansPage({
  region: target,
  services: {
    getScans: async () => page([scanRow]),
    getProjects: async () => { projectCalls += 1; return page([projectRow]); },
  },
}).settled;
expectText(target, "Payments API");
expectText(target, "Completed");
if (projectCalls > scans.MAX_PROJECT_LOOKUP_PAGES) throw new Error("Unbounded lookup");

const unresolvedId = "33333333-3333-4333-8333-333333333333";
target = region();
await scans.renderScansPage({
  region: target,
  services: {
    getScans: async () => page([{ ...scanRow, project_id: unresolvedId }]),
    getProjects: async () => { throw new Error("unavailable"); },
  },
}).settled;
expectText(target, "Project unavailable");

target = region();
await scans.renderScansPage({
  region: target,
  services: {
    getScans: async () => page([]),
    getProjects: async () => page([]),
  },
}).settled;
expectText(target, "No scans yet");
'''
    harness_path = tmp_path / "c2-runtime.mjs"
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

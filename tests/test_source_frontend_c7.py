# ruff: noqa: E501 -- executable JavaScript navigation fixture stays readable as source.

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_WEB = _ROOT / "src" / "securescan" / "web"
_JAVASCRIPT = {
    path.name: path.read_text(encoding="utf-8")
    for path in sorted(_WEB.glob("*.js"))
}
_STYLES = {
    path.name: path.read_text(encoding="utf-8")
    for path in sorted(_WEB.glob("*.css"))
}
_ALL_JAVASCRIPT = "\n".join(_JAVASCRIPT.values())
_ALL_STYLES = "\n".join(_STYLES.values())


def _luminance(value: str) -> float:
    channels = [int(value[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        channel / 12.92
        if channel <= 0.04045
        else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(first: str, second: str) -> float:
    high, low = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def test_c7_every_approved_route_has_real_navigation_and_a_renderer() -> None:
    application = _JAVASCRIPT["app.js"]
    router = _JAVASCRIPT["router.js"]
    for route, renderer in (
        ("overview", "renderOverviewPage"),
        ("projects", "renderProjectsPage"),
        ("project", "renderProjectPage"),
        ("scans", "renderScansPage"),
        ("scan", "renderScanPage"),
        ("findings", "renderFindingsPage"),
        ("assurance", "renderAssurancePage"),
        ("dependencies", "renderDependenciesPage"),
        ("coverage", "renderCoveragePage"),
        ("gaps", "renderGapsPage"),
        ("report", "renderReportPage"),
    ):
        assert f"{route}: {renderer}" in application
    for suffix in ("findings", "assurance", "dependencies", "coverage", "gaps", "report"):
        assert suffix in router
        assert f'routeName: "{suffix}"' in application
    for phrase in (
        "will be implemented",
        "coming soon",
        "checkpoint shell",
        "sample finding",
        "sample package",
    ):
        assert phrase not in _ALL_JAVASCRIPT.lower()


def test_c7_hostile_text_and_browser_security_invariants_are_global() -> None:
    for sink in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert sink not in _ALL_JAVASCRIPT
    assert 'name.toLowerCase().startsWith("on")' in _JAVASCRIPT["components.js"]
    assert 'method: "GET"' in _JAVASCRIPT["api.js"]
    read_only_modules = "\n".join(
        source for name, source in _JAVASCRIPT.items() if name != "project_mutations.js"
    )
    assert not re.search(r'method:\s*"(?:POST|PUT|PATCH|DELETE)"', read_only_modules)
    assert _JAVASCRIPT["project_mutations.js"].count('method: "POST"') == 1
    assert "unicode-bidi: isolate" in _ALL_STYLES
    assert "overflow-wrap: anywhere" in _ALL_STYLES
    assert "api.osv.dev" not in _ALL_JAVASCRIPT
    assert not re.search(r'from\s+["\'](?:https?:)?//', _ALL_JAVASCRIPT)


def test_c7_empty_error_and_unknown_states_stay_distinct() -> None:
    expected = {
        "projects.js": ("No projects", "Project data unavailable"),
        "scans.js": ("No scans", "Scan data unavailable"),
        "findings.js": ("No findings", "No matching findings", "Findings not ready"),
        "dependencies.js": ("No packages", "Dependencies not ready", "Dependency data unavailable"),
        "coverage.js": ("Coverage is pending publication", "Coverage detail unavailable"),
        "gaps.js": ("No published gaps", "Gaps not ready", "Gap data unavailable"),
        "report.js": ("Report not ready", "Verified report unavailable"),
    }
    for module, markers in expected.items():
        for marker in markers:
            assert marker in _JAVASCRIPT[module] or marker in _ALL_JAVASCRIPT
    for casual in ("Oops", "Uh oh", "Something weird happened"):
        assert casual not in _ALL_JAVASCRIPT


def test_c7_accessibility_and_responsive_contract_remain_explicit() -> None:
    application = _JAVASCRIPT["app.js"]
    assert 'class="skip-link"' in (_WEB / "index.html").read_text(encoding="utf-8")
    for marker in (
        'aria-current", "page"',
        'event.key === "Escape"',
        'event.key !== "Tab"',
        "previousFocus.focus()",
        'main.inert = true',
        'sidebar.setAttribute("aria-modal", "true")',
    ):
        assert marker in application
    assert "min-height: 40px" in _ALL_STYLES
    assert "prefers-reduced-motion: reduce" in _ALL_STYLES
    assert "@media (max-width: 767px)" in _ALL_STYLES
    assert "min-width: 768px" in _ALL_STYLES
    for module in ("projects.js", "project.js", "scans.js"):
        assert 'createElement("caption"' in _JAVASCRIPT[module]
    for module in ("findings.js", "dependencies.js"):
        assert 'createElement("dialog"' in _JAVASCRIPT[module]
        assert "showModal()" in _JAVASCRIPT[module]
        assert ".focus()" in _JAVASCRIPT[module]


def test_c7_normal_text_tokens_meet_wcag_aa_on_active_surfaces() -> None:
    tokens = dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-f]{6});", _STYLES["tokens.css"]))
    foregrounds = (
        "color-text",
        "color-text-secondary",
        "color-text-muted",
        "color-accent",
        "color-accent-dim",
        "color-critical",
        "color-high",
        "color-medium",
        "color-low",
        "color-success",
        "color-warning",
        "color-neutral",
    )
    backgrounds = ("color-bg", "color-surface", "color-surface-raised", "color-surface-hover")
    for foreground in foregrounds:
        for background in backgrounds:
            assert _contrast(tokens[foreground], tokens[background]) >= 4.5, (
                foreground,
                background,
            )


def test_c7_performance_and_maintainability_remain_bounded() -> None:
    assert "setInterval(" not in _ALL_JAVASCRIPT
    assert _JAVASCRIPT["report.js"].count("JSON.stringify") == 1
    assert "Promise.allSettled" in _JAVASCRIPT["report.js"]
    assert "limit: 6" in _JAVASCRIPT["report.js"]
    assert "limit: 1" in _JAVASCRIPT["report.js"]
    assert "listRequest.cancel()" in _JAVASCRIPT["findings.js"]
    assert "listRequest.cancel()" in _JAVASCRIPT["dependencies.js"]
    for name, source in _JAVASCRIPT.items():
        assert len(source.splitlines()) < 1100, name


def test_c7_navigation_deep_links_history_and_new_tabs_execute(tmp_path: Path) -> None:
    node = Path("/mnt/c/Program Files/nodejs/node.exe")
    if not node.is_file():
        pytest.skip("Node is not available for executable C7 navigation tests")
    router = tmp_path / "router.mjs"
    router.write_text(_JAVASCRIPT["router.js"], encoding="utf-8")
    harness = tmp_path / "navigation.mjs"
    harness.write_text(
        r'''
import { pathToFileURL } from "node:url";
class FakeElement {
  constructor(href, { target = "", download = false } = {}) { this.href = href; this.target = target; this.download = download; }
  closest(selector) { return selector === "a[href]" ? this : null; }
  hasAttribute(name) { return name === "download" && this.download; }
}
globalThis.Element = FakeElement;
const listeners = new Map();
globalThis.document = { addEventListener(name, callback) { listeners.set(name, callback); } };
const location = { origin: "http://securescan.local", href: "http://securescan.local/", pathname: "/", search: "", hash: "" };
const pushes = [];
globalThis.window = {
  location,
  history: { pushState(state, _unused, path) { pushes.push({ state, path }); location.pathname = path; location.href = `${location.origin}${path}`; } },
  addEventListener(name, callback) { listeners.set(name, callback); },
};
const router = await import(pathToFileURL(process.argv[2]));
const navigated = [];
router.installNavigation((route) => navigated.push(route));
const click = (anchor, overrides = {}) => {
  let prevented = false;
  listeners.get("click")({ defaultPrevented: false, button: 0, metaKey: false, ctrlKey: false, shiftKey: false, altKey: false, target: anchor, preventDefault() { prevented = true; }, ...overrides });
  return prevented;
};
const project = "11111111-1111-4111-8111-111111111111";
const run = "22222222-2222-4222-8222-222222222222";
for (const [path, name] of [["/", "overview"], ["/projects", "projects"], [`/projects/${project}`, "project"], ["/scans", "scans"], [`/scans/${run}`, "scan"], [`/scans/${run}/findings`, "findings"], [`/scans/${run}/dependencies`, "dependencies"], [`/scans/${run}/coverage`, "coverage"], [`/scans/${run}/gaps`, "gaps"], [`/scans/${run}/report`, "report"]]) {
  const parsed = router.parseRoute(path);
  if (!parsed || parsed.name !== name) throw new Error(`Deep link failed: ${path}`);
}
if (!click(new FakeElement(`${location.origin}/projects`))) throw new Error("Same-origin route was not intercepted");
if (pushes.length !== 1 || navigated.at(-1).name !== "projects") throw new Error("History push changed");
if (click(new FakeElement(`${location.origin}/scans`, { target: "_blank" }))) throw new Error("New-tab link was intercepted");
if (click(new FakeElement(`${location.origin}/scans`), { ctrlKey: true })) throw new Error("Modified click was intercepted");
if (click(new FakeElement(`${location.origin}/projects?offset=50`))) throw new Error("Query-state link was intercepted");
location.pathname = `/scans/${run}/report`; location.href = `${location.origin}${location.pathname}`;
listeners.get("popstate")();
if (navigated.at(-1).name !== "report") throw new Error("Back/forward route restoration changed");
''',
        encoding="utf-8",
    )
    windows_harness = subprocess.run(
        ["wslpath", "-w", str(harness)], check=True, capture_output=True, text=True
    ).stdout.strip()
    windows_router = subprocess.run(
        ["wslpath", "-w", str(router)], check=True, capture_output=True, text=True
    ).stdout.strip()
    result = subprocess.run(
        [str(node), windows_harness, windows_router],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr

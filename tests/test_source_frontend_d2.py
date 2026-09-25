from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from securescan.api.main import app
from securescan.web.routes import _ASSETS, frontend_asset, frontend_index
from securescan.web.routes import router as frontend_router

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_WEB_ROOT = _REPOSITORY_ROOT / "src" / "securescan" / "web"
_HTML = (_WEB_ROOT / "index.html").read_text(encoding="utf-8")
_JAVASCRIPT = {
    path.name: path.read_text(encoding="utf-8")
    for path in sorted(_WEB_ROOT.glob("*.js"))
}
_STYLESHEETS = {
    path.name: path.read_text(encoding="utf-8")
    for path in sorted(_WEB_ROOT.glob("*.css"))
}
_ALL_JAVASCRIPT = "\n".join(_JAVASCRIPT.values())
_ALL_STYLES = "\n".join(_STYLESHEETS.values())
_PROJECT_ID = "11111111-1111-4111-8111-111111111111"
_RUN_ID = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def client() -> TestClient:
    application = FastAPI()
    application.include_router(frontend_router)
    return TestClient(application)


def test_root_and_every_explicit_deep_link_serve_the_same_no_cache_shell(
    client: TestClient,
) -> None:
    routes = (
        "/",
        "/projects",
        f"/projects/{_PROJECT_ID}",
        "/scans",
        f"/scans/{_RUN_ID}",
        f"/scans/{_RUN_ID}/findings",
        f"/scans/{_RUN_ID}/dependencies",
        f"/scans/{_RUN_ID}/coverage",
        f"/scans/{_RUN_ID}/gaps",
        f"/scans/{_RUN_ID}/report",
    )

    for path in routes:
        response = client.get(path)
        assert response.status_code == 200
        assert response.text == _HTML
        assert response.headers["content-type"].startswith("text/html")
        assert response.headers["cache-control"] == "no-cache"


@pytest.mark.parametrize(
    "path",
    [
        "/projects/not-a-uuid",
        "/projects/ABCDEFAB-CDEF-4ABC-8ABC-ABCDEFABCDEF",
        "/projects/11111111111141118111111111111111",
        "/projects/11111111-1111-0111-8111-111111111111",
        "/projects/11111111-1111-1111-1111-111111111111/extra",
        "/scans/not-a-uuid",
        f"/scans/{_RUN_ID}/unknown",
        f"/scans/{_RUN_ID}/findings/extra",
        "/v1/not-a-frontend-route",
        "/health/not-a-frontend-route",
    ],
)
def test_invalid_or_reserved_paths_never_resolve_as_frontend_shell(
    client: TestClient, path: str
) -> None:
    response = client.get(path)
    assert response.status_code in {404, 422}
    assert response.text != _HTML


def test_frontend_router_contains_no_wildcard_shell_or_asset_route() -> None:
    paths = {route.path for route in frontend_router.routes}
    assert "/{path:path}" not in paths
    assert "/assets/{path:path}" not in paths
    assert paths == {
        "/",
        "/projects",
        "/projects/{project_id}",
        "/scans",
        "/scans/{run_id}",
        "/scans/{run_id}/findings",
        "/scans/{run_id}/dependencies",
        "/scans/{run_id}/coverage",
        "/scans/{run_id}/gaps",
        "/scans/{run_id}/report",
        "/assets/{filename}",
    }


def test_v1_and_health_routes_remain_registered_as_api_operations() -> None:
    document = app.openapi()
    assert "/health" in document["paths"]
    assert "/health/ready" in document["paths"]
    assert "/v1/projects" in document["paths"]
    assert "/v1/scans" in document["paths"]
    assert set(document["paths"]["/v1/scans"]) == {"get", "post"}
    for path in (
        "/",
        "/projects",
        "/scans/{run_id}/findings",
        "/assets/{filename}",
    ):
        assert path not in document["paths"]


def test_static_assets_are_strictly_allowlisted_and_no_cache(client: TestClient) -> None:
    expected = {
        "app.js": "text/javascript",
        "api.js": "text/javascript",
        "components.js": "text/javascript",
        "format.js": "text/javascript",
        "router.js": "text/javascript",
        "state.js": "text/javascript",
        "base.css": "text/css",
        "shell.css": "text/css",
        "tokens.css": "text/css",
        "views.css": "text/css",
    }
    assert set(_ASSETS) == set(expected)
    for filename, content_type in expected.items():
        response = client.get(f"/assets/{filename}")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["cache-control"] == "no-cache"
        assert Path(frontend_asset(filename).path).resolve() == (_WEB_ROOT / filename).resolve()

    assert client.get("/assets/unknown.js").status_code == 404
    assert client.get("/assets/../routes.py").status_code == 404


def test_shell_and_assets_preserve_strict_security_headers(client: TestClient) -> None:
    for path in ("/", "/assets/app.js", "/assets/tokens.css"):
        response = client.get(path)
        csp = response.headers["content-security-policy"]
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "style-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "base-uri 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp
        assert "unsafe-eval" not in csp
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["permissions-policy"] == (
            "camera=(), geolocation=(), microphone=()"
        )


def test_index_is_a_minimal_semantic_module_shell_without_inline_code() -> None:
    assert '<html lang="en">' in _HTML
    assert '<meta name="color-scheme" content="dark">' in _HTML
    assert '<a class="skip-link" href="#main-content">' in _HTML
    assert '<div id="app-root"></div>' in _HTML
    assert "<noscript>" in _HTML
    assert '<script type="module" src="/assets/app.js"></script>' in _HTML
    assert "<style" not in _HTML
    assert not re.search(r"<script(?![^>]+\bsrc=)", _HTML)
    assert not re.search(r"\son[a-z]+\s*=", _HTML, re.IGNORECASE)
    assert not re.search(r"(?:src|href)=[\"'](?:https?:)?//", _HTML, re.IGNORECASE)
    for stylesheet in ("tokens.css", "base.css", "shell.css", "views.css"):
        assert f'href="/assets/{stylesheet}"' in _HTML


def test_javascript_uses_no_html_injection_or_dynamic_execution_sinks() -> None:
    for unsafe in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert unsafe not in _ALL_JAVASCRIPT
    assert "textContent" in _JAVASCRIPT["components.js"]
    assert "document.createElement" in _JAVASCRIPT["components.js"]
    assert 'startsWith("on")' in _JAVASCRIPT["components.js"]


def test_browser_code_remains_get_only_and_requests_only_readiness_in_c1() -> None:
    api = _JAVASCRIPT["api.js"]
    assert 'method: "GET"' in api
    assert "encodeURIComponent(String(value))" in api
    assert 'path.includes("\\\\")' in api
    assert "url.origin !== window.location.origin" in api
    assert 'getJson("/health/ready"' in api
    assert 'acceptedStatuses: [503]' in api
    for forbidden in ('method: "POST"', 'method: "PUT"', 'method: "PATCH"', 'method: "DELETE"'):
        assert forbidden not in _ALL_JAVASCRIPT
    assert "/v1/projects" not in _ALL_JAVASCRIPT
    assert "/v1/scans" not in _ALL_JAVASCRIPT


def test_router_has_exact_history_api_and_uuid_security_contract() -> None:
    router = _JAVASCRIPT["router.js"]
    for marker in (
        "window.history.pushState",
        'window.addEventListener("popstate"',
        "parseRoute",
        "isCanonicalUuid",
        "%2f|%5c",
        '"/assets"',
        '"/health"',
        '"/v1"',
        "event.metaKey",
        "event.ctrlKey",
        "event.shiftKey",
        "event.altKey",
    ):
        assert marker in router
    assert "catch-all" not in router
    assert "path:path" not in router


def test_route_generation_aborts_stale_requests() -> None:
    state = _JAVASCRIPT["state.js"]
    assert "routeGeneration: 0" in state
    assert "abortPendingRequests();" in state
    assert "controller.abort();" in state
    assert "generation === state.routeGeneration" in state
    assert "!controller.signal.aborted" in state


def test_shell_uses_semantic_contextual_anchor_navigation() -> None:
    application = _JAVASCRIPT["app.js"]
    assert 'createElement("aside"' in application
    assert 'createElement("main"' in application
    assert 'createElement("header"' in application
    assert 'createElement("nav"' in application
    assert 'createElement("a"' in application
    assert 'link.setAttribute("aria-current", "page")' in application
    assert "if (route.runId)" in application
    assert 'textContent: "Current scan"' in application
    assert "No product data is loaded by this C1 route." in application
    assert "sample finding" not in application.lower()


def test_accessibility_foundations_cover_mobile_dialog_and_route_states() -> None:
    application = _JAVASCRIPT["app.js"]
    components = _JAVASCRIPT["components.js"]
    for marker in (
        'sidebar.setAttribute("role", "dialog")',
        'sidebar.setAttribute("aria-modal", "true")',
        'main.inert = true',
        'sidebar.inert = true',
        'sidebar.inert = false',
        'sidebar.setAttribute("aria-hidden", "true")',
        'event.key === "Escape"',
        'event.key !== "Tab"',
        "previousFocus.focus()",
        '"aria-expanded": "false"',
        'textContent: "Close"',
        '"aria-busy": "true"',
        'attributes: { role: "alert" }',
        'attributes: { role: "status" }',
    ):
        assert marker in application or marker in components
    assert "prefers-reduced-motion: reduce" in _ALL_STYLES
    assert "min-height: 40px" in _ALL_STYLES


def test_readiness_display_preserves_ready_not_ready_and_unavailable() -> None:
    application = _JAVASCRIPT["app.js"]
    assert 'payload.status === "ready"' in application
    assert '"System ready"' in application
    assert '"System not ready"' in application
    assert '"System unavailable"' in application
    for field in (
        "database_reachable",
        "schema_at_head",
        "reason",
        "checked_at",
    ):
        assert field in application


def test_design_tokens_and_active_css_follow_the_approved_visual_contract() -> None:
    tokens = _STYLESHEETS["tokens.css"].lower()
    for token in (
        "--color-bg: #0a0c0b",
        "--color-surface: #101310",
        "--color-accent: #c8f75a",
        "--color-critical: #ff6262",
        "--sidebar-full: 232px",
        "--sidebar-compact: 72px",
        "--content-max: 1560px",
        "--radius-small: 4px",
        "--radius-normal: 7px",
        "--radius-dialog: 10px",
    ):
        assert token in tokens
    for forbidden in (
        "linear-gradient",
        "radial-gradient",
        "backdrop-filter",
        "glass",
        "neon",
        "border-radius: 999",
    ):
        assert forbidden not in _ALL_STYLES.lower()
    assert _ALL_STYLES.count("box-shadow:") == 1


def test_responsive_contract_uses_full_compact_and_mobile_drawer_breakpoints() -> None:
    shell = _STYLESHEETS["shell.css"]
    assert "@media (min-width: 768px) and (max-width: 1199px)" in shell
    assert "@media (max-width: 767px)" in shell
    assert "grid-template-columns: var(--sidebar-full)" in shell
    assert "grid-template-columns: var(--sidebar-compact)" in shell
    assert "transform: translateX(-101%)" in shell
    assert 'sidebar[data-open="true"]' in shell


def test_all_allowlisted_modules_and_styles_are_packaged() -> None:
    for filename in _ASSETS:
        assert (_WEB_ROOT / filename).is_file()
    pyproject = tomllib.loads((_REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["tool"]["setuptools"]["package-data"]["securescan.web"] == [
        "*.html",
        "*.js",
        "*.css",
    ]
    dockerfile = (_REPOSITORY_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY --chown=securescan:securescan src /app/src" in dockerfile


def test_frontend_assets_do_not_embed_credentials_or_external_dependencies() -> None:
    assets = "\n".join((_HTML, _ALL_JAVASCRIPT, _ALL_STYLES))
    assert "http://" not in assets
    assert "https://" not in assets
    assert "@import" not in _ALL_STYLES
    credential_patterns = (
        r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}",
        r"\bpassword\s*[:=]\s*[\"'][^\"']+[\"']",
    )
    for pattern in credential_patterns:
        assert re.search(pattern, assets, re.IGNORECASE) is None


def test_direct_shell_response_uses_packaged_index_and_no_cache() -> None:
    response = frontend_index()
    assert Path(response.path).resolve() == (_WEB_ROOT / "index.html").resolve()
    assert response.media_type == "text/html; charset=utf-8"
    assert response.headers["cache-control"] == "no-cache"

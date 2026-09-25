from __future__ import annotations

import re
import tomllib
from pathlib import Path

from securescan.api.main import app
from securescan.web.routes import (
    frontend_index,
    frontend_javascript,
    frontend_stylesheet,
)
from securescan.web.routes import (
    router as frontend_router,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_WEB_ROOT = _REPOSITORY_ROOT / "src" / "securescan" / "web"
_HTML = (_WEB_ROOT / "index.html").read_text(encoding="utf-8")
_JAVASCRIPT = (_WEB_ROOT / "app.js").read_text(encoding="utf-8")
_STYLESHEET = (_WEB_ROOT / "styles.css").read_text(encoding="utf-8")


def test_frontend_routes_return_packaged_local_assets() -> None:
    cases = (
        (frontend_index(), "index.html", "text/html; charset=utf-8", "no-store"),
        (
            frontend_javascript(),
            "app.js",
            "text/javascript; charset=utf-8",
            "public, max-age=3600",
        ),
        (
            frontend_stylesheet(),
            "styles.css",
            "text/css; charset=utf-8",
            "public, max-age=3600",
        ),
    )

    for response, filename, media_type, cache_control in cases:
        assert Path(response.path).resolve() == (_WEB_ROOT / filename).resolve()
        assert response.media_type == media_type
        assert response.headers["cache-control"] == cache_control
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "default-src 'self'" in response.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_frontend_page_uses_only_local_script_and_stylesheet_assets() -> None:
    assert '<script src="/assets/app.js" defer></script>' in _HTML
    assert '<link rel="stylesheet" href="/assets/styles.css">' in _HTML
    assert not re.search(r"(?:src|href)=[\"'](?:https?:)?//", _HTML, re.IGNORECASE)
    assert not re.search(r"@import\s+url|url\([\"']?(?:https?:)?//", _STYLESHEET, re.IGNORECASE)
    assert "http://" not in _JAVASCRIPT
    assert "https://" not in _JAVASCRIPT


def test_frontend_does_not_introduce_repository_path_submission() -> None:
    form_fields = set(
        re.findall(r"<(?:input|select)\b[^>]*\bname=[\"']([^\"']+)[\"']", _HTML)
    )
    assert form_fields == {"run_id", "authority", "category", "priority", "lifecycle_state"}
    assert not re.search(r"<input\b[^>]*\btype=[\"']file[\"']", _HTML, re.IGNORECASE)
    assert "method=\"post\"" not in _HTML.lower()
    assert "method: \"POST\"" not in _JAVASCRIPT
    for forbidden_field in ("source_path", "repository_path", "workspace_root"):
        assert forbidden_field not in _HTML
        assert forbidden_field not in _JAVASCRIPT
    assert "Repository scans are submitted from the trusted SecureScan host CLI." in _HTML


def test_frontend_javascript_uses_only_existing_read_apis() -> None:
    assert 'const SCAN_API = "/v1/scans";' in _JAVASCRIPT
    assert _JAVASCRIPT.count('"/v1/') == 1
    for route_suffix in (
        "/findings?",
        "/dependencies?",
        "/coverage",
        "/gaps?",
        "/report",
    ):
        assert route_suffix in _JAVASCRIPT
    assert 'method: "GET"' in _JAVASCRIPT
    assert "fetch(" in _JAVASCRIPT


def test_frontend_constructs_untrusted_content_without_html_injection_apis() -> None:
    assert "textContent" in _JAVASCRIPT
    assert "document.createElement" in _JAVASCRIPT
    for unsafe in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert unsafe not in _JAVASCRIPT


def test_frontend_handles_required_safe_status_and_error_states() -> None:
    for marker in (
        "INVALID_RUN_ID",
        "API_UNAVAILABLE",
        "INVALID_RESPONSE",
        "detail.code",
        "detail.message",
        "FAILED",
        "CANCELLED",
        "still running or awaiting publication",
        "No findings were returned within the completed declared coverage.",
        "This does not prove the repository is secure.",
        "incomplete coverage",
        "No findings match this view.",
    ):
        assert marker in _JAVASCRIPT or marker in _HTML
    assert "raw exception" not in _JAVASCRIPT.lower()


def test_frontend_displays_exact_product_core_and_s4_fields() -> None:
    for field in (
        "run_id",
        "lineage_id",
        "submission_sequence_number",
        "product_status",
        "published_at",
        "finalized_at",
        "finding_count",
        "priority_counts",
        "category_counts",
        "coverage_complete",
        "coverage_counts",
        "gap_count",
        "finding_id",
        "authority",
        "category",
        "severity",
        "priority_band",
        "lifecycle_state",
        "subject",
        "primary_location",
        "advisories",
        "canonical_advisory_id",
        "cve_aliases",
        "ghsa_aliases",
        "fixed_versions",
        "priority_bands",
        "selected_scope",
        "counts_by_state",
        "reason_code",
    ):
        assert field in _JAVASCRIPT
    assert "item.finding_id === finding.finding_id" in _JAVASCRIPT
    assert "Runtime reachability is not claimed." in _HTML


def test_dependency_renderer_preserves_unknown_and_observed_advisory_semantics() -> None:
    renderer = _JAVASCRIPT[
        _JAVASCRIPT.index("function dependencyKnownVulnerabilityLabel") :
        _JAVASCRIPT.index("async function loadCoverage")
    ]
    for required in (
        'dependency.known_vulnerability_count !== null',
        'dependency.vulnerability_evaluation === "NOT_APPLICABLE" ? "N/A" : "Unknown"',
        "Known vulnerabilities:",
        "Evaluation:",
        "Observed advisories:",
        "Advisories: none",
        "advisory.canonical_advisory_id",
        "CVE aliases:",
        "GHSA aliases:",
        "Fixed versions reported by advisory:",
        "No fixed version reported",
        "SecureScan priority:",
    ):
        assert required in renderer
    for misleading in (
        "0 vulnerabilities",
        "Recommended upgrade",
        "Safe version",
        "No fix exists",
        "OSV severity",
        "CVSS score",
        "risk score",
        "exploitability",
    ):
        assert misleading not in renderer


def test_dependency_table_uses_conservative_fixed_version_wording() -> None:
    assert "Fixed versions reported by advisory" in _HTML
    assert "Recommended upgrade" not in _HTML
    assert "Safe version" not in _HTML


def test_incomplete_coverage_takes_precedence_over_zero_findings() -> None:
    open_scan = _JAVASCRIPT[
        _JAVASCRIPT.index("async function openScan") : _JAVASCRIPT.index(
            "function filterParameters"
        )
    ]
    incomplete_branch = open_scan.index("summary.coverage_complete === false")
    zero_findings_branch = open_scan.index(
        "summary.finding_count === 0 && summary.coverage_complete === true"
    )
    assert incomplete_branch < zero_findings_branch

    zero_findings_message = open_scan[
        zero_findings_branch : open_scan.index("} else {", zero_findings_branch)
    ]
    assert '"info"' in zero_findings_message
    assert '"success"' not in zero_findings_message
    assert "This does not prove the repository is secure." in zero_findings_message


def test_async_loaders_are_bound_to_current_run_and_request_generation() -> None:
    assert "requestGeneration: 0" in _JAVASCRIPT
    assert "findingsRequestGeneration: 0" in _JAVASCRIPT
    assert "dependenciesRequestGeneration: 0" in _JAVASCRIPT
    assert "const generation = ++state.requestGeneration;" in _JAVASCRIPT
    assert "function isCurrentRequest(runId, generation)" in _JAVASCRIPT
    assert "generation === state.requestGeneration" in _JAVASCRIPT
    assert "runId === state.runId" in _JAVASCRIPT
    assert "encodeURIComponent(state.runId)" not in _JAVASCRIPT

    open_scan = _JAVASCRIPT[
        _JAVASCRIPT.index("async function openScan") : _JAVASCRIPT.index(
            "function filterParameters"
        )
    ]
    assert open_scan.index("await requestJson") < open_scan.index(
        "generation !== state.requestGeneration"
    ) < open_scan.index("state.runId = summary.run_id")
    assert open_scan.index("await Promise.allSettled") < open_scan.index(
        "!isCurrentRequest(canonicalRunId, generation)"
    ) < open_scan.index("const rejected")

    loaders = (
        ("loadFindings", "subjectLabel", "state.findings = page"),
        ("loadDependencies", "joinValues", "state.dependencies = page"),
        ("loadCoverage", "loadGaps", "state.coverage = coverage"),
        ("loadGaps", "loadReport", "state.gaps = gaps"),
        ("loadReport", "renderCoverage", "state.report = response.report"),
    )
    for function_name, next_function, mutation in loaders:
        body = _JAVASCRIPT[
            _JAVASCRIPT.index(f"async function {function_name}(runId, generation)") :
            _JAVASCRIPT.index(f"function {next_function}")
        ]
        awaited = body.index("await requestJson")
        mutated = body.index(mutation)
        assert awaited < body.rindex("isCurrentRequest(runId, generation)", awaited, mutated)
        assert "encodeURIComponent(runId)" in body

    assert "requestGeneration !== state.findingsRequestGeneration" in _JAVASCRIPT
    assert "requestGeneration !== state.dependenciesRequestGeneration" in _JAVASCRIPT
    assert _JAVASCRIPT.count("const request = activeRequest();") == 5


def test_frontend_and_existing_public_routes_are_registered_without_schema_pollution() -> None:
    frontend_routes = {
        (route.path, method)
        for route in frontend_router.routes
        for method in route.methods
    }
    for route in (
        ("/", "GET"),
        ("/assets/app.js", "GET"),
        ("/assets/styles.css", "GET"),
    ):
        assert route in frontend_routes

    document = app.openapi()
    assert "/" not in document["paths"]
    assert "/assets/app.js" not in document["paths"]
    assert "/health/ready" in document["paths"]
    assert "/v1/scans" in document["paths"]
    assert "/v1/scans/{run_id}" in document["paths"]
    assert "/v1/scans/{run_id}/findings" in document["paths"]
    assert "/v1/scans/{run_id}/components" in document["paths"]
    assert "/v1/scans/{run_id}/dependencies" in document["paths"]
    assert "/v1/scans/{run_id}/coverage" in document["paths"]
    assert "/v1/scans/{run_id}/gaps" in document["paths"]
    assert "/v1/scans/{run_id}/report" in document["paths"]
    assert "/v1/scans/{run_id}/cancel" in document["paths"]


def test_frontend_assets_are_in_wheel_and_existing_container_source_copy() -> None:
    pyproject = tomllib.loads((_REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = pyproject["tool"]["setuptools"]["package-data"]
    assert package_data["securescan.web"] == ["*.html", "*.js", "*.css"]

    dockerfile = (_REPOSITORY_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY --chown=securescan:securescan src /app/src" in dockerfile


def test_frontend_assets_do_not_embed_credentials() -> None:
    assets = "\n".join((_HTML, _JAVASCRIPT, _STYLESHEET))
    credential_patterns = (
        r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}",
        r"\bpassword\s*[:=]\s*[\"'][^\"']+[\"']",
    )
    for pattern in credential_patterns:
        assert re.search(pattern, assets, re.IGNORECASE) is None

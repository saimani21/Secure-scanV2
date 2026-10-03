from __future__ import annotations

from pathlib import Path

_WEB = Path(__file__).resolve().parents[1] / "src" / "securescan" / "web"


def test_v15_ui_uses_same_origin_api_and_safe_dom_rendering() -> None:
    api = (_WEB / "product_release_api.js").read_text(encoding="utf-8")
    view = (_WEB / "product_release.js").read_text(encoding="utf-8")
    assert "/v1/assurance/" in api
    assert "api.openai.com" not in api + view
    assert "innerHTML" not in view
    assert "textContent" in view
    assert "AI-generated explanation" in view
    assert "Scanner finding ≠ manually validated vulnerability" in view


def test_v15_ui_is_integrated_into_assurance_and_finding_surfaces() -> None:
    assurance = (_WEB / "assurance.js").read_text(encoding="utf-8")
    findings = (_WEB / "findings.js").read_text(encoding="utf-8")
    routes = (_WEB / "routes.py").read_text(encoding="utf-8")
    assert "Threat-informed Assurance Dashboard" in assurance
    assert "renderV15Dashboard" in assurance
    assert "renderKnowledgeCard" in findings
    assert "askAssistant" in findings
    assert '"product_release.js"' in routes
    assert '"product_release_api.js"' in routes

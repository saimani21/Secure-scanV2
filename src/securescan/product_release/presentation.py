# ruff: noqa: E501 -- the HTML below is a deterministic, auditable document template.
from __future__ import annotations

import html
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .models import CIResult

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BIDI = re.compile(r"[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_MAX_TEXT = 4096


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def safe_text(value: object, maximum: int = _MAX_TEXT) -> str:
    if value is None:
        return "Unknown"
    text = str(value)
    text = _CONTROL.sub("�", text)
    text = _BIDI.sub(lambda match: f"\\u{ord(match.group()):04x}", text)
    if len(text) > maximum:
        return text[:maximum] + "…"
    return text


def markdown_text(value: object, maximum: int = 512) -> str:
    text = safe_text(value, maximum).replace("\\", "\\\\")
    for character in "`*_{}[]<>()#+-.!|":
        text = text.replace(character, f"\\{character}")
    return " ".join(text.splitlines())


def render_ci_summary(result: CIResult, dashboard: Mapping[str, Any]) -> bytes:
    delta = result.delta_summary
    threat = result.threat_summary
    governance = result.governance_summary
    lines = [
        "# SecureScan Security Gate",
        "",
        f"Decision: **{markdown_text(result.decision, 16)}**",
        "",
        f"Candidate: `{markdown_text(result.candidate_run_id, 80)}`",
        f"Baseline: {markdown_text(result.baseline_revision, 40)}",
        f"Intelligence bundle: `{markdown_text(result.intelligence_bundle_id, 80)}`",
        "",
        "## Security Delta",
        "",
        f"- Introduced: {delta.get('INTRODUCED', 0)}",
        f"- Present: {delta.get('PRESENT', 0)}",
        f"- Removed: {delta.get('REMOVED', 0)}",
        f"- Not comparable: {delta.get('NOT_COMPARABLE', 0)}",
        "",
        "## Threat",
        "",
        f"- Exact CVE relationships: {threat.get('cve_relationships', 0)}",
        f"- KEV listed: {threat.get('kev_listed', 0)}",
        f"- EPSS policy hits: {threat.get('epss_policy_hits', 0)}",
        "",
        "## Governance",
        "",
        f"- False positive: {governance.get('false_positive', 0)}",
        f"- Accepted risk: {governance.get('accepted_risk', 0)}",
        f"- Active suppression: {governance.get('suppressed', 0)}",
        f"- Review required: {governance.get('review_required', 0)}",
        "",
        "## Coverage",
        "",
        f"- Complete: {str(result.coverage_summary.get('complete', False)).lower()}",
        f"- Gaps: {result.coverage_summary.get('gap_count', 0)}",
        f"- Comparison: {markdown_text(result.coverage_summary.get('comparison_status'))}",
        "",
        "## Blocking Findings",
        "",
    ]
    proof = dashboard.get("proof") if isinstance(dashboard, Mapping) else None
    decisions = proof.get("decisions", []) if isinstance(proof, Mapping) else []
    blocking = [
        item
        for item in decisions
        if isinstance(item, Mapping) and item.get("kind") in {"VIOLATION", "ERROR"}
    ]
    if not blocking:
        lines.append("None.")
    for index, item in enumerate(blocking[:200], 1):
        lines.extend(
            [
                f"{index}. `{markdown_text(item.get('finding_id') or 'run-level', 80)}`",
                f"   - Rule: `{markdown_text(item.get('rule_id'), 120)}`",
                f"   - Reason: {markdown_text(item.get('reason_code'), 240)}",
                f"   - CVE: {markdown_text(item.get('cve_id') or 'NOT_APPLICABLE', 80)}",
                f"   - Delta: {markdown_text(item.get('delta_state') or 'UNKNOWN', 80)}",
            ]
        )
    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            *[
                f"- {markdown_text(name, 80)}: `{markdown_text(path, 160)}`"
                for name, path in sorted(result.artifacts.items())
            ],
            "",
            "Unknown is not clean. Policy ERROR is distinct from policy FAIL.",
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _html_value(value: object, maximum: int = _MAX_TEXT) -> str:
    return html.escape(safe_text(value, maximum), quote=True)


def _list(items: Sequence[object]) -> str:
    return "<ul>" + "".join(f"<li>{_html_value(item)}</li>" for item in items) + "</ul>"


def render_assessment_html(dashboard: Mapping[str, Any]) -> bytes:
    decision = dashboard.get("decision", "ERROR")
    scope = dashboard.get("scope", {})
    delta = dashboard.get("delta", {})
    threat = dashboard.get("threat", {})
    governance = dashboard.get("governance", {})
    coverage = dashboard.get("coverage", {})
    intelligence = dashboard.get("intelligence", {})
    toolchain = dashboard.get("toolchain", {})
    proof = dashboard.get("proof", {})
    findings = dashboard.get("findings", [])
    if not isinstance(findings, Sequence) or isinstance(findings, str | bytes):
        findings = []
    rows = []
    for finding in findings[:500]:
        if not isinstance(finding, Mapping):
            continue
        rows.append(
            "<tr>"
            f"<td><code>{_html_value(finding.get('finding_id'), 80)}</code></td>"
            f"<td>{_html_value(finding.get('category'), 80)}</td>"
            f"<td>{_html_value(finding.get('delta_state'), 80)}</td>"
            f"<td>{_html_value(finding.get('cve_state'), 160)}</td>"
            f"<td>{_html_value(finding.get('policy_impact'), 120)}</td>"
            "</tr>"
        )
    proof_reasons = (
        [
            f"{item.get('rule_id')}: {item.get('reason_code')}"
            for item in proof.get("decisions", [])
            if isinstance(item, Mapping)
        ]
        if isinstance(proof, Mapping)
        else []
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureScan Security Assessment</title>
<style>
:root {{ color-scheme: light; font-family: system-ui,sans-serif; }}
body {{ margin: 2rem auto; max-width: 70rem; padding: 0 1rem; color: #17202a; }}
h1,h2 {{ color: #102a43; }} code {{ overflow-wrap:anywhere; }}
table {{ border-collapse:collapse; width:100%; }} th,td {{ border:1px solid #bcccdc; padding:.5rem; text-align:left; }}
.decision {{ font-size:1.4rem; font-weight:700; }} .limitation {{ border-left:.3rem solid #b7791f; padding-left:1rem; }}
@media print {{ body {{ max-width:none; margin:0; }} a {{ color:inherit; text-decoration:none; }} }}
</style></head><body>
<header><p>Deterministic SecureScan product view</p><h1>Security Assessment</h1><p class="decision">Decision: {_html_value(decision, 16)}</p></header>
<section><h2>1. Executive Summary</h2><p>SecureScan evaluated one verified candidate against its explicit baseline, selected intelligence bundle, and trusted policy.</p></section>
<section><h2>2. Scope</h2><dl><dt>Project</dt><dd><code>{_html_value(scope.get("project_id"), 80)}</code></dd><dt>Lineage</dt><dd><code>{_html_value(scope.get("lineage_id"), 80)}</code></dd><dt>Candidate run</dt><dd><code>{_html_value(scope.get("run_id"), 80)}</code></dd></dl></section>
<section><h2>3. Coverage and limitations</h2><p>Complete: {_html_value(coverage.get("complete"))}; gaps: {_html_value(coverage.get("gap_count"))}; comparison: {_html_value(coverage.get("comparison_status"))}.</p></section>
<section><h2>4. Policy Decision</h2><p>{_html_value(decision, 16)}</p>{_list(proof_reasons)}</section>
<section><h2>5. Security Delta</h2><pre>{_html_value(json.dumps(delta, sort_keys=True), 12000)}</pre></section>
<section><h2>6. Authoritative External Intelligence</h2><pre>{_html_value(json.dumps(threat, sort_keys=True), 12000)}</pre><pre>{_html_value(json.dumps(intelligence, sort_keys=True), 12000)}</pre></section>
<section><h2>6A. Toolchain Provenance</h2><pre>{_html_value(json.dumps(toolchain, sort_keys=True), 12000)}</pre></section>
<section><h2>7. Detailed Technical Findings</h2><table><thead><tr><th>Finding</th><th>Category</th><th>Delta</th><th>CVE / threat state</th><th>Policy impact</th></tr></thead><tbody>{"".join(rows)}</tbody></table></section>
<section><h2>8. Governance Decisions</h2><pre>{_html_value(json.dumps(governance, sort_keys=True), 12000)}</pre></section>
<section><h2>9. Policy Decision Proof</h2><p>Proof ID: <code>{_html_value(dashboard.get("proof_id"), 80)}</code></p></section>
<section><h2>10. Explicit Limitations</h2><p class="limitation">A finding is not proof of exploitability. Guidance is not a verified patch. Missing evidence is unknown, not clean. No DAST, reachability, VEX, runtime, OCI, SLSA, or Sigstore claim is made.</p></section>
</body></html>"""
    return document.encode("utf-8")

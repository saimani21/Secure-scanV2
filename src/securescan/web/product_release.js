"use strict";

import { codeValue, createElement, errorState, statusIndicator } from "/assets/components.js";
import { boundedDisplayText } from "/assets/format.js";

function safe(value, maximum = 240) {
  return typeof value === "string" && value ? boundedDisplayText(value, maximum) : "Unknown";
}

function metric(label, value) {
  return createElement("div", { className: "scan-metric" }, [
    createElement("dt", { textContent: label }),
    createElement("dd", { textContent: String(value) }),
  ]);
}

function facts(values) {
  return createElement("dl", { className: "finding-facts" }, values.map(([label, value, code]) =>
    createElement("div", { className: "finding-fact" }, [
      createElement("dt", { textContent: label }),
      createElement("dd", {}, [code ? codeValue(safe(value, 520)) : createElement("span", { textContent: safe(value, 520) })]),
    ])));
}

export function renderV15Dashboard(data) {
  if (!data || !["PASS", "FAIL", "ERROR"].includes(data.decision) ||
      !data.delta || !data.threat || !data.governance || !data.coverage ||
      !data.intelligence || !Array.isArray(data.findings)) {
    return errorState("Threat-informed assurance unavailable", "SecureScan returned an invalid assurance projection.", "ASSURANCE_INVALID");
  }
  const tones = { PASS: "success", FAIL: "failure", ERROR: "error" };
  const kev = data.intelligence.kev || {};
  const epss = data.intelligence.epss || {};
  const toolchain = data.toolchain || {};
  return createElement("div", { className: "v15-dashboard" }, [
    createElement("div", { className: "v15-decision" }, [
      statusIndicator(data.decision, tones[data.decision]),
      createElement("p", { textContent: data.decision === "ERROR"
        ? "SecureScan could not make the required decision safely."
        : data.decision === "FAIL" ? "Authoritative evidence violated trusted policy."
        : "The candidate satisfied the evaluated trusted policy." }),
    ]),
    createElement("h3", { textContent: "Security Delta" }),
    createElement("dl", { className: "scan-metrics" }, [
      metric("Introduced", data.delta.INTRODUCED), metric("Present", data.delta.PRESENT),
      metric("Removed", data.delta.REMOVED), metric("Not comparable", data.delta.NOT_COMPARABLE),
    ]),
    createElement("h3", { textContent: "Threat Context" }),
    createElement("dl", { className: "scan-metrics" }, [
      metric("Exact CVEs", data.threat.exact_cve_count), metric("KEV listed", data.threat.kev_listed),
      metric("EPSS policy hits", data.threat.epss_policy_hits), metric("Relationships", data.threat.cve_relationships),
    ]),
    createElement("h3", { textContent: "Governance" }),
    createElement("dl", { className: "scan-metrics" }, [
      metric("Unreviewed", data.governance.unreviewed), metric("False positive", data.governance.false_positive),
      metric("Accepted risk", data.governance.accepted_risk), metric("Suppressed", data.governance.suppressed),
    ]),
    createElement("h3", { textContent: "Provenance" }),
    facts([
      ["Policy Decision Proof", data.proof_id, true],
      ["Intelligence bundle", data.intelligence.bundle_id, true],
      ["CISA KEV snapshot", kev.snapshot_id || "UNAVAILABLE", true],
      ["KEV source date", kev.source_effective_at || "UNAVAILABLE", false],
      ["FIRST EPSS snapshot", epss.snapshot_id || "UNAVAILABLE", true],
      ["EPSS score date", epss.source_effective_at || "UNAVAILABLE", false],
      ["Coverage", data.coverage.complete ? "COMPLETE" : "PARTIAL", false],
      ["Comparison", data.coverage.comparison_status, false],
      ["Toolchain manifest", toolchain.manifest_sha256 || "UNAVAILABLE", true],
      ["Evidence report", toolchain.report_artifact_sha256 || data.coverage.report_artifact_sha256, true],
    ]),
    createElement("details", { className: "finding-technical-evidence" }, [
      createElement("summary", { textContent: "Why? Deterministic policy proof" }),
      createElement("ol", { className: "assurance-list" }, (data.proof.decisions || []).slice(0, 200).map((item) =>
        createElement("li", { textContent: `${safe(item.kind, 32)} · ${safe(item.rule_id, 120)} · ${safe(item.reason_code, 240)} · ${safe(item.finding_id || "run-level", 80)}` }))),
    ]),
  ]);
}

function renderAssistant(onAsk) {
  const output = createElement("div", {
    className: "ai-assistant-output state-message",
    textContent: "Optional. If the server is not configured, core assurance remains available.",
    attributes: { role: "status", "aria-live": "polite" },
  });
  const actions = [
    ["EXPLAIN_FINDING", "Explain vulnerability", "Explain this finding using supplied evidence."],
    ["EXPLAIN_POLICY_DECISION", "Why is this blocking?", "Why does policy block this finding?"],
    ["REMEDIATION_HELP", "Remediation help", "Suggest bounded remediation considerations."],
    ["VERIFICATION_HELP", "Verification help", "How can I manually verify a safe fix?"],
    ["EXPLAIN_CVSS_KEV_EPSS", "Explain CVSS / KEV / EPSS", "Explain the supplied threat evidence."],
  ];
  const buttons = actions.map(([task, label, question]) => {
    const button = createElement("button", {
      className: "button button-secondary",
      textContent: label,
      attributes: { type: "button" },
    });
    button.addEventListener("click", async () => {
      output.textContent = "Generating an optional evidence-grounded explanation…";
      button.disabled = true;
      try {
        const response = await onAsk(task, question);
        output.replaceChildren(
          createElement("strong", { textContent: "AI-generated explanation" }),
          createElement("p", { textContent: safe(response.answer, 12000) }),
          createElement("p", {
            textContent: `Evidence references: ${(response.evidence_refs || []).map((item) => safe(item, 100)).join(", ") || "None"}`,
          }),
        );
      } catch (_error) {
        output.textContent = "AI Assistant: Not configured or temporarily unavailable.";
      } finally {
        button.disabled = false;
      }
    });
    return button;
  });
  return createElement("section", { className: "ai-assistant" }, [
    createElement("h4", { textContent: "AI Assistant" }),
    createElement("div", { className: "ai-assistant-actions" }, buttons),
    output,
  ]);
}

export function renderKnowledgeCard(card, onAsk = null) {
  if (!card || typeof card.finding_id !== "string") return null;
  const cves = Array.isArray(card.cves) ? card.cves : [];
  const playbook = card.verification_playbook || {};
  const content = [
    createElement("h3", { textContent: "Finding Knowledge Card" }),
    facts([
      ["Finding ID", card.finding_id, true], ["Delta", card.delta_state, false],
      ["Policy impact", card.policy_impact, false], ["Advisory", card.advisory_id || "NOT_APPLICABLE", true],
      ["Threat context", card.cve_state, false],
    ]),
    ...cves.map((item) => createElement("article", { className: "knowledge-cve" }, [
      createElement("h4", { textContent: item.cve_id }),
      facts([
        ["CISA KEV", item.kev && item.kev.state, false],
        ["FIRST EPSS", item.epss && item.epss.state, false],
        ["NVD record", item.nvd ? item.nvd.enrichment_id : "UNAVAILABLE", true],
      ]),
    ])),
    createElement("h4", { textContent: "Verification Playbook" }),
    createElement("p", { textContent: safe(playbook.expected_secure_behavior, 1000) }),
    createElement("ul", {}, (playbook.manual_verification || []).map((item) =>
      createElement("li", { textContent: safe(item, 1000) }))),
    createElement("p", { textContent: `Retest: ${safe(playbook.retest, 1000)}` }),
    createElement("p", { className: "state-message", textContent: "Scanner finding ≠ manually validated vulnerability. Guidance ≠ verified patch." }),
  ];
  if (typeof onAsk === "function") content.push(renderAssistant(onAsk));
  return createElement("section", { className: "finding-knowledge-card" }, content);
}

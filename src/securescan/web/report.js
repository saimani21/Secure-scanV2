"use strict";

import { getCoverage, getDependencies, getGaps, getScanReport, getScanStages, getScanSummary } from "/assets/api.js";
import { codeValue, copyButton, createElement, errorState, loadingState } from "/assets/components.js";
import { authorityLabel, boundedDisplayText, capabilityLabel, coverageState, formatDateTime, priorityLabel, productStatus } from "/assets/format.js";
import { beginRequest } from "/assets/state.js";

function isRecord(value) { return Boolean(value && typeof value === "object" && !Array.isArray(value)); }
function safe(value, maximum = 520) { return typeof value === "string" && value ? boundedDisplayText(value, maximum) : null; }
function link(runId, suffix, label) { return createElement("a", { className: "text-link", textContent: label, attributes: { href: `/scans/${runId}/${suffix}` } }); }
function metric(label, value) { return createElement("div", { className: "report-metric" }, [createElement("dt", { textContent: label }), createElement("dd", { textContent: String(value) })]); }
function section(title, description, content, action = null) {
  return createElement("section", { className: "report-section" }, [
    createElement("header", { className: "report-section-heading" }, [
      createElement("div", {}, [createElement("h2", { textContent: title }), createElement("p", { textContent: description })]),
      ...(action ? [action] : []),
    ]),
    content,
  ]);
}

function downloadButton(raw, runId) {
  const button = createElement("button", { className: "button button-secondary", textContent: "Download JSON", attributes: { type: "button" } });
  button.addEventListener("click", () => {
    const blob = new Blob([raw], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = createElement("a", { attributes: { href: url, download: `securescan-report-${runId}.json` } });
    document.body.append(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(url);
  });
  return button;
}

function safeReason(error) {
  if (error && error.status === 409) return ["Report not ready", "The verified report has not been published for this scan.", "REPORT_NOT_READY"];
  if (error && error.status === 404) return ["Scan not found", "This scan does not exist or is no longer available.", "SCAN_NOT_FOUND"];
  return ["Verified report unavailable", "SecureScan could not load the canonical evidence report.", "REPORT_UNAVAILABLE"];
}

export function renderReportPage({
  region,
  route,
  services = { getCoverage, getDependencies, getGaps, getScanReport, getScanStages, getScanSummary },
  print = () => window.print(),
}) {
  region.replaceChildren(createElement("div", { className: "route-stack" }, [loadingState("Loading security report")]));
  region.setAttribute("aria-busy", "true");
  const request = beginRequest();
  const settled = Promise.allSettled([
    services.getScanSummary(route.runId, { signal: request.signal }),
    services.getScanStages(route.runId, { signal: request.signal }),
    services.getCoverage(route.runId, { signal: request.signal }),
    services.getGaps(route.runId, { limit: 6, offset: 0, signal: request.signal }),
    services.getScanReport(route.runId, { signal: request.signal }),
    services.getDependencies(route.runId, { limit: 1, offset: 0, signal: request.signal }),
  ]).then(([summaryResult, stagesResult, coverageResult, gapsResult, reportResult, dependenciesResult]) => {
    if (!request.isCurrent()) return;
    if (summaryResult.status === "rejected") {
      const [title, message, code] = safeReason(summaryResult.reason);
      region.replaceChildren(errorState(title, message, code)); return;
    }
    const summary = summaryResult.value;
    const stages = stagesResult.status === "fulfilled" && Array.isArray(stagesResult.value.stages) ? stagesResult.value.stages : [];
    const coverage = coverageResult.status === "fulfilled" ? coverageResult.value : null;
    const gaps = gapsResult.status === "fulfilled" ? gapsResult.value : null;
    const reportResponse = reportResult.status === "fulfilled" && isRecord(reportResult.value) && isRecord(reportResult.value.report) ? reportResult.value : null;
    const dependencyPage = dependenciesResult.status === "fulfilled" ? dependenciesResult.value : null;
    const status = productStatus(summary.product_status);
    const rawReport = reportResponse ? JSON.stringify(reportResponse.report, null, 2) : null;
    const actions = createElement("div", { className: "report-actions" }, [
      ...(rawReport ? [copyButton(rawReport, "Copy JSON"), downloadButton(rawReport, route.runId)] : []),
      (() => { const button = createElement("button", { className: "button button-secondary", textContent: "Print", attributes: { type: "button" } }); button.addEventListener("click", print); return button; })(),
    ]);
    const content = [
      createElement("header", { className: "page-header report-header" }, [
        createElement("p", { className: "eyebrow", textContent: "Report" }),
        createElement("h1", { textContent: "Security scan report" }),
        createElement("p", { className: "page-description", textContent: "Generated from immutable SecureScan evidence." }),
        actions,
      ]),
      section("Summary", "Authoritative Product Core scan totals.", createElement("dl", { className: "report-metrics" }, [
        metric("Status", status.label), metric("Findings", Number.isInteger(summary.finding_count) ? summary.finding_count : "Unknown"),
        metric("Analysis gaps", summary.gap_count === null ? "Unknown" : summary.gap_count),
        metric("Coverage complete", summary.coverage_complete === null ? "Pending" : summary.coverage_complete ? "Yes" : "No"),
      ])),
      section("Analysis coverage", "Execution and coverage remain separate authoritative states.", createElement("ul", { className: "report-compact-list" }, stages.map((stage) => createElement("li", {}, [
        createElement("strong", { textContent: capabilityLabel(stage.capability) }),
        createElement("span", { textContent: `${authorityLabel(stage.authority)} · ${stage.progress_state}` }),
        createElement("span", { textContent: stage.coverage_states === null ? "Coverage pending" : stage.coverage_states.map(coverageState).join(", ") || "Coverage unavailable" }),
      ]))), link(route.runId, "coverage", "Open Coverage →")),
      section("Findings", "Published security evidence by SecureScan priority.", createElement("dl", { className: "report-metrics" }, Object.entries(summary.priority_counts || {}).map(([priority, count]) => metric(priorityLabel(priority), count))), link(route.runId, "findings", "Open Findings →")),
      section("Dependencies", "Package inventory and dependency evaluation remain in the dedicated workspace.", createElement("p", { textContent: dependencyPage ? `${dependencyPage.total} ${dependencyPage.total === 1 ? "package" : "packages"} observed. Known vulnerability totals are not inferred here.` : "Dependency summary unavailable." }), link(route.runId, "dependencies", "Open Dependencies →")),
      section("Analysis gaps", "Published limitations remain distinct from coverage completion.", gaps ? (gaps.total ? createElement("ul", { className: "report-compact-list" }, gaps.items.map((gap) => createElement("li", {}, [createElement("strong", { textContent: authorityLabel(gap.authority) }), codeValue(safe(gap.code, 256) || "REASON_UNAVAILABLE"), createElement("bdi", { textContent: safe(gap.scope && gap.scope.value, 520) || "Scope unavailable" })]))) : createElement("p", { textContent: "No published gaps. Review Coverage before drawing a completeness conclusion." })) : createElement("p", { textContent: "Gap summary unavailable." }), link(route.runId, "gaps", "Open Gaps →")),
    ];
    const scope = reportResponse && isRecord(reportResponse.report.scope) ? reportResponse.report.scope : null;
    const provenance = [
      ["Run ID", route.runId], ["Project ID", safe(summary.project_id) || "Not provided"],
      ["Finalized", summary.finalized_at ? formatDateTime(summary.finalized_at) : "Not finalized"],
      ["Authorities", stages.length ? stages.map((stage) => authorityLabel(stage.authority)).join(", ") : "Unavailable"],
    ];
    if (scope) {
      for (const [label, field] of [["Repository digest", "repository_digest"], ["Profile digest", "profile_digest"], ["Plan digest", "plan_digest"]]) {
        const value = safe(scope[field], 128); if (value) provenance.push([label, value]);
      }
    }
    content.push(section(
      "Provenance",
      "Safe identifiers for the immutable source and evidence result.",
      createElement("dl", { className: "report-provenance" }, provenance.map(
        ([label, value]) => createElement("div", {}, [
          createElement("dt", { textContent: label }),
          createElement("dd", {}, [codeValue(value)]),
        ]),
      )),
    ));
    if (rawReport) {
      content.push(createElement("details", { className: "report-raw" }, [createElement("summary", { textContent: "Raw evidence report" }), createElement("pre", { textContent: rawReport })]));
    } else {
      const [title, message, code] = safeReason(reportResult.status === "rejected" ? reportResult.reason : null);
      content.push(errorState(title, message, code));
    }
    if (!coverage) content.splice(2, 0, errorState("Coverage detail unavailable", "The human report remains available, but verified coverage detail could not be loaded.", "COVERAGE_UNAVAILABLE"));
    region.replaceChildren(createElement("article", { className: "route-stack report-page" }, content));
  }).finally(() => { request.finish(); region.setAttribute("aria-busy", "false"); });
  return { dispose: request.cancel, settled };
}

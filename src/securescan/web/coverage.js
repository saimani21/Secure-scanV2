"use strict";

import { getCoverage, getScanStages } from "/assets/api.js";
import { codeValue, createElement, errorState, loadingState, statusIndicator } from "/assets/components.js";
import { authorityLabel, boundedDisplayText, capabilityLabel, coverageState, stageProgress } from "/assets/format.js";
import { beginRequest } from "/assets/state.js";

const COVERAGE_TONES = Object.freeze({
  COMPLETE: "success", COMPLETE_WITH_FINDINGS: "success", COMPLETE_WITH_SUPPRESSIONS: "success",
  PARTIAL: "warning", FAILED: "failure", NOT_APPLICABLE: "neutral",
});

function isRecord(value) { return Boolean(value && typeof value === "object" && !Array.isArray(value)); }
function safe(value, maximum = 520) { return typeof value === "string" && value ? boundedDisplayText(value, maximum) : null; }

function scopeLabel(location) {
  if (!isRecord(location)) return "Scope unavailable";
  if (location.kind === "REPOSITORY_SCOPE") return "Repository scope";
  return safe(location.path, 1100) || "Scope unavailable";
}

function outcomeView(outcome) {
  const label = coverageState(outcome && outcome.state);
  const tone = COVERAGE_TONES[outcome && outcome.state] || "neutral";
  const summary = [];
  if (safe(outcome && outcome.framework, 128)) summary.push(`Framework: ${safe(outcome.framework, 128)}`);
  if (Number.isInteger(outcome && outcome.finding_count)) summary.push(`Findings: ${outcome.finding_count}`);
  if (Number.isInteger(outcome && outcome.suppression_count)) summary.push(`Suppressions: ${outcome.suppression_count}`);
  if (Number.isInteger(outcome && outcome.gap_count)) summary.push(`Gaps: ${outcome.gap_count}`);
  const scope = Array.isArray(outcome && outcome.selected_scope) ? outcome.selected_scope.map(scopeLabel) : [];
  const technical = [
    createElement("p", { textContent: summary.join(" · ") }),
  ];
  const reason = safe(outcome && outcome.reason_code, 256);
  if (reason) technical.push(createElement("p", {}, [createElement("span", { textContent: "Reason · " }), codeValue(reason)]));
  if (scope.length) technical.push(createElement("ul", { className: "coverage-scope-list" }, scope.map((value) => createElement("li", { textContent: value }))));
  return createElement("article", { className: "coverage-outcome" }, [
    createElement("div", { className: "coverage-outcome-heading" }, [
      statusIndicator(label, tone),
      ...(safe(outcome && outcome.framework, 128) ? [createElement("span", { textContent: safe(outcome.framework, 128) })] : []),
    ]),
    createElement("details", { className: "coverage-technical" }, [createElement("summary", { textContent: "Technical scope" }), ...technical]),
  ]);
}

function stageCard(stage, outcomes, coveragePending) {
  const progress = stageProgress(stage && stage.progress_state);
  const values = [
    createElement("header", { className: "coverage-capability-heading" }, [
      createElement("div", {}, [
        createElement("h2", { textContent: capabilityLabel(stage && stage.capability) }),
        createElement("p", { textContent: authorityLabel(stage && stage.authority) }),
      ]),
    ]),
    createElement("dl", { className: "coverage-state-pair" }, [
      createElement("div", {}, [createElement("dt", { textContent: "Execution" }), createElement("dd", {}, [statusIndicator(progress.label, progress.tone)])]),
      createElement("div", {}, [
        createElement("dt", { textContent: "Coverage" }),
        createElement("dd", {}, coveragePending
          ? [statusIndicator("Pending", "neutral")]
          : outcomes.length
          ? [createElement("span", { textContent: outcomes.map((item) => coverageState(item.state)).join(", ") })]
          : [statusIndicator("Unavailable", "neutral")]),
      ]),
    ]),
  ];
  if (!coveragePending && outcomes.length) values.push(createElement("div", { className: "coverage-outcomes" }, outcomes.map(outcomeView)));
  return createElement("section", { className: "coverage-capability" }, values);
}

export function renderCoveragePage({ region, route, services = { getCoverage, getScanStages } }) {
  region.replaceChildren(createElement("div", { className: "route-stack" }, [loadingState("Loading coverage") ]));
  region.setAttribute("aria-busy", "true");
  const request = beginRequest();
  const settled = Promise.allSettled([
    services.getScanStages(route.runId, { signal: request.signal }),
    services.getCoverage(route.runId, { signal: request.signal }),
  ]).then(([stagesResult, coverageResult]) => {
    if (!request.isCurrent()) return;
    if (stagesResult.status === "rejected") {
      region.replaceChildren(errorState("Coverage unavailable", "SecureScan could not load the authoritative analysis roster.", "STAGES_UNAVAILABLE"));
      return;
    }
    const stages = Array.isArray(stagesResult.value.stages) ? stagesResult.value.stages : [];
    const coverage = coverageResult.status === "fulfilled" && isRecord(coverageResult.value) ? coverageResult.value : null;
    const outcomes = coverage && Array.isArray(coverage.outcomes) ? coverage.outcomes.filter(isRecord) : [];
    const pending = !coverage && coverageResult.status === "rejected" && coverageResult.reason && coverageResult.reason.status === 409;
    const cards = stages.map((stage) => stageCard(stage, outcomes.filter((item) => item.authority === stage.authority && item.capability === stage.capability), pending));
    const content = [
      createElement("header", { className: "page-header" }, [
        createElement("p", { className: "eyebrow", textContent: "Coverage" }),
        createElement("h1", { textContent: "Analysis coverage" }),
        createElement("p", { className: "page-description", textContent: "What SecureScan actually analyzed for this scan." }),
      ]),
    ];
    if (!coverage && !pending) content.push(errorState("Coverage detail unavailable", "Execution state remains available, but verified coverage detail could not be loaded.", "COVERAGE_UNAVAILABLE"));
    if (pending) content.push(createElement("p", { className: "coverage-pending-note", textContent: "Coverage is pending publication. Execution state remains current." }));
    content.push(createElement("div", { className: "coverage-roster" }, cards));
    region.replaceChildren(createElement("div", { className: "route-stack coverage-page" }, content));
  }).finally(() => { request.finish(); region.setAttribute("aria-busy", "false"); });
  return { dispose: request.cancel, settled };
}

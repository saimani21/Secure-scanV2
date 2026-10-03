"use strict";

import { getCoverage, getGaps } from "/assets/api.js";
import {
  evaluatePolicy, getBaseline, getBaselineHistory, getSecurityDelta,
  getTrustedPolicy, promoteBaseline, runScope,
} from "/assets/assurance_api.js";
import {
  codeValue, createElement, emptyState, errorState, loadingState,
  pageHeader, sectionHeading, statusIndicator,
} from "/assets/components.js";
import { boundedDisplayText, formatDateTime } from "/assets/format.js";
import { beginRequest, registerRouteCleanup } from "/assets/state.js";
import { getV15Assurance, v15Scope } from "/assets/product_release_api.js";
import { renderV15Dashboard } from "/assets/product_release.js";

const DELTA_STATES = ["INTRODUCED", "PRESENT", "REMOVED", "NOT_COMPARABLE"];
const POLICY_KINDS = ["VIOLATION", "WARNING", "EXCLUSION", "ERROR"];
const COMPARISON = new Set(["COMPLETE", "PARTIAL", "NOT_COMPARABLE"]);

function safe(value, maximum = 240) {
  return typeof value === "string" && value ? boundedDisplayText(value, maximum) : "Not provided";
}

function row(label, value, { code = false } = {}) {
  return createElement("div", { className: "finding-fact" }, [
    createElement("dt", { textContent: label }),
    createElement("dd", {}, [code ? codeValue(safe(value)) : createElement("span", { textContent: safe(value) })]),
  ]);
}

function section(title, id, body) {
  return createElement("section", { className: "page-section", attributes: { "aria-labelledby": id } }, [
    sectionHeading(title, "", id), body,
  ]);
}

function notReady(title, message, code) {
  return errorState(title, message, code);
}

function renderBaselineData(scope, state, history, onPromote) {
  if (!state || state.lineage_id !== scope.lineageId || !Number.isInteger(state.revision)) {
    return notReady("Baseline unavailable", "Current trusted baseline could not be verified.", "BASELINE_UNAVAILABLE");
  }
  const content = [createElement("p", { textContent:
    "A trusted baseline is the explicit comparison state. It does not mean the repository is vulnerability-free." })];
  if (state.baseline) {
    const baseline = state.baseline;
    content.push(createElement("p", {}, [statusIndicator("Trusted comparison state", "neutral")]));
    content.push(createElement("dl", { className: "finding-facts" }, [
      row("Baseline ID", baseline.baseline_id, { code: true }),
      row("Run ID", baseline.run_id, { code: true }),
      row("Revision", String(state.revision)),
      row("Promoted", formatDateTime(baseline.promoted_at)),
      row("Actor", baseline.actor_type),
    ]));
  } else {
    content.push(emptyState("No trusted baseline", "No run has been explicitly promoted for this lineage.",
      "No baseline is not evidence that the repository is clean."));
  }
  const promotion = createElement("button", { className: "button button-primary",
    textContent: "Promote this run as trusted baseline", attributes: { type: "button" } });
  const confirm = createElement("button", { className: "button button-primary", textContent: "Confirm promotion",
    attributes: { type: "button" } });
  const cancel = createElement("button", { className: "button button-secondary", textContent: "Cancel",
    attributes: { type: "button" } });
  const dialog = createElement("dialog", { className: "product-confirmation",
    attributes: { "aria-label": "Confirm trusted baseline promotion" } }, [
    createElement("h3", { textContent: "Promote this run?" }),
    createElement("p", { textContent:
      "This explicitly changes the trusted comparison state. It does not claim that this run is vulnerability-free." }),
    createElement("p", {}, [codeValue(scope.runId)]), confirm, cancel,
  ]);
  promotion.addEventListener("click", () => dialog.showModal());
  cancel.addEventListener("click", () => dialog.close());
  confirm.addEventListener("click", () => { dialog.close(); onPromote(state.revision); });
  content.push(promotion, dialog);
  if (history && Array.isArray(history.items) && history.items.length) {
    content.push(createElement("h3", { textContent: "Promotion history" }));
    content.push(createElement("ol", { className: "assurance-list" }, history.items.map((item) =>
      createElement("li", { textContent:
        `Revision ${item.revision}: ${safe(item.run_id, 80)} at ${formatDateTime(item.promoted_at)}` }))));
    if (history.total > history.items.length) content.push(createElement("p", { textContent:
      `Showing ${history.items.length} of ${history.total} promotions.` }));
  }
  return createElement("div", { className: "assurance-block" }, content);
}

function renderDeltaData(scope, delta) {
  if (!delta || delta.candidate_run_id !== scope.runId || !delta.baseline_id ||
      !COMPARISON.has(delta.comparison_status) || !Array.isArray(delta.findings) ||
      !Array.isArray(delta.authority_summaries)) {
    return notReady("Security Delta unavailable", "No exact, verified comparison is available for this run.",
      "DELTA_UNAVAILABLE");
  }
  const tone = delta.comparison_status === "COMPLETE" ? "success" : "warning";
  const content = [
    createElement("p", { textContent:
      "This comparison is pinned to the exact trusted baseline below; it is not the current baseline if a later promotion occurred." }),
    statusIndicator(delta.comparison_status, tone),
    createElement("dl", { className: "finding-facts" }, [
      row("Exact baseline ID", delta.baseline_id, { code: true }),
      row("Baseline run", delta.baseline_run_id, { code: true }),
      row("Baseline revision", String(delta.baseline_revision)),
      row("Candidate run", delta.candidate_run_id, { code: true }),
    ]),
  ];
  if (delta.comparison_status !== "COMPLETE") content.push(createElement("p", {
    className: "state-message state-error",
    textContent: "Comparison is partial or not comparable. Missing evidence must not be read as zero findings or a clean result.",
  }));
  content.push(createElement("h3", { textContent: "Authority comparison" }));
  content.push(createElement("ul", { className: "assurance-list" }, delta.authority_summaries.map((item) =>
    createElement("li", { textContent: `${safe(item.authority, 80)}: ${safe(item.comparison_status, 40)} · ` +
      `introduced ${item.introduced_count}, present ${item.present_count}, removed ${item.removed_count}, ` +
      `not comparable ${item.not_comparable_count}. ` +
      `Reasons: ${Array.isArray(item.reason_codes) ? item.reason_codes.map((reason) => safe(reason, 80)).join(", ") : "unavailable"}` }))));
  const counts = Object.fromEntries(DELTA_STATES.map((state) => [state, 0]));
  for (const item of delta.findings) if (DELTA_STATES.includes(item.state)) counts[item.state]++;
  content.push(createElement("p", { textContent: DELTA_STATES.map((state) => `${state}: ${counts[state]}`).join(" · ") }));
  if (delta.findings.length) content.push(createElement("ol", { className: "assurance-list" },
    delta.findings.slice(0, 200).map((item) => createElement("li", { textContent:
      `${safe(item.state, 40)} · ${safe(item.authority, 80)} · ${safe(item.finding_id, 80)} · ` +
      `${Array.isArray(item.reason_codes) ? item.reason_codes.map((reason) => safe(reason, 80)).join(", ") : "Reasons unavailable"}` }))));
  if (delta.findings.length > 200) content.push(createElement("p", { textContent:
    `Showing the first 200 of ${delta.findings.length} delta findings. Use the API for the full response.` }));
  return createElement("div", { className: "assurance-block" }, content);
}

function renderPolicyData(scope, trusted, evaluation, onEvaluate) {
  if (!trusted || trusted.lineage_id !== scope.lineageId || !trusted.policy_id) {
    return notReady("Trusted policy unavailable", "The current policy could not be verified.", "POLICY_UNAVAILABLE");
  }
  const content = [createElement("p", { textContent:
    "Policy is evaluated only when you request it. A completed scan alone is not a policy PASS." }),
    createElement("dl", { className: "finding-facts" }, [
      row("Current policy ID", trusted.policy_id, { code: true }),
      row("Current version", String(trusted.version)),
      row("Current digest", trusted.digest, { code: true }),
    ])];
  const evaluate = createElement("button", { className: "button button-primary",
    textContent: "Evaluate policy for this run", attributes: { type: "button" } });
  evaluate.addEventListener("click", onEvaluate);
  content.push(evaluate);
  if (!evaluation) {
    content.push(emptyState("Not evaluated in this view", "No policy outcome is assumed until an explicit evaluation returns."));
    return createElement("div", { className: "assurance-block" }, content);
  }
  if (evaluation.candidate_run_id !== scope.runId || !["PASS", "FAIL", "ERROR"].includes(evaluation.result)) {
    content.push(notReady("Policy result unavailable", "The evaluation did not match this run.", "POLICY_SCOPE_MISMATCH"));
    return createElement("div", { className: "assurance-block" }, content);
  }
  const descriptions = {
    PASS: "Policy evaluated safely and no configured blocking rule was violated.",
    FAIL: "Policy evaluated safely and a configured rule was violated.",
    ERROR: "SecureScan could not safely determine policy compliance.",
  };
  const tones = { PASS: "success", FAIL: "failure", ERROR: "error" };
  content.push(statusIndicator(evaluation.result, tones[evaluation.result]));
  content.push(createElement("p", { textContent: descriptions[evaluation.result] }));
  content.push(createElement("dl", { className: "finding-facts" }, [
    row("Evaluation ID", evaluation.evaluation_id, { code: true }),
    row("Candidate run", evaluation.candidate_run_id, { code: true }),
    row("Exact policy ID", evaluation.policy_id, { code: true }),
    row("Exact policy version", String(evaluation.policy_version)),
    row("Exact policy digest", evaluation.policy_digest, { code: true }),
    row("Exact baseline ID", evaluation.baseline_id || "Not configured", { code: true }),
    row("Exact baseline revision", evaluation.baseline_revision === null ? "Not configured" : String(evaluation.baseline_revision)),
    row("Evaluated", formatDateTime(evaluation.evaluated_at)),
  ]));
  for (const kind of POLICY_KINDS) {
    const decisions = Array.isArray(evaluation.decisions)
      ? evaluation.decisions.filter((item) => item.kind === kind) : [];
    content.push(createElement("h3", { textContent: kind === "EXCLUSION" ? "Excluded by effective governance" : `${kind[0]}${kind.slice(1).toLowerCase()}s` }));
    content.push(decisions.length
      ? createElement("ol", { className: "assurance-list" }, decisions.slice(0, 200).map((item) =>
        createElement("li", { textContent:
          `${safe(item.reason_code, 100)} · ${safe(item.finding_id, 80)} · ${safe(item.rule_id, 100)}` })))
      : createElement("p", { textContent: "None in this evaluation." }));
  }
  content.push(createElement("p", { textContent:
    "Excluded findings remain visible in the Findings view; exclusion does not erase evidence." }));
  return createElement("div", { className: "assurance-block" }, content);
}

function renderCoverageContext(runId, coverage, gaps) {
  const content = [createElement("p", { textContent:
    "Coverage and gaps qualify every findings count, delta and policy result. Unavailable coverage is not clean coverage." })];
  if (!coverage || typeof coverage.complete !== "boolean") {
    content.push(notReady("Coverage unavailable", "Authoritative coverage could not be read.", "COVERAGE_UNAVAILABLE"));
  } else {
    content.push(statusIndicator(coverage.complete ? "Coverage complete" : "Coverage incomplete",
      coverage.complete ? "success" : "warning"));
    if (coverage.counts_by_state && typeof coverage.counts_by_state === "object") {
      content.push(createElement("p", { textContent: Object.entries(coverage.counts_by_state)
        .map(([key, value]) => `${safe(key, 80)}: ${value}`).join(" · ") }));
    }
  }
  if (!gaps || !Number.isInteger(gaps.total)) content.push(notReady("Gaps unavailable",
    "Published analysis gaps could not be read.", "GAPS_UNAVAILABLE"));
  else content.push(createElement("p", { textContent: `Published gaps: ${gaps.total}` }));
  content.push(createElement("a", { className: "text-link", textContent: "Inspect coverage",
    attributes: { href: `/scans/${runId}/coverage` } }));
  content.push(createElement("a", { className: "text-link", textContent: "Inspect gaps",
    attributes: { href: `/scans/${runId}/gaps` } }));
  return createElement("div", { className: "assurance-block" }, content);
}

export function renderAssurancePage({
  region, route,
  services = { runScope, getBaseline, getBaselineHistory, promoteBaseline,
    getSecurityDelta, getTrustedPolicy, evaluatePolicy, getCoverage, getGaps,
    getV15Assurance },
}) {
  const v15Region = createElement("div", {}, [loadingState("Loading threat-informed assurance")]);
  const baselineRegion = createElement("div", {}, [loadingState("Loading trusted baseline")]);
  const deltaRegion = createElement("div", {}, [loadingState("Loading Security Delta")]);
  const policyRegion = createElement("div", {}, [loadingState("Loading trusted policy")]);
  const coverageRegion = createElement("div", {}, [loadingState("Loading coverage and gaps")]);
  const notice = createElement("p", { attributes: { role: "status", "aria-live": "polite" } });
  region.replaceChildren(createElement("div", { className: "route-stack assurance-page" }, [
    pageHeader({ eyebrow: "Assurance", title: "Baseline, delta and policy",
      description: "Exact run decisions and current trusted configuration are labeled separately." }),
    notice,
    section("Threat-informed Assurance Dashboard", "assurance-v15", v15Region),
    section("Coverage and gaps", "assurance-coverage", coverageRegion),
    section("Trusted baseline", "assurance-baseline", baselineRegion),
    section("Security Delta", "assurance-delta", deltaRegion),
    section("Trusted policy", "assurance-policy", policyRegion),
  ]));
  region.setAttribute("aria-busy", "true");
  let disposed = false;
  let scope = null;
  let baseline = null;
  let history = null;
  let trusted = null;
  let evaluation = null;
  let actionRequest = null;
  const initial = beginRequest();
  const unregister = registerRouteCleanup(dispose);

  function dispose() {
    disposed = true;
    initial.cancel();
    if (actionRequest) actionRequest.cancel();
    unregister();
  }

  async function refreshBaselineAndDelta() {
    const request = beginRequest();
    actionRequest = request;
    const [base, past, delta] = await Promise.allSettled([
      services.getBaseline(scope, { signal: request.signal }),
      services.getBaselineHistory(scope, { signal: request.signal }),
      services.getSecurityDelta(scope, { signal: request.signal }),
    ]);
    if (request.isCurrent() && !disposed) {
      baseline = base.status === "fulfilled" ? base.value : null;
      history = past.status === "fulfilled" ? past.value : null;
      baselineRegion.replaceChildren(renderBaselineData(scope, baseline, history, onPromote));
      deltaRegion.replaceChildren(delta.status === "fulfilled"
        ? renderDeltaData(scope, delta.value)
        : notReady("Security Delta unavailable", "A trusted baseline or comparable candidate is unavailable.",
          "DELTA_UNAVAILABLE"));
    }
    if (actionRequest === request) actionRequest = null;
    request.finish();
  }

  async function onPromote(expectedRevision) {
    if (actionRequest || disposed) return;
    const request = beginRequest();
    actionRequest = request;
    notice.textContent = "Promoting the selected run explicitly…";
    try {
      await services.promoteBaseline(scope, expectedRevision, { signal: request.signal });
      if (request.isCurrent() && !disposed) {
        actionRequest = null;
        request.finish();
        notice.textContent = "Promotion recorded. Refreshing authoritative baseline and delta.";
        await refreshBaselineAndDelta();
      }
    } catch (error) {
      if (request.isCurrent() && !disposed) notice.textContent = error && error.status === 409
        ? "Baseline revision changed. Refresh the page before promoting again."
        : "Promotion failed or the run was ineligible. No baseline change was assumed.";
    } finally {
      if (actionRequest === request) actionRequest = null;
      request.finish();
    }
  }

  async function onEvaluate() {
    if (actionRequest || disposed) return;
    const request = beginRequest();
    actionRequest = request;
    notice.textContent = "Evaluating trusted policy for this exact run…";
    try {
      const result = await services.evaluatePolicy(scope, { signal: request.signal });
      if (request.isCurrent() && !disposed) {
        evaluation = result;
        policyRegion.replaceChildren(renderPolicyData(scope, trusted, evaluation, onEvaluate));
        notice.textContent = "Policy evaluation recorded. Its baseline and policy identity are shown below.";
      }
    } catch (_error) {
      if (request.isCurrent() && !disposed) notice.textContent =
        "Policy evaluation could not be completed. This is not a PASS or FAIL result.";
    } finally {
      if (actionRequest === request) actionRequest = null;
      request.finish();
    }
  }

  const settled = (async () => {
    try {
      scope = await services.runScope(route.runId, { signal: initial.signal });
      if (!initial.isCurrent() || disposed) return;
      const [base, past, delta, policy, coverage, gaps] = await Promise.allSettled([
        services.getBaseline(scope, { signal: initial.signal }),
        services.getBaselineHistory(scope, { signal: initial.signal }),
        services.getSecurityDelta(scope, { signal: initial.signal }),
        services.getTrustedPolicy(scope, { signal: initial.signal }),
        services.getCoverage(route.runId, { signal: initial.signal }),
        services.getGaps(route.runId, { limit: 1, offset: 0, signal: initial.signal }),
      ]);
      if (!initial.isCurrent() || disposed) return;
      baseline = base.status === "fulfilled" ? base.value : null;
      history = past.status === "fulfilled" ? past.value : null;
      trusted = policy.status === "fulfilled" ? policy.value : null;
      baselineRegion.replaceChildren(renderBaselineData(scope, baseline, history, onPromote));
      deltaRegion.replaceChildren(delta.status === "fulfilled"
        ? renderDeltaData(scope, delta.value)
        : notReady("Security Delta unavailable", "A trusted baseline or comparable candidate is unavailable.",
          "DELTA_UNAVAILABLE"));
      policyRegion.replaceChildren(renderPolicyData(scope, trusted, evaluation, onEvaluate));
      coverageRegion.replaceChildren(renderCoverageContext(route.runId,
        coverage.status === "fulfilled" ? coverage.value : null,
        gaps.status === "fulfilled" ? gaps.value : null));
      const productScope = v15Scope(scope);
      if (productScope === null) {
        v15Region.replaceChildren(emptyState(
          "No V1.5 decision selected",
          "Select an immutable intelligence bundle and PolicyDecisionProof using the bundle and proof URL parameters.",
          "No decision is inferred from scan completion alone.",
        ));
      } else {
        try {
          const dashboard = await services.getV15Assurance(productScope, {
            signal: initial.signal,
          });
          if (initial.isCurrent() && !disposed) {
            v15Region.replaceChildren(renderV15Dashboard(dashboard));
          }
        } catch (_error) {
          if (initial.isCurrent() && !disposed) {
            v15Region.replaceChildren(notReady(
              "Threat-informed assurance unavailable",
              "The selected bundle and proof could not be verified for this run.",
              "ASSURANCE_UNAVAILABLE",
            ));
          }
        }
      }
    } catch (_error) {
      if (initial.isCurrent() && !disposed) region.replaceChildren(notReady(
        "Run assurance unavailable", "This run could not be scoped to an admitted project and lineage.",
        "RUN_SCOPE_UNAVAILABLE"));
    } finally {
      initial.finish();
      if (!disposed) region.setAttribute("aria-busy", "false");
    }
  })();
  return { dispose, settled };
}

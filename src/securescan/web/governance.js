"use strict";

import { codeValue, createElement, errorState, loadingState, statusIndicator } from "/assets/components.js";
import { boundedDisplayText, formatDateTime, lifecycleState } from "/assets/format.js";
import {
  getEffectiveGovernance,
  getFindingGovernance,
  getFindingSuppression,
  putFindingGovernance,
  putFindingSuppression,
  revokeFindingSuppression,
} from "/assets/governance_api.js";
import { isCanonicalUuid } from "/assets/router.js";
import { beginRequest } from "/assets/state.js";

const FINDING_ID = /^[0-9a-f]{64}$/;
const DISPOSITIONS = ["UNREVIEWED", "FALSE_POSITIVE", "ACCEPTED_RISK"];

function scopeOf(summary) {
  if (!summary || !isCanonicalUuid(summary.project_id) ||
      !isCanonicalUuid(summary.lineage_id) || !FINDING_ID.test(summary.finding_id || "")) {
    return null;
  }
  return { projectId: summary.project_id, lineageId: summary.lineage_id, findingId: summary.finding_id };
}

function scopeKey(scope) {
  return scope ? `${scope.projectId}/${scope.lineageId}/${scope.findingId}` : null;
}

export function createGovernanceController({ services = {
  getEffectiveGovernance, getFindingGovernance, getFindingSuppression,
  putFindingGovernance, putFindingSuppression, revokeFindingSuppression,
}, onChange }) {
  let selected = null;
  let activeRequest = null;
  let generation = 0;
  let disposed = false;
  let state = null;

  function change() {
    if (!disposed && typeof onChange === "function") onChange();
  }

  function cancel() {
    if (activeRequest) activeRequest.cancel();
    activeRequest = null;
  }

  async function load(scope = selected) {
    if (!scope || disposed) return;
    cancel();
    const current = ++generation;
    const request = beginRequest();
    activeRequest = request;
    state = { key: scopeKey(scope), loading: true, busy: false, error: null,
      governance: null, suppression: null, effective: null };
    change();
    const args = [scope.projectId, scope.lineageId, scope.findingId, { signal: request.signal }];
    const results = await Promise.allSettled([
      services.getFindingGovernance(...args),
      services.getFindingSuppression(...args),
      services.getEffectiveGovernance(...args),
    ]);
    if (!request.isCurrent() || current !== generation || disposed ||
        scopeKey(scope) !== scopeKey(selected)) {
      request.finish();
      return;
    }
    if (results.some((result) => result.status !== "fulfilled") ||
        results.some((result) => !result.value || result.value.finding_id !== scope.findingId ||
          result.value.lineage_id !== scope.lineageId)) {
      state = { ...state, loading: false, error: "Current governance is unavailable." };
    } else {
      state = { key: scopeKey(scope), loading: false, busy: false, error: null,
        governance: results[0].value, suppression: results[1].value, effective: results[2].value };
    }
    activeRequest = null;
    request.finish();
    change();
  }

  async function mutate(operation, body) {
    const scope = selected;
    if (!scope || !state || state.key !== scopeKey(scope) || state.loading || state.busy || state.error) return;
    cancel();
    const current = ++generation;
    const request = beginRequest();
    activeRequest = request;
    state = { ...state, busy: true, error: null };
    change();
    try {
      const args = [scope.projectId, scope.lineageId, scope.findingId];
      if (operation === "governance") {
        await services.putFindingGovernance(...args, body, { signal: request.signal });
      } else if (operation === "suppression") {
        await services.putFindingSuppression(...args, body, { signal: request.signal });
      } else if (operation === "revoke") {
        await services.revokeFindingSuppression(...args, body.expected_revision, { signal: request.signal });
      } else {
        throw new TypeError("Unknown governance action.");
      }
      if (request.isCurrent() && current === generation && scopeKey(scope) === scopeKey(selected)) {
        request.finish();
        activeRequest = null;
        await load(scope);
      }
    } catch (error) {
      if (request.isCurrent() && current === generation && scopeKey(scope) === scopeKey(selected)) {
        state = { ...state, busy: false, error: error && error.status === 409
          ? "State changed elsewhere. Refresh current governance before trying again."
          : "Governance update failed. No local decision was assumed." };
        change();
      }
    } finally {
      if (activeRequest === request) activeRequest = null;
      request.finish();
    }
  }

  return {
    select(summary) {
      const next = scopeOf(summary);
      if (scopeKey(next) === scopeKey(selected)) return;
      selected = next;
      cancel();
      generation++;
      state = null;
      change();
      if (next) void load(next);
    },
    stateFor(summary) {
      return state && state.key === scopeKey(scopeOf(summary)) ? state : null;
    },
    mutate,
    refresh() { return load(); },
    dispose() { disposed = true; cancel(); selected = null; state = null; },
  };
}

function field(label, value) {
  return createElement("div", { className: "finding-fact" }, [
    createElement("dt", { textContent: label }),
    createElement("dd", { textContent: boundedDisplayText(value, 240) }),
  ]);
}

function expiryValue(input) {
  const date = new Date(input.value);
  if (!input.value || Number.isNaN(date.getTime())) throw new TypeError("A valid expiry is required.");
  return date.toISOString();
}

function governanceForm(governance, busy, mutate) {
  const disposition = createElement("select", { attributes: { "aria-label": "Disposition" } });
  for (const value of DISPOSITIONS) {
    const option = createElement("option", { textContent: value });
    option.value = value;
    disposition.append(option);
  }
  disposition.value = DISPOSITIONS.includes(governance.disposition) ? governance.disposition : "UNREVIEWED";
  const reason = createElement("textarea", { attributes: { "aria-label": "Decision reason", maxlength: "1000", rows: "3" } });
  reason.value = governance.reason || "";
  const expiry = createElement("input", { attributes: { "aria-label": "Risk expiry", type: "datetime-local" } });
  const message = createElement("p", { attributes: { role: "status", "aria-live": "polite" } });
  const button = createElement("button", { className: "button button-primary", textContent: "Save decision", attributes: { type: "submit" } });
  button.disabled = busy;
  const form = createElement("form", { className: "product-form" }, [
    createElement("p", { textContent: "Unreviewed clears the decision. False positive needs a reason. Accepted risk needs a reason and future expiry." }),
    disposition, reason, expiry, button, message,
  ]);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    try {
      const value = disposition.value;
      if (!DISPOSITIONS.includes(value)) throw new TypeError("Invalid disposition.");
      const body = { disposition: value, reason: value === "UNREVIEWED" ? null : reason.value,
        expires_at: value === "ACCEPTED_RISK" ? expiryValue(expiry) : null,
        expected_revision: governance.revision };
      if (value !== "UNREVIEWED" && !reason.value.trim()) throw new TypeError("A reason is required.");
      message.textContent = "Saving current decision…";
      void mutate("governance", body);
    } catch (_error) {
      message.textContent = "Enter a valid reason and, for accepted risk, a future expiry.";
    }
  });
  return form;
}

function suppressionForm(suppression, busy, mutate) {
  const reason = createElement("textarea", { attributes: { "aria-label": "Suppression reason", maxlength: "1000", rows: "3" } });
  reason.value = suppression.reason || "";
  const expiry = createElement("input", { attributes: { "aria-label": "Suppression expiry", type: "datetime-local" } });
  const message = createElement("p", { attributes: { role: "status", "aria-live": "polite" } });
  const save = createElement("button", { className: "button button-primary", textContent: "Save suppression", attributes: { type: "submit" } });
  save.disabled = busy;
  const children = [reason, expiry, save, message];
  if (suppression.active) {
    const revoke = createElement("button", { className: "button button-secondary", textContent: "Revoke suppression", attributes: { type: "button" } });
    revoke.disabled = busy;
    revoke.addEventListener("click", () => { void mutate("revoke", { expected_revision: suppression.revision }); });
    children.push(revoke);
  }
  const form = createElement("form", { className: "product-form" }, children);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    try {
      if (!reason.value.trim()) throw new TypeError("A reason is required.");
      const body = { reason: reason.value, expires_at: expiryValue(expiry),
        expected_revision: suppression.revision };
      message.textContent = "Saving suppression…";
      void mutate("suppression", body);
    } catch (_error) {
      message.textContent = "Enter a valid reason and future expiry.";
    }
  });
  return form;
}

export function renderGovernance(state, mutate, refresh) {
  if (!state) return null;
  const content = [createElement("h3", { textContent: "Current governance" })];
  if (state.loading) {
    content.push(loadingState("Loading current governance"));
  } else if (state.error) {
    content.push(errorState("Governance unavailable", state.error, "GOVERNANCE_UNAVAILABLE"));
    const retry = createElement("button", { className: "button button-secondary", textContent: "Refresh governance", attributes: { type: "button" } });
    retry.addEventListener("click", () => { void refresh(); });
    content.push(retry);
  } else {
    const effective = state.effective;
    const governance = state.governance;
    const suppression = state.suppression;
    if (effective.review_required) {
      content.push(createElement("p", { className: "state-message state-error", textContent:
        "The finding has reopened after a prior exclusionary decision. The earlier decision is dormant until explicitly reaffirmed." }));
    }
    content.push(createElement("p", { textContent:
      `Current/evaluation-time state at ${formatDateTime(effective.evaluated_at)}. Historical scan lifecycle above is unchanged.` }));
    content.push(createElement("div", {}, [statusIndicator(
      effective.review_required ? "Review required" : "Current state",
      effective.review_required ? "warning" : "neutral",
    )]));
    content.push(createElement("dl", { className: "finding-facts" }, [
      field("Current lifecycle", lifecycleState(effective.lifecycle_state)),
      field("Disposition", governance.disposition),
      field("Decision revision", String(governance.revision)),
      field("False positive effective", String(effective.false_positive_effective)),
      field("Accepted risk effective", String(effective.accepted_risk_effective)),
      field("Suppression effective", String(effective.suppression_effective)),
      field("Suppression revision", String(suppression.revision)),
    ]));
    if (suppression.suppression_id) content.push(codeValue(suppression.suppression_id));
    if (Array.isArray(effective.reason_codes) && effective.reason_codes.length) {
      content.push(createElement("p", { textContent:
        `Reason codes: ${effective.reason_codes.map((value) => boundedDisplayText(value, 80)).join(", ")}` }));
    }
    content.push(governanceForm(governance, state.busy, mutate));
    content.push(createElement("h4", { textContent: "Suppression" }));
    if (suppression.expires_at) content.push(createElement("p", { textContent: `Expiry: ${formatDateTime(suppression.expires_at)}` }));
    content.push(suppressionForm(suppression, state.busy, mutate));
    if (state.busy) content.push(loadingState("Updating current governance"));
  }
  return createElement("section", { className: "finding-governance", attributes: { "aria-label": "Current governance" } }, content);
}

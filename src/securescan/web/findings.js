"use strict";

import { getFindings, getScanReport, getScanSummary } from "/assets/api.js";
import { getFindingGuidance, getRunProductFindings } from "/assets/product_api.js";
import { renderGuidance } from "/assets/guidance.js";
import { createGuidanceController } from "/assets/finding_guidance_state.js";
import { createGovernanceController, renderGovernance } from "/assets/governance.js";
import {
  getEffectiveGovernance,
  getFindingGovernance,
  getFindingSuppression,
  putFindingGovernance,
  putFindingSuppression,
  revokeFindingSuppression,
} from "/assets/governance_api.js";
import {
  codeValue,
  copyButton,
  createElement,
  emptyState,
  errorState,
  loadingState,
  paginationControls,
  statusIndicator,
} from "/assets/components.js";
import {
  authorityLabel,
  boundedDisplayText,
  findingCategory,
  formatDateTime,
  lifecycleState,
  paginationLabel,
  priorityPresentation,
} from "/assets/format.js";
import { beginRequest, registerRouteCleanup } from "/assets/state.js";

export const FINDING_PAGE_LIMIT = 50;
export const FINDING_ID_PATTERN = /^[0-9a-f]{64}$/;

const FILTERS = Object.freeze({
  priority: Object.freeze([
    ["CRITICAL", "Critical"],
    ["HIGH", "High"],
    ["MEDIUM", "Medium"],
    ["LOW", "Low"],
    ["INFO", "Info"],
    ["UNRANKED", "Priority not assigned"],
  ]),
  category: Object.freeze([
    ["CODE_SECURITY", "Code security"],
    ["SECRET_EXPOSURE", "Secret exposure"],
    ["DEPENDENCY_VULNERABILITY", "Dependency vulnerability"],
    ["CONFIGURATION_SECURITY", "Configuration security"],
  ]),
  lifecycle_state: Object.freeze([
    ["NEW", "New"],
    ["EXISTING", "Existing"],
    ["RESOLVED", "Resolved"],
    ["REOPENED", "Reopened"],
  ]),
  authority: Object.freeze([
    ["semgrep-ce", "Semgrep"],
    ["gitleaks", "Gitleaks"],
    ["osv.dev", "OSV"],
    ["checkov", "Checkov"],
  ]),
});

function isRecord(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function isAbortError(error) {
  return Boolean(error && typeof error === "object" && error.name === "AbortError");
}

function exactString(value, maximum = 512) {
  return typeof value === "string" && value ? boundedDisplayText(value, maximum) : null;
}

function knownFilter(name, value) {
  return FILTERS[name].some(([candidate]) => candidate === value) ? value : null;
}

export function readFindingUrlState(search) {
  const query = new URLSearchParams(typeof search === "string" ? search : "");
  const rawOffset = query.get("offset");
  const offset = rawOffset && /^\d+$/.test(rawOffset) ? Number(rawOffset) : 0;
  const finding = query.get("finding");
  return {
    authority: knownFilter("authority", query.get("authority")),
    category: knownFilter("category", query.get("category")),
    priority: knownFilter("priority", query.get("priority")),
    lifecycle_state: knownFilter("lifecycle_state", query.get("lifecycle_state")),
    offset: Number.isSafeInteger(offset) && offset >= 0 ? offset : 0,
    finding: finding && FINDING_ID_PATTERN.test(finding) ? finding : null,
  };
}

export function findingQuery(state) {
  const query = new URLSearchParams();
  for (const name of ["priority", "category", "lifecycle_state", "authority"]) {
    const value = knownFilter(name, state[name]);
    if (value) {
      query.set(name, value);
    }
  }
  if (Number.isSafeInteger(state.offset) && state.offset > 0) {
    query.set("offset", String(state.offset));
  }
  if (FINDING_ID_PATTERN.test(state.finding || "")) {
    query.set("finding", state.finding);
  }
  const rendered = query.toString();
  return rendered ? `?${rendered}` : "";
}

function subjectValue(summary, field) {
  return isRecord(summary && summary.subject) ? exactString(summary.subject[field]) : null;
}

export function findingSummaryTitle(summary) {
  const kind = subjectValue(summary, "kind");
  if (kind === "SOURCE_CODE" || kind === "SECRET_EXPOSURE") {
    return subjectValue(summary, "rule_id") || findingCategory(summary && summary.category);
  }
  if (kind === "CONFIGURATION_RESOURCE") {
    return subjectValue(summary, "resource", 320) || findingCategory(summary && summary.category);
  }
  return findingCategory(summary && summary.category);
}

export function formatFindingLocation(location) {
  if (!isRecord(location)) {
    return "Location unavailable";
  }
  if (location.kind === "REPOSITORY_SCOPE") {
    return "Repository scope";
  }
  const path = exactString(location.path, 520);
  if (!path) {
    return "Location unavailable";
  }
  if (location.kind === "SOURCE_SPAN" && Number.isInteger(location.start_line)) {
    const end = Number.isInteger(location.end_line) && location.end_line !== location.start_line
      ? `–${location.end_line}`
      : "";
    return `${path}:${location.start_line}${end}`;
  }
  if (location.kind === "REPOSITORY_PATH" || location.kind === "SOURCE_SPAN") {
    return path;
  }
  return "Location unavailable";
}

export function correlateFindingEvidence(summary, response) {
  if (
    !isRecord(summary) ||
    !FINDING_ID_PATTERN.test(summary.finding_id || "") ||
    !isRecord(response) ||
    !isRecord(response.report) ||
    !Array.isArray(response.report.findings) ||
    !Array.isArray(response.report.evidence) ||
    !Array.isArray(response.report.components)
  ) {
    return null;
  }
  const matches = response.report.findings.filter(
    (finding) => isRecord(finding) && finding.finding_id === summary.finding_id,
  );
  if (
    matches.length !== 1 ||
    matches[0].authority !== summary.authority ||
    matches[0].category !== summary.category ||
    !Array.isArray(matches[0].primary_evidence_refs) ||
    !matches[0].primary_evidence_refs.length
  ) {
    return null;
  }
  const evidenceById = new Map(
    response.report.evidence
      .filter((item) => isRecord(item) && typeof item.evidence_id === "string")
      .map((item) => [item.evidence_id, item]),
  );
  const primary = [];
  for (const reference of matches[0].primary_evidence_refs) {
    const evidence = typeof reference === "string" ? evidenceById.get(reference) : null;
    if (!evidence || evidence.authority !== summary.authority) {
      return null;
    }
    primary.push(evidence);
  }
  let component = null;
  if (isRecord(matches[0].subject) && typeof matches[0].subject.component_ref === "string") {
    const components = response.report.components.filter(
      (item) => isRecord(item) && item.component_ref === matches[0].subject.component_ref,
    );
    if (components.length !== 1) {
      return null;
    }
    component = components[0];
  }
  return { finding: matches[0], primary, component };
}

function evidenceOfKind(correlation, kind) {
  return correlation && correlation.primary.find(
    (item) => item.evidence_kind === kind && isRecord(item.payload),
  );
}

export function findingEvidenceTitle(summary, correlation) {
  if (summary.authority === "semgrep-ce") {
    const evidence = evidenceOfKind(correlation, "SEMGREP_RULE_MATCH");
    return exactString(evidence && evidence.payload.message, 256) || findingSummaryTitle(summary);
  }
  if (summary.authority === "checkov") {
    const evidence = evidenceOfKind(correlation, "CHECKOV_POLICY_OBSERVATION");
    return exactString(evidence && evidence.payload.check_name, 320) || findingSummaryTitle(summary);
  }
  if (summary.authority === "gitleaks") {
    const evidence = evidenceOfKind(correlation, "GITLEAKS_SECRET_OBSERVATION");
    return exactString(evidence && evidence.payload.rule_id) || findingSummaryTitle(summary);
  }
  if (summary.authority === "osv.dev") {
    const evidence = evidenceOfKind(correlation, "OSV_ADVISORY_GROUP");
    return exactString(evidence && evidence.payload.canonical_advisory_id) ||
      findingSummaryTitle(summary);
  }
  return findingSummaryTitle(summary);
}

function bdi(value, className = "") {
  return createElement("bdi", { className, textContent: value });
}

function filterControl(name, label, values, current, onChange) {
  const id = `finding-filter-${name}`;
  const select = createElement("select", {
    className: "finding-filter-select",
    attributes: { id, name, "aria-label": label },
  });
  const all = createElement("option", { textContent: `All ${label.toLowerCase()}` });
  all.value = "";
  select.append(all);
  for (const [value, text] of values) {
    const option = createElement("option", { textContent: text });
    option.value = value;
    option.selected = current === value;
    select.append(option);
  }
  select.value = current || "";
  select.addEventListener("change", () => onChange(select.value || null));
  return createElement("div", { className: "finding-filter" }, [
    createElement("label", { textContent: label, attributes: { for: id } }),
    select,
  ]);
}

function countLabel(total) {
  return `${total} ${total === 1 ? "finding" : "findings"}`;
}

function searchCandidates(summary) {
  const values = [
    findingSummaryTitle(summary),
    authorityLabel(summary && summary.authority),
    findingCategory(summary && summary.category),
    formatFindingLocation(summary && summary.primary_location),
  ];
  const subject = isRecord(summary && summary.subject) ? summary.subject : {};
  for (const field of ["rule_id", "resource", "framework", "detection_kind"]) {
    if (typeof subject[field] === "string") {
      values.push(subject[field]);
    }
  }
  return values.join("\n").toLocaleLowerCase();
}

function findingRow(summary, selected, href, onSelect) {
  const priority = priorityPresentation(summary && summary.priority_band);
  const link = createElement("a", {
    className: "finding-row-link",
    dataset: { findingId: summary.finding_id },
    attributes: {
      href,
      "aria-label": `Open finding ${findingSummaryTitle(summary)}, priority ${priority.label}`,
    },
  }, [
    createElement("div", { className: "finding-row-topline" }, [
      statusIndicator(priority.label, priority.tone),
      createElement("span", {
        className: "finding-lifecycle",
        textContent: summary && summary.lifecycle_state_at_run
          ? `At scan: ${lifecycleState(summary.lifecycle_state_at_run)}`
          : `Current: ${lifecycleState(summary && summary.lifecycle_state)}`,
      }),
    ]),
    createElement("h3", { textContent: findingSummaryTitle(summary) }),
    bdi(formatFindingLocation(summary && summary.primary_location), "finding-location"),
    createElement("span", {
      className: "finding-category",
      textContent: findingCategory(summary && summary.category),
    }),
  ]);
  if (selected) {
    link.setAttribute("aria-current", "true");
  }
  link.addEventListener("click", (event) => {
    if (
      event.defaultPrevented ||
      (event.button !== undefined && event.button !== 0) ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey
    ) {
      return;
    }
    event.preventDefault();
    onSelect();
  });
  return createElement("li", { className: "finding-row" }, [link]);
}

function fact(label, content, { code = false, copy = false } = {}) {
  const value = content instanceof Node
    ? content
    : code
    ? codeValue(boundedDisplayText(content, 520))
    : bdi(boundedDisplayText(content, 520));
  const values = [value];
  if (copy && typeof content === "string" && content) {
    values.push(copyButton(content, `Copy ${label.toLowerCase()}`));
  }
  return createElement("div", { className: "finding-fact" }, [
    createElement("dt", { textContent: label }),
    createElement("dd", {}, values),
  ]);
}

function exactEvidenceFields(summary, correlation) {
  const fields = [];
  if (summary.authority === "semgrep-ce") {
    const evidence = evidenceOfKind(correlation, "SEMGREP_RULE_MATCH");
    const rule = exactString(evidence && evidence.payload.rule_id);
    if (rule) fields.push(fact("Rule", rule, { code: true, copy: true }));
    const cwes = evidence && Array.isArray(evidence.payload.cwe_ids)
      ? evidence.payload.cwe_ids.filter((item) => typeof item === "string")
      : [];
    if (cwes.length) fields.push(fact("Classification", cwes.join(", "), { code: true }));
  } else if (summary.authority === "gitleaks") {
    const evidence = evidenceOfKind(correlation, "GITLEAKS_SECRET_OBSERVATION");
    const rule = exactString(evidence && evidence.payload.rule_id);
    const kind = exactString(evidence && evidence.payload.detection_kind);
    if (rule) fields.push(fact("Rule", rule, { code: true, copy: true }));
    if (kind) fields.push(fact("Detection kind", kind));
  } else if (summary.authority === "checkov") {
    const evidence = evidenceOfKind(correlation, "CHECKOV_POLICY_OBSERVATION");
    const check = exactString(evidence && evidence.payload.check_id);
    const resource = exactString(evidence && evidence.payload.resource, 520);
    if (check) fields.push(fact("Check", check, { code: true, copy: true }));
    if (resource) fields.push(fact("Resource", resource, { code: true }));
  } else if (summary.authority === "osv.dev") {
    const evidence = evidenceOfKind(correlation, "OSV_ADVISORY_GROUP");
    const advisory = exactString(evidence && evidence.payload.canonical_advisory_id);
    if (advisory) fields.push(fact("Advisory", advisory, { code: true, copy: true }));
    const payload = correlation && correlation.component && correlation.component.payload;
    if (isRecord(payload)) {
      const name = exactString(payload.package_name);
      const version = exactString(payload.package_version);
      if (name) fields.push(fact("Package", version ? `${name} ${version}` : name));
      const purl = exactString(payload.purl, 520);
      if (purl) fields.push(fact("Package URL", purl, { code: true, copy: true }));
    }
  }
  return fields;
}

function technicalEvidence(summary, correlation) {
  const rows = [
    fact("Finding ID", summary.finding_id, { code: true, copy: true }),
    fact("Authority", authorityLabel(summary.authority)),
    fact("Category", findingCategory(summary.category)),
    fact("SecureScan priority", priorityPresentation(summary.priority_band).label),
  ];
  if (typeof summary.severity === "string" && summary.severity) {
    rows.push(fact("Scanner severity", summary.severity));
  }
  const reasons = Array.isArray(summary.priority_reason_codes)
    ? summary.priority_reason_codes.filter((item) => typeof item === "string")
    : [];
  if (reasons.length) {
    rows.push(
      fact(
        "Priority reason codes",
        createElement("ul", { className: "technical-code-list" }, reasons.map((reason) =>
          createElement("li", {}, [codeValue(boundedDisplayText(reason, 160))])
        )),
      ),
    );
  }
  if (correlation) {
    const nativeIdentity = exactString(correlation.finding.native_finding_identity);
    if (nativeIdentity) {
      rows.push(fact("Native finding identity", nativeIdentity, { code: true }));
    }
    rows.push(
      fact(
        "Evidence references",
        createElement("ul", { className: "technical-code-list" }, correlation.primary.map(
          (item) => createElement("li", {}, [codeValue(item.evidence_id)]),
        )),
      ),
    );
  }
  return createElement("details", { className: "finding-technical-evidence" }, [
    createElement("summary", { textContent: "Technical evidence" }),
    createElement("dl", { className: "finding-facts finding-technical-facts" }, rows),
  ]);
}

function findingDetail(summary, reportState, guidanceState, governanceState, governanceActions) {
  const correlation = reportState.payload
    ? correlateFindingEvidence(summary, reportState.payload)
    : null;
  const priority = priorityPresentation(summary.priority_band);
  const title = findingEvidenceTitle(summary, correlation);
  const content = [
    createElement("div", { className: "finding-detail-status" }, [
      statusIndicator(priority.label, priority.tone),
      createElement("span", {
        className: "finding-lifecycle",
        textContent: summary.lifecycle_state_at_run
          ? `At scan: ${lifecycleState(summary.lifecycle_state_at_run)}`
          : `Current: ${lifecycleState(summary.lifecycle_state)}`,
      }),
    ]),
    createElement("h2", { textContent: title, attributes: { id: "finding-detail-title" } }),
    bdi(formatFindingLocation(summary.primary_location), "finding-detail-location"),
  ];
  const facts = [
    fact("Detected by", authorityLabel(summary.authority)),
    fact("Category", findingCategory(summary.category)),
  ];
  if (typeof summary.severity === "string" && summary.severity) {
    facts.push(fact("Scanner severity", summary.severity));
  }
  if (summary.first_seen_at) {
    facts.push(fact("First seen", formatDateTime(summary.first_seen_at)));
  }
  if (summary.last_seen_at) {
    facts.push(fact("Last seen", formatDateTime(summary.last_seen_at)));
  }
  if (summary.resolved_at) {
    facts.push(fact("Resolved", formatDateTime(summary.resolved_at)));
  }
  if (correlation) {
    facts.push(...exactEvidenceFields(summary, correlation));
  }
  content.push(createElement("dl", { className: "finding-facts" }, facts));

  if (!reportState.attempted || reportState.loading) {
    content.push(loadingState("Loading technical evidence"));
  } else if (reportState.failed) {
    content.push(errorState(
      "Technical evidence unavailable",
      "SecureScan could not load the verified evidence report.",
      "REPORT_UNAVAILABLE",
    ));
  } else if (!correlation) {
    content.push(errorState(
      "Technical evidence unavailable",
      "No exact report evidence matched this finding ID.",
      "EVIDENCE_NOT_CORRELATED",
    ));
  } else {
    content.push(technicalEvidence(summary, correlation));
  }
  const guidance = renderGuidance(guidanceState);
  if (guidance) content.push(guidance);
  const governance = renderGovernance(
    governanceState, governanceActions.mutate, governanceActions.refresh,
  );
  if (governance) content.push(governance);
  return createElement("article", {
    className: "finding-detail",
    attributes: { "aria-labelledby": "finding-detail-title" },
  }, content);
}

function noFindingSelected() {
  return emptyState(
    "Select a finding",
    "Choose a finding to inspect its validated summary and technical evidence.",
  );
}

function missingSelectedFinding() {
  return errorState(
    "Finding not present in this page",
    "This finding ID is not in the currently loaded result page. Change pages or clear the selection.",
    "FINDING_NOT_IN_PAGE",
  );
}

function fatalFindingsError(error, runId) {
  if (error && error.status === 404) {
    return ["Scan not found", "This scan does not exist or is no longer available.", "SCAN_NOT_FOUND"];
  }
  if (error && error.status === 409) {
    const code = ["SCAN_NOT_PUBLISHED", "PRODUCT_CORE_NOT_READY"].includes(error.code)
      ? error.code
      : "FINDINGS_NOT_READY";
    return [
      "Findings not ready",
      "Verified findings are not available for this scan yet.",
      code,
      `/scans/${runId}`,
    ];
  }
  return [
    "Findings unavailable",
    "SecureScan could not reconstruct the verified finding view for this scan. The system did not substitute an empty result.",
    "QUERY_UNAVAILABLE",
  ];
}

export function renderFindingsPage({
  region,
  route,
  services = { getFindings, getScanReport, getScanSummary, getFindingGuidance, getRunProductFindings,
    getEffectiveGovernance, getFindingGovernance, getFindingSuppression,
    putFindingGovernance, putFindingSuppression, revokeFindingSuppression },
  navigation = {
    search: () => window.location.search,
    push: (url) => window.history.pushState({ securescanRoute: "findings" }, "", url),
    replace: (url) => window.history.replaceState({ securescanRoute: "findings" }, "", url),
  },
  responsive = {
    desktop: window.matchMedia("(min-width: 1200px)"),
    mobile: window.matchMedia("(max-width: 767px)"),
  },
}) {
  const runId = route.runId;
  const state = readFindingUrlState(navigation.search());
  const countRegion = createElement("p", {
    className: "findings-total",
    textContent: "Loading findings",
    attributes: { role: "status", "aria-live": "polite" },
  });
  const updateWarning = createElement("div", {
    className: "findings-update-warning",
    attributes: { role: "status" },
  });
  const controlsRegion = createElement("div", { className: "findings-controls" });
  const listRegion = createElement("div", {
    className: "finding-list-region",
    attributes: { "aria-busy": "true" },
  }, [loadingState("Loading findings")]);
  const detailRegion = createElement("div", {
    className: "finding-detail-region",
    attributes: { "aria-label": "Finding detail" },
  }, [noFindingSelected()]);
  const mobileBack = createElement("button", {
    className: "button button-secondary finding-mobile-back",
    textContent: "Back to findings",
    attributes: { type: "button" },
  });
  const mobileDetailRegion = createElement("div", {
    className: "finding-mobile-detail",
    attributes: { "aria-label": "Finding detail" },
  });
  const dialogClose = createElement("button", {
    className: "button button-secondary",
    textContent: "Close",
    attributes: { type: "button", "aria-label": "Close finding detail" },
  });
  const dialogContent = createElement("div", { className: "finding-drawer-content" });
  const detailDialog = createElement("dialog", {
    className: "finding-detail-drawer",
    attributes: {
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "finding-drawer-title",
    },
  }, [
    createElement("header", { className: "finding-drawer-header" }, [
      createElement("h2", { textContent: "Finding detail", attributes: { id: "finding-drawer-title" } }),
      dialogClose,
    ]),
    dialogContent,
  ]);
  const workspace = createElement("div", { className: "findings-workspace" }, [
    createElement("div", { className: "finding-list-pane" }, [controlsRegion, listRegion]),
    detailRegion,
    createElement("div", { className: "finding-mobile-detail-shell" }, [
      mobileBack,
      mobileDetailRegion,
    ]),
  ]);

  region.replaceChildren(
    createElement("div", { className: "route-stack findings-page" }, [
      createElement("header", { className: "page-header findings-header" }, [
        createElement("p", { className: "eyebrow", textContent: "Findings" }),
        createElement("h1", { textContent: "Security findings" }),
        createElement("p", {
          className: "page-description",
          textContent: "Validated findings published for this scan.",
        }),
        countRegion,
        updateWarning,
      ]),
      workspace,
      detailDialog,
    ]),
  );
  region.setAttribute("aria-busy", "false");

  let disposed = false;
  let page = null;
  let searchTerm = "";
  let loadGeneration = 0;
  let listRequest = null;
  let suppressDialogClose = false;
  const reportState = {
    attempted: false,
    failed: false,
    loading: false,
    payload: null,
    promise: null,
  };

  const guidanceController = createGuidanceController({
    runId, services,
    onChange: () => { if (!disposed && state.finding) renderDetailTarget(); },
  });
  const governanceController = createGovernanceController({
    services,
    onChange: () => { if (!disposed && state.finding) renderDetailTarget(); },
  });
  const removeResponsiveListeners = [];
  let unregisterCleanup = () => {};
  function dispose() {
    if (disposed) return;
    disposed = true;
    guidanceController.dispose();
    governanceController.dispose();
    for (const remove of removeResponsiveListeners) remove();
    if (detailDialog.open) {
      suppressDialogClose = true;
      detailDialog.close();
    }
    unregisterCleanup();
  }
  unregisterCleanup = registerRouteCleanup(dispose);

  function currentUrl() {
    return `/scans/${runId}/findings${findingQuery(state)}`;
  }

  function writeUrl(mode = "push") {
    navigation[mode](currentUrl());
  }

  function selectedSummary() {
    return page && state.finding
      ? page.items.find((item) => item.finding_id === state.finding) || null
      : null;
  }

  function renderDetailTarget() {
    const selected = selectedSummary();
    const content = state.finding
      ? selected
        ? findingDetail(
          selected, reportState, guidanceController.stateFor(selected.finding_id),
          governanceController.stateFor(selected),
          { mutate: governanceController.mutate, refresh: governanceController.refresh },
        )
        : missingSelectedFinding()
      : noFindingSelected();
    workspace.className = `findings-workspace${state.finding ? " findings-has-selection" : ""}`;
    if (responsive.desktop.matches) {
      if (detailDialog.open) {
        suppressDialogClose = true;
        detailDialog.close();
      }
      dialogContent.replaceChildren();
      mobileDetailRegion.replaceChildren();
      detailRegion.replaceChildren(content);
      return;
    }
    if (responsive.mobile.matches) {
      if (detailDialog.open) {
        suppressDialogClose = true;
        detailDialog.close();
      }
      detailRegion.replaceChildren();
      dialogContent.replaceChildren();
      mobileDetailRegion.replaceChildren(content);
      return;
    }
    detailRegion.replaceChildren();
    mobileDetailRegion.replaceChildren();
    dialogContent.replaceChildren(content);
    if (state.finding && !detailDialog.open) {
      detailDialog.showModal();
      dialogClose.focus();
    } else if (!state.finding && detailDialog.open) {
      suppressDialogClose = true;
      detailDialog.close();
    }
  }

  async function ensureReport() {
    if (reportState.attempted) {
      return reportState.promise || Promise.resolve(reportState.payload);
    }
    reportState.attempted = true;
    reportState.loading = true;
    reportState.failed = false;
    const request = beginRequest();
    reportState.promise = services.getScanReport(runId, { signal: request.signal })
      .then((payload) => {
        if (
          request.isCurrent() &&
          !disposed &&
          isRecord(payload) &&
          payload.run_id === runId &&
          isRecord(payload.report)
        ) {
          reportState.payload = payload;
        } else if (request.isCurrent() && !disposed) {
          reportState.failed = true;
        }
        return reportState.payload;
      })
      .catch((error) => {
        if (!isAbortError(error) && request.isCurrent() && !disposed) {
          reportState.failed = true;
        }
        return null;
      })
      .finally(() => {
        reportState.loading = false;
        reportState.promise = null;
        request.finish();
        if (!disposed && state.finding) renderDetailTarget();
      });
    return reportState.promise;
  }

  function selectFinding(findingId, { historyMode = "push" } = {}) {
    if (!FINDING_ID_PATTERN.test(findingId || "")) return;
    state.finding = findingId;
    writeUrl(historyMode);
    renderList();
    renderDetailTarget();
    if (selectedSummary()) {
      void ensureReport();
      void guidanceController.select(selectedSummary().finding_id, selectedSummary().authority);
      governanceController.select(selectedSummary());
    }
  }

  function clearSelection({ historyMode = "push", restoreFocus = true } = {}) {
    const restoreId = state.finding;
    state.finding = null;
    governanceController.select(null);
    writeUrl(historyMode);
    renderList();
    renderDetailTarget();
    const restore = restoreId
      ? listRegion.querySelector(`[data-finding-id="${restoreId}"]`)
      : null;
    if (restoreFocus && restore instanceof HTMLElement && restore.isConnected) {
      restore.focus();
    }
  }

  mobileBack.addEventListener("click", () => clearSelection());
  dialogClose.addEventListener("click", () => {
    suppressDialogClose = true;
    detailDialog.close();
    clearSelection();
  });
  detailDialog.addEventListener("close", () => {
    if (suppressDialogClose) {
      suppressDialogClose = false;
      return;
    }
    if (state.finding) clearSelection();
  });

  function setFilter(name, value) {
    state[name] = knownFilter(name, value);
    state.offset = 0;
    state.finding = null;
    writeUrl();
    void loadFindings();
  }

  function clearFilters() {
    for (const name of Object.keys(FILTERS)) state[name] = null;
    state.offset = 0;
    state.finding = null;
    writeUrl();
    void loadFindings();
  }

  function renderControls() {
    const searchId = "finding-current-page-search";
    const search = createElement("input", {
      className: "finding-search-input",
      attributes: {
        id: searchId,
        type: "search",
        value: searchTerm,
        placeholder: "Title, authority, category, or path",
        autocomplete: "off",
      },
    });
    search.value = searchTerm;
    search.addEventListener("input", () => {
      searchTerm = search.value;
      renderList();
    });
    controlsRegion.replaceChildren(
      createElement("div", { className: "finding-server-filters" }, [
        filterControl("priority", "Priority", FILTERS.priority, state.priority, (value) =>
          setFilter("priority", value)
        ),
        filterControl("category", "Category", FILTERS.category, state.category, (value) =>
          setFilter("category", value)
        ),
        filterControl(
          "lifecycle_state",
          "Lifecycle",
          FILTERS.lifecycle_state,
          state.lifecycle_state,
          (value) => setFilter("lifecycle_state", value),
        ),
        filterControl("authority", "Authority", FILTERS.authority, state.authority, (value) =>
          setFilter("authority", value)
        ),
      ]),
      createElement("div", { className: "finding-page-search" }, [
        createElement("label", { textContent: "Search this page", attributes: { for: searchId } }),
        search,
        createElement("span", {
          className: "finding-search-scope",
          textContent: "Filters only the currently loaded page.",
        }),
      ]),
    );
  }

  function renderList() {
    if (!page) return;
    const needle = searchTerm.trim().toLocaleLowerCase();
    const visible = needle
      ? page.items.filter((item) => searchCandidates(item).includes(needle))
      : page.items;
    const activeFilters = Object.keys(FILTERS).some((name) => state[name]);
    const content = [];
    if (!page.total) {
      if (activeFilters) {
        const clear = createElement("button", {
          className: "button button-secondary",
          textContent: "Clear filters",
          attributes: { type: "button" },
        });
        clear.addEventListener("click", clearFilters);
        content.push(createElement("div", { className: "finding-empty-action" }, [
          emptyState(
            "No matching findings",
            "No findings on this result set match the selected filters.",
          ),
          clear,
        ]));
      } else {
        content.push(emptyState(
          "No findings",
          "No findings were reported by the analyses that completed for this scan.",
          "Review Coverage before interpreting this result as clean.",
        ));
      }
    } else if (!visible.length) {
      content.push(emptyState(
        "No matches on this page",
        "No loaded finding matches the current-page search.",
        `${page.items.length} findings are loaded on this page.`,
      ));
    } else {
      content.push(
        createElement("p", {
          className: "finding-page-count",
          textContent: needle
            ? `${visible.length} ${visible.length === 1 ? "match" : "matches"} on this page · ${countLabel(page.total)} for selected server filters`
            : `${page.items.length} loaded on this page`,
        }),
        createElement("ol", {
          className: "finding-list",
          attributes: { "aria-label": "Security findings" },
        }, visible.map((item) => findingRow(
          item,
          item.finding_id === state.finding,
          `/scans/${runId}/findings${findingQuery({ ...state, finding: item.finding_id })}`,
          () => selectFinding(item.finding_id),
        ))),
      );
    }
    if (page.total > 0) {
      content.push(paginationControls(
        { ...page, label: paginationLabel(page) },
        () => changePage(Math.max(0, page.offset - page.limit)),
        () => changePage(page.offset + page.limit),
      ));
    }
    listRegion.replaceChildren(...content);
    listRegion.setAttribute("aria-busy", "false");
  }

  function changePage(offset) {
    state.offset = offset;
    state.finding = null;
    writeUrl();
    void loadFindings();
  }

  async function loadFindings() {
    const generation = ++loadGeneration;
    const hadPage = page !== null;
    if (listRequest) listRequest.cancel();
    const request = beginRequest();
    listRequest = request;
    listRegion.setAttribute("aria-busy", "true");
    updateWarning.replaceChildren();
    if (!hadPage) listRegion.replaceChildren(loadingState("Loading findings"));
    try {
      const result = await (services.getRunProductFindings || services.getFindings)(runId, {
        authority: state.authority,
        category: state.category,
        priority: state.priority,
        lifecycleState: state.lifecycle_state,
        limit: FINDING_PAGE_LIMIT,
        offset: state.offset,
        signal: request.signal,
      });
      if (!request.isCurrent() || disposed || generation !== loadGeneration) return;
      page = result;
      countRegion.textContent = countLabel(page.total);
      renderControls();
      renderList();
      renderDetailTarget();
      if (selectedSummary()) {
        void ensureReport();
        void guidanceController.select(selectedSummary().finding_id, selectedSummary().authority);
        governanceController.select(selectedSummary());
      }
    } catch (error) {
      if (isAbortError(error) || !request.isCurrent() || disposed) return;
      if (hadPage) {
        updateWarning.replaceChildren(createElement("p", {
          textContent: "Finding update delayed. The previous result page remains displayed.",
        }));
        listRegion.setAttribute("aria-busy", "false");
      } else {
        const [title, message, code, overview] = fatalFindingsError(error, runId);
        dispose();
        const renderedError = errorState(title, message, code);
        const values = [
          createElement("header", { className: "page-header" }, [
            createElement("p", { className: "eyebrow", textContent: "Findings" }),
            createElement("h1", { textContent: title }),
            createElement("p", { className: "page-description", textContent: message }),
          ]),
          renderedError,
        ];
        if (overview) {
          values.push(createElement("a", {
            className: "text-link",
            textContent: "Open Scan Overview",
            attributes: { href: overview },
          }));
        }
        region.replaceChildren(createElement("div", { className: "route-stack" }, values));
      }
    } finally {
      if (listRequest === request) listRequest = null;
      request.finish();
    }
  }

  function responsiveChange() {
    if (!disposed) renderDetailTarget();
  }
  for (const media of [responsive.desktop, responsive.mobile]) {
    media.addEventListener("change", responsiveChange);
    removeResponsiveListeners.push(() => media.removeEventListener("change", responsiveChange));
  }

  renderControls();
  const settled = loadFindings();
  return { dispose, settled };
}

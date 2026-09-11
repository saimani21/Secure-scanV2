"use strict";

const SCAN_API = "/v1/scans";
const PAGE_SIZE = 50;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PRIORITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRANKED"];

const state = {
  requestGeneration: 0,
  activeGeneration: 0,
  findingsRequestGeneration: 0,
  dependenciesRequestGeneration: 0,
  runId: null,
  summary: null,
  findings: null,
  findingsOffset: 0,
  dependencies: null,
  dependenciesOffset: 0,
  coverage: null,
  gaps: null,
  report: null,
};

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function element(id) {
  return document.getElementById(id);
}

function clear(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function text(tag, value, className) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  node.textContent = value === null || value === undefined || value === "" ? "Not provided" : String(value);
  return node;
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") {
    return "Not provided";
  }
  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }
  return String(value);
}

function formatDate(value) {
  if (!value) {
    return "Not provided";
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? String(value) : parsed.toLocaleString();
}

function formatJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch (_error) {
    return "Not provided";
  }
}

function makeBadge(value, extraClass) {
  const badge = text("span", displayValue(value), "badge");
  const normalized = String(value || "neutral")
    .toLowerCase()
    .replaceAll("_", "-")
    .replace(/[^a-z0-9-]/g, "-");
  badge.classList.add(`status-${normalized}`);
  if (extraClass) {
    badge.classList.add(extraClass);
  }
  return badge;
}

function setBadge(node, value) {
  node.className = "badge";
  const normalized = String(value || "neutral")
    .toLowerCase()
    .replaceAll("_", "-")
    .replace(/[^a-z0-9-]/g, "-");
  node.classList.add(`status-${normalized}`);
  node.textContent = displayValue(value);
}

function setMessage(message, kind = "info") {
  const node = element("global-message");
  if (!message) {
    node.hidden = true;
    node.textContent = "";
    return;
  }
  node.className = `message message-${kind}`;
  node.textContent = message;
  node.hidden = false;
}

async function requestJson(path) {
  let response;
  try {
    response = await fetch(path, {
      method: "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
  } catch (_error) {
    throw new ApiError(0, "API_UNAVAILABLE", "SecureScan API is unavailable.");
  }

  let payload = null;
  try {
    payload = await response.json();
  } catch (_error) {
    if (response.ok) {
      throw new ApiError(response.status, "INVALID_RESPONSE", "SecureScan returned an invalid response.");
    }
  }
  if (!response.ok) {
    const detail = payload && typeof payload.detail === "object" ? payload.detail : null;
    const code = detail && typeof detail.code === "string" ? detail.code : `HTTP_${response.status}`;
    const message = detail && typeof detail.message === "string" ? detail.message : "SecureScan request failed.";
    throw new ApiError(response.status, code, message);
  }
  return payload;
}

function describeError(error) {
  if (error instanceof ApiError) {
    return `${error.code}: ${error.message}`;
  }
  return "API_UNAVAILABLE: SecureScan API is unavailable.";
}

function isCurrentRequest(runId, generation) {
  return (
    generation === state.requestGeneration &&
    generation === state.activeGeneration &&
    runId === state.runId
  );
}

function activeRequest() {
  if (!state.runId || state.activeGeneration !== state.requestGeneration) {
    return null;
  }
  return { runId: state.runId, generation: state.requestGeneration };
}

function showCurrentError(error, runId, generation) {
  if (isCurrentRequest(runId, generation)) {
    setMessage(describeError(error), "error");
  }
}

function appendDefinition(list, label, value, monospace = false) {
  const term = text("dt", label);
  const description = text("dd", displayValue(value), monospace ? "monospace" : "");
  list.append(term, description);
}

function summaryCard(label, value, note, tone) {
  const card = document.createElement("article");
  card.className = `summary-card ${tone || ""}`.trim();
  card.append(text("span", label, "summary-label"));
  card.append(text("strong", displayValue(value), "summary-value"));
  card.append(text("span", note, "summary-note"));
  return card;
}

function renderSummary(summary) {
  element("current-run-id").textContent = summary.run_id;
  setBadge(element("product-status"), summary.product_status);

  const cards = element("summary-cards");
  clear(cards);
  const coverage = summary.coverage_complete === null
    ? "PENDING"
    : summary.coverage_complete
      ? "COMPLETE"
      : "INCOMPLETE";
  cards.append(
    summaryCard("Product status", summary.product_status, "Durable lifecycle state", "accent-blue"),
    summaryCard("Findings", summary.finding_count, "Normalized indexed findings", "accent-red"),
    summaryCard("Coverage", coverage, "Never inferred from finding count", "accent-green"),
    summaryCard("Gaps", summary.gap_count, "Explicit analysis limitations", "accent-amber"),
  );

  const priorities = element("priority-summary");
  clear(priorities);
  for (const priority of PRIORITIES) {
    const row = document.createElement("div");
    row.className = "metric-row";
    row.append(makeBadge(priority));
    row.append(text("strong", summary.priority_counts[priority] || 0));
    priorities.append(row);
  }

  const categories = element("category-summary");
  clear(categories);
  const categoryEntries = Object.entries(summary.category_counts || {}).sort(
    ([left], [right]) => left.localeCompare(right),
  );
  for (const [category, count] of categoryEntries) {
    const row = document.createElement("div");
    row.className = "metric-row";
    row.append(text("span", category, "metric-name"));
    row.append(text("strong", count));
    categories.append(row);
  }
  if (categoryEntries.length === 0) {
    categories.append(text("p", "No indexed categories.", "inline-note"));
  }

  const metadata = element("run-metadata");
  clear(metadata);
  appendDefinition(metadata, "Lineage ID", summary.lineage_id, true);
  appendDefinition(metadata, "Submission sequence", summary.submission_sequence_number);
  appendDefinition(metadata, "Predecessor", summary.predecessor_run_id, true);
  appendDefinition(metadata, "Created", formatDate(summary.created_at));
  appendDefinition(metadata, "Published", formatDate(summary.published_at));
  appendDefinition(metadata, "Finalized", formatDate(summary.finalized_at));
  appendDefinition(metadata, "Indexed", summary.indexed);
  appendDefinition(metadata, "Lifecycle evaluated", summary.lifecycle_evaluated);
  appendDefinition(metadata, "Coverage counts", formatJson(summary.coverage_counts), true);
}

function resetPublishedState() {
  state.findingsRequestGeneration += 1;
  state.dependenciesRequestGeneration += 1;
  state.findings = null;
  state.findingsOffset = 0;
  state.dependencies = null;
  state.dependenciesOffset = 0;
  state.coverage = null;
  state.gaps = null;
  state.report = null;
  renderFindings();
  renderDependencies();
  renderCoverage();
}

async function openScan(runId) {
  const generation = ++state.requestGeneration;
  if (!UUID_PATTERN.test(runId)) {
    setMessage("INVALID_RUN_ID: Enter a canonical UUID returned by SecureScan.", "error");
    return;
  }

  setMessage("Loading durable scan state…", "info");
  resetPublishedState();
  try {
    const summary = await requestJson(`${SCAN_API}/${encodeURIComponent(runId)}`);
    if (generation !== state.requestGeneration) {
      return;
    }
    state.runId = summary.run_id;
    state.activeGeneration = generation;
    state.summary = summary;
    element("empty-state").hidden = true;
    element("scan-workspace").hidden = false;
    renderSummary(summary);

    if (!summary.published_at) {
      const status = summary.product_status;
      const explanation = status === "FAILED" || status === "CANCELLED"
        ? `${status}: No published report is available; this state is not clean.`
        : `${status}: The scan is still running or awaiting publication.`;
      setMessage(explanation, status === "FAILED" ? "error" : "warning");
      return;
    }

    const canonicalRunId = summary.run_id;
    const tasks = [
      loadCoverage(canonicalRunId, generation),
      loadGaps(canonicalRunId, generation),
      loadDependencies(canonicalRunId, generation),
      loadReport(canonicalRunId, generation),
    ];
    if (summary.indexed && summary.lifecycle_evaluated) {
      tasks.push(loadFindings(canonicalRunId, generation));
    }
    const results = await Promise.allSettled(tasks);
    if (!isCurrentRequest(canonicalRunId, generation)) {
      return;
    }
    const rejected = results.find((result) => result.status === "rejected");
    if (rejected && rejected.status === "rejected") {
      setMessage(describeError(rejected.reason), "warning");
    } else if (summary.coverage_complete === false) {
      setMessage("Published analysis contains incomplete coverage. Review the explicit gaps.", "warning");
    } else if (summary.finding_count === 0 && summary.coverage_complete === true) {
      setMessage(
        "No findings were returned within the completed declared coverage. " +
          "This does not prove the repository is secure.",
        "info",
      );
    } else {
      setMessage("Published analysis loaded from verified Product Core views.", "success");
    }
  } catch (error) {
    if (generation !== state.requestGeneration) {
      return;
    }
    state.runId = null;
    state.activeGeneration = 0;
    state.summary = null;
    element("scan-workspace").hidden = true;
    element("empty-state").hidden = false;
    setMessage(describeError(error), "error");
  }
}

function filterParameters() {
  const form = new FormData(element("finding-filters"));
  const parameters = new URLSearchParams({
    limit: String(PAGE_SIZE),
    offset: String(state.findingsOffset),
  });
  for (const name of ["authority", "category", "priority", "lifecycle_state"]) {
    const value = form.get(name);
    if (typeof value === "string" && value) {
      parameters.set(name, value);
    }
  }
  return parameters;
}

async function loadFindings(runId, generation) {
  const requestGeneration = ++state.findingsRequestGeneration;
  let page;
  try {
    page = await requestJson(
      `${SCAN_API}/${encodeURIComponent(runId)}/findings?${filterParameters()}`,
    );
  } catch (error) {
    if (
      !isCurrentRequest(runId, generation) ||
      requestGeneration !== state.findingsRequestGeneration
    ) {
      return;
    }
    throw error;
  }
  if (
    !isCurrentRequest(runId, generation) ||
    requestGeneration !== state.findingsRequestGeneration
  ) {
    return;
  }
  state.findings = page;
  renderFindings();
}

function subjectLabel(subject) {
  if (!subject || typeof subject !== "object") {
    return "Not provided";
  }
  for (const key of ["rule_id", "resource", "component_ref", "package_name"]) {
    if (subject[key]) {
      return String(subject[key]);
    }
  }
  return formatJson(subject);
}

function locationLabel(location) {
  if (!location || typeof location !== "object") {
    return "Not provided";
  }
  const path = location.path || location.value || "Not provided";
  if (location.start_line) {
    const end = location.end_line && location.end_line !== location.start_line
      ? `–${location.end_line}`
      : "";
    return `${path}:${location.start_line}${end}`;
  }
  return String(path);
}

function tableCell(value, className) {
  const cell = document.createElement("td");
  if (className) {
    cell.className = className;
  }
  cell.textContent = displayValue(value);
  return cell;
}

function renderFindings() {
  const rows = element("finding-rows");
  clear(rows);
  const page = state.findings;
  const items = page ? page.items : [];
  for (const finding of items) {
    const row = document.createElement("tr");
    row.tabIndex = 0;
    row.className = "interactive-row";
    row.setAttribute("aria-label", `Open finding ${finding.finding_id}`);

    const priority = document.createElement("td");
    priority.append(makeBadge(finding.priority_band));
    row.append(priority);
    row.append(tableCell(finding.lifecycle_state));
    row.append(tableCell(finding.category));
    row.append(tableCell(finding.authority));
    row.append(tableCell(subjectLabel(finding.subject), "subject-cell"));
    row.append(tableCell(locationLabel(finding.primary_location), "monospace"));
    row.addEventListener("click", () => openFindingDetail(finding));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openFindingDetail(finding);
      }
    });
    rows.append(row);
  }

  const total = page ? page.total : 0;
  const offset = page ? page.offset : 0;
  const end = Math.min(offset + items.length, total);
  element("finding-total").textContent = `${total} ${total === 1 ? "finding" : "findings"}`;
  element("findings-page").textContent = total ? `${offset + 1}–${end} of ${total}` : "0–0 of 0";
  element("findings-empty").hidden = items.length !== 0;
  element("findings-previous").disabled = !page || offset === 0;
  element("findings-next").disabled = !page || end >= total;
}

async function loadDependencies(runId, generation) {
  const requestGeneration = ++state.dependenciesRequestGeneration;
  const parameters = new URLSearchParams({
    limit: String(PAGE_SIZE),
    offset: String(state.dependenciesOffset),
  });
  let page;
  try {
    page = await requestJson(
      `${SCAN_API}/${encodeURIComponent(runId)}/dependencies?${parameters}`,
    );
  } catch (error) {
    if (
      !isCurrentRequest(runId, generation) ||
      requestGeneration !== state.dependenciesRequestGeneration
    ) {
      return;
    }
    throw error;
  }
  if (
    !isCurrentRequest(runId, generation) ||
    requestGeneration !== state.dependenciesRequestGeneration
  ) {
    return;
  }
  state.dependencies = page;
  renderDependencies();
}

function joinValues(values) {
  return Array.isArray(values) && values.length ? values.join(", ") : "Not provided";
}

function renderDependencies() {
  const rows = element("dependency-rows");
  clear(rows);
  const page = state.dependencies;
  const items = page ? page.items : [];
  for (const dependency of items) {
    const row = document.createElement("tr");
    const packageCell = document.createElement("td");
    packageCell.append(text("strong", dependency.name));
    packageCell.append(text("code", dependency.purl, "table-subvalue"));
    row.append(packageCell);
    row.append(tableCell(dependency.version, "monospace"));
    row.append(tableCell(dependency.package_type));
    row.append(tableCell((dependency.locations || []).map(locationLabel).join(", ") || "Not provided", "monospace"));

    const advisoryCell = document.createElement("td");
    advisoryCell.append(text("strong", dependency.known_vulnerability_count));
    advisoryCell.append(text("span", joinValues(dependency.advisory_aliases), "table-subvalue"));
    const bands = document.createElement("div");
    bands.className = "badge-row";
    for (const band of dependency.priority_bands || []) {
      bands.append(makeBadge(band));
    }
    advisoryCell.append(bands);
    row.append(advisoryCell);
    row.append(tableCell(joinValues(dependency.fixed_versions)));
    rows.append(row);
  }

  const total = page ? page.total : 0;
  const offset = page ? page.offset : 0;
  const end = Math.min(offset + items.length, total);
  element("dependency-total").textContent = `${total} ${total === 1 ? "package" : "packages"}`;
  element("dependencies-page").textContent = total ? `${offset + 1}–${end} of ${total}` : "0–0 of 0";
  element("dependencies-empty").hidden = items.length !== 0;
  element("dependencies-previous").disabled = !page || offset === 0;
  element("dependencies-next").disabled = !page || end >= total;
}

async function loadCoverage(runId, generation) {
  const coverage = await requestJson(`${SCAN_API}/${encodeURIComponent(runId)}/coverage`);
  if (!isCurrentRequest(runId, generation)) {
    return;
  }
  state.coverage = coverage;
  renderCoverage();
}

async function loadGaps(runId, generation) {
  const parameters = new URLSearchParams({ limit: "200", offset: "0" });
  const gaps = await requestJson(
    `${SCAN_API}/${encodeURIComponent(runId)}/gaps?${parameters}`,
  );
  if (!isCurrentRequest(runId, generation)) {
    return;
  }
  state.gaps = gaps;
  renderCoverage();
}

async function loadReport(runId, generation) {
  const response = await requestJson(`${SCAN_API}/${encodeURIComponent(runId)}/report`);
  if (!isCurrentRequest(runId, generation)) {
    return;
  }
  state.report = response.report;
}

function renderCoverage() {
  const coverage = state.coverage;
  setBadge(
    element("coverage-status"),
    coverage ? (coverage.complete ? "COMPLETE" : "INCOMPLETE") : "NOT PUBLISHED",
  );

  const counts = element("coverage-counts");
  clear(counts);
  if (coverage) {
    for (const [name, count] of Object.entries(coverage.counts_by_state)) {
      const item = document.createElement("div");
      item.append(makeBadge(name));
      item.append(text("strong", count));
      counts.append(item);
    }
  }

  const outcomes = element("coverage-outcomes");
  clear(outcomes);
  for (const outcome of coverage ? coverage.outcomes : []) {
    const item = document.createElement("article");
    item.className = "stack-item";
    const heading = document.createElement("div");
    heading.className = "stack-heading";
    heading.append(text("strong", outcome.authority));
    heading.append(makeBadge(outcome.state));
    item.append(heading);
    item.append(text("span", outcome.capability, "stack-subtitle"));
    const details = document.createElement("dl");
    details.className = "mini-definition-list";
    appendDefinition(details, "Framework", outcome.framework);
    appendDefinition(details, "Findings", outcome.finding_count);
    appendDefinition(details, "Gaps", outcome.gap_count);
    appendDefinition(details, "Suppressions", outcome.suppression_count);
    appendDefinition(details, "Reason", outcome.reason_code);
    item.append(details);
    item.append(text("span", "Selected scope", "stack-subtitle scope-label"));
    item.append(text("code", formatJson(outcome.selected_scope), "scope-block"));
    outcomes.append(item);
  }
  if (coverage && coverage.outcomes.length === 0) {
    outcomes.append(text("p", "No coverage outcomes were published.", "inline-empty"));
  }

  const gaps = element("gap-list");
  clear(gaps);
  const gapItems = state.gaps ? state.gaps.items : [];
  for (const gap of gapItems) {
    const item = document.createElement("article");
    item.className = "stack-item gap-item";
    const heading = document.createElement("div");
    heading.className = "stack-heading";
    heading.append(text("strong", gap.code));
    heading.append(makeBadge(gap.authority));
    item.append(heading);
    item.append(text("p", gap.message || "No explanatory message was provided."));
    item.append(text("code", formatJson(gap.scope), "scope-block"));
    gaps.append(item);
  }
  if (state.gaps && gapItems.length === 0) {
    gaps.append(text("p", "No explicit gaps were published.", "inline-empty"));
  }
  const gapTotal = state.gaps ? state.gaps.total : 0;
  element("gap-total").textContent = `${gapTotal} ${gapTotal === 1 ? "gap" : "gaps"}`;
}

function detailSection(title, value) {
  const section = document.createElement("section");
  section.className = "detail-section";
  section.append(text("h3", title));
  const block = document.createElement("pre");
  block.textContent = formatJson(value);
  section.append(block);
  return section;
}

function openFindingDetail(finding) {
  const drawer = element("finding-detail");
  const backdrop = element("drawer-backdrop");
  const content = element("detail-content");
  clear(content);

  const metadata = document.createElement("dl");
  metadata.className = "definition-list detail-metadata";
  appendDefinition(metadata, "Finding ID", finding.finding_id, true);
  appendDefinition(metadata, "Authority", finding.authority);
  appendDefinition(metadata, "Category", finding.category);
  appendDefinition(metadata, "Severity", finding.severity);
  appendDefinition(metadata, "Priority", finding.priority_band);
  appendDefinition(metadata, "Lifecycle", finding.lifecycle_state);
  appendDefinition(metadata, "First seen", formatDate(finding.first_seen_at));
  appendDefinition(metadata, "Last seen", formatDate(finding.last_seen_at));
  appendDefinition(metadata, "Resolved", formatDate(finding.resolved_at));
  content.append(metadata);
  content.append(detailSection("Subject", finding.subject));
  content.append(detailSection("Primary location", finding.primary_location));

  const reportFindings = state.report && Array.isArray(state.report.findings)
    ? state.report.findings
    : [];
  const reportFinding = reportFindings.find((item) => item.finding_id === finding.finding_id);
  if (reportFinding) {
    content.append(detailSection("Published finding", reportFinding));
    const references = [
      ...(reportFinding.primary_evidence_refs || []),
      ...(reportFinding.supporting_evidence_refs || []),
    ];
    const evidence = state.report && Array.isArray(state.report.evidence)
      ? state.report.evidence.filter((item) => references.includes(item.evidence_id))
      : [];
    content.append(detailSection("Evidence and provenance", evidence));
  } else {
    content.append(text("p", "Published detail is not available for this finding.", "inline-empty"));
  }

  drawer.hidden = false;
  backdrop.hidden = false;
  document.body.classList.add("drawer-open");
  element("close-detail").focus();
}

function closeFindingDetail() {
  element("finding-detail").hidden = true;
  element("drawer-backdrop").hidden = true;
  document.body.classList.remove("drawer-open");
}

function selectView(name) {
  for (const panel of document.querySelectorAll("[data-panel]")) {
    panel.hidden = panel.dataset.panel !== name;
  }
  for (const button of document.querySelectorAll("[data-view]")) {
    const selected = button.dataset.view === name;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-current", selected ? "page" : "false");
  }
}

element("open-scan-form").addEventListener("submit", (event) => {
  event.preventDefault();
  openScan(element("run-id").value.trim());
});

element("refresh-scan").addEventListener("click", () => {
  if (state.runId) {
    openScan(state.runId);
  }
});

element("finding-filters").addEventListener("submit", (event) => {
  event.preventDefault();
  const request = activeRequest();
  if (!request) {
    return;
  }
  state.findingsOffset = 0;
  loadFindings(request.runId, request.generation).catch((error) =>
    showCurrentError(error, request.runId, request.generation),
  );
});

element("findings-previous").addEventListener("click", () => {
  const request = activeRequest();
  if (!request) {
    return;
  }
  state.findingsOffset = Math.max(0, state.findingsOffset - PAGE_SIZE);
  loadFindings(request.runId, request.generation).catch((error) =>
    showCurrentError(error, request.runId, request.generation),
  );
});

element("findings-next").addEventListener("click", () => {
  const request = activeRequest();
  if (!request) {
    return;
  }
  state.findingsOffset += PAGE_SIZE;
  loadFindings(request.runId, request.generation).catch((error) =>
    showCurrentError(error, request.runId, request.generation),
  );
});

element("dependencies-previous").addEventListener("click", () => {
  const request = activeRequest();
  if (!request) {
    return;
  }
  state.dependenciesOffset = Math.max(0, state.dependenciesOffset - PAGE_SIZE);
  loadDependencies(request.runId, request.generation).catch((error) =>
    showCurrentError(error, request.runId, request.generation),
  );
});

element("dependencies-next").addEventListener("click", () => {
  const request = activeRequest();
  if (!request) {
    return;
  }
  state.dependenciesOffset += PAGE_SIZE;
  loadDependencies(request.runId, request.generation).catch((error) =>
    showCurrentError(error, request.runId, request.generation),
  );
});

for (const button of document.querySelectorAll("[data-view]")) {
  button.addEventListener("click", () => selectView(button.dataset.view));
}

element("close-detail").addEventListener("click", closeFindingDetail);
element("drawer-backdrop").addEventListener("click", closeFindingDetail);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !element("finding-detail").hidden) {
    closeFindingDetail();
  }
});

renderFindings();
renderDependencies();
renderCoverage();

"use strict";

import { getProject, getScanStages, getScanSummary } from "/assets/api.js";
import {
  codeValue,
  copyButton,
  createElement,
  errorState,
  loadingState,
  sectionHeading,
  statusIndicator,
} from "/assets/components.js";
import {
  boundedDisplayText,
  coverageState,
  formatDateTime,
  priorityLabel,
  productStatus,
  stageProgress,
} from "/assets/format.js";
import { isCanonicalUuid } from "/assets/router.js";
import { cachedProjectName, rememberProject } from "/assets/scans.js";
import { beginRequest, registerRouteCleanup } from "/assets/state.js";

export const SCAN_POLL_DELAY_MS = 5000;
export const TERMINAL_PRODUCT_STATUSES = new Set(["COMPLETED", "CANCELLED", "FAILED"]);
export const NONTERMINAL_PRODUCT_STATUSES = new Set([
  "QUEUED",
  "RUNNING",
  "PUBLISHED_PENDING_FINALIZATION",
  "BLOCKED_BY_PREDECESSOR",
]);

const PRIORITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRANKED"];
const STAGE_LABELS = new Map([
  ["semgrep-ce/python_sast", { label: "SAST", authority: "Semgrep" }],
  ["gitleaks/secret_detection", { label: "Secrets", authority: "Gitleaks" }],
  ["syft/package_inventory", { label: "Package inventory", authority: "Syft" }],
  [
    "osv.dev/dependency_advisory_matching",
    { label: "Dependency vulnerabilities", authority: "OSV" },
  ],
  [
    "checkov/configuration_security",
    { label: "Configuration security", authority: "Checkov" },
  ],
]);

function statusCopy(status) {
  const values = {
    QUEUED: {
      title: "Analysis queued",
      message: "SecureScan is waiting to begin processing this repository snapshot.",
    },
    RUNNING: {
      title: "Analysis in progress",
      message: "SecureScan is still processing this repository snapshot.",
    },
    PUBLISHED_PENDING_FINALIZATION: {
      title: "Results published",
      message: "Durable results are available and finalization is pending.",
    },
    BLOCKED_BY_PREDECESSOR: {
      title: "Analysis waiting on predecessor",
      message: "Finalization is waiting for the predecessor scan in this lineage.",
    },
    COMPLETED: {
      title: "Analysis completed",
      message: "The durable scan has been finalized.",
    },
    CANCELLED: {
      title: "Analysis cancelled",
      message: "This scan did not complete.",
    },
    FAILED: {
      title: "Analysis failed",
      message: "SecureScan could not complete this scan.",
    },
  };
  return values[status] || {
    title: "Analysis state unknown",
    message: "SecureScan returned an unrecognized durable product state.",
  };
}

function stageIdentity(stage) {
  const key = `${stage && stage.authority}/${stage && stage.capability}`;
  return STAGE_LABELS.get(key) || { label: "Unknown analysis", authority: "Unknown authority" };
}

function metric(label, value) {
  return createElement("div", { className: "scan-metric" }, [
    createElement("dt", { textContent: label }),
    createElement("dd", { textContent: value }),
  ]);
}

function nonnegativeInteger(value) {
  return Number.isInteger(value) && value >= 0;
}

function isAbortError(error) {
  return Boolean(error && typeof error === "object" && error.name === "AbortError");
}

function isRecord(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function renderMetrics(summary) {
  const metrics = [];
  const published = typeof summary.published_at === "string" && summary.published_at;
  if (published) {
    if (nonnegativeInteger(summary.finding_count)) {
      metrics.push(metric("Findings", String(summary.finding_count)));
    }
    if (typeof summary.coverage_complete === "boolean") {
      metrics.push(metric("Coverage", summary.coverage_complete ? "Complete" : "Incomplete"));
    } else {
      metrics.push(metric("Coverage", "Pending"));
    }
    if (nonnegativeInteger(summary.gap_count)) {
      metrics.push(metric("Gaps", String(summary.gap_count)));
    }
  } else {
    metrics.push(metric("Findings", "Pending"));
    metrics.push(metric("Coverage", "Pending"));
    metrics.push(metric("Gaps", "Pending"));
  }

  if (summary.indexed === true && summary.priority_counts && typeof summary.priority_counts === "object") {
    for (const priority of PRIORITY_ORDER) {
      const count = summary.priority_counts[priority];
      if (nonnegativeInteger(count)) {
        metrics.push(metric(priorityLabel(priority), String(count)));
      }
    }
  }
  return createElement("dl", { className: "scan-metrics" }, metrics);
}

function coveragePresentation(states) {
  if (states === null || states === undefined) {
    return createElement("span", { className: "coverage-pending", textContent: "Pending" });
  }
  if (!Array.isArray(states) || !states.length) {
    return createElement("span", { className: "coverage-pending", textContent: "Not reported" });
  }
  return createElement("ul", { className: "coverage-state-list" }, states.map((state) =>
    createElement("li", { textContent: coverageState(state) })
  ));
}

function stageRow(stage) {
  const identity = stageIdentity(stage);
  const progress = stageProgress(stage && stage.progress_state);
  const content = [
    createElement("div", { className: "stage-identity" }, [
      createElement("h3", { textContent: identity.label }),
      createElement("p", { textContent: identity.authority }),
    ]),
    createElement("div", { className: "stage-field" }, [
      createElement("span", { className: "stage-field-label", textContent: "Execution" }),
      statusIndicator(progress.label, progress.tone),
    ]),
    createElement("div", { className: "stage-field" }, [
      createElement("span", { className: "stage-field-label", textContent: "Coverage" }),
      coveragePresentation(stage && stage.coverage_states),
    ]),
  ];
  if (stage && typeof stage.reason_code === "string" && stage.reason_code) {
    content.push(
      createElement("div", { className: "stage-reason" }, [
        createElement("span", { className: "stage-field-label", textContent: "Reason" }),
        codeValue(boundedDisplayText(stage.reason_code, 160)),
      ]),
    );
  }
  return createElement("li", { className: "stage-row" }, content);
}

function renderStages(payload) {
  if (!payload || !Array.isArray(payload.stages)) {
    throw new TypeError("SecureScan returned an invalid stage roster.");
  }
  if (!payload.stages.length) {
    return errorState(
      "Analysis unavailable",
      "SecureScan returned no analysis stages for this source scan.",
      "INVALID_STAGE_ROSTER",
    );
  }
  return createElement("ol", {
    className: "stage-list",
    attributes: { "aria-label": "Analysis stages" },
  }, payload.stages.map(stageRow));
}

function detailRow(label, value, { allowCopy = true } = {}) {
  const rendered = boundedDisplayText(value, 240);
  const description = [codeValue(rendered)];
  if (allowCopy && typeof value === "string" && value) {
    description.push(copyButton(value, `Copy ${label.toLowerCase()}`));
  }
  return createElement("div", {}, [
    createElement("dt", { textContent: label }),
    createElement("dd", {}, description),
  ]);
}

function renderTechnicalDetails(summary) {
  const rows = [
    detailRow("Run ID", summary.run_id),
    detailRow("Project ID", summary.project_id),
    detailRow("Target ID", summary.target_id),
    detailRow("Lineage ID", summary.lineage_id),
  ];
  if (nonnegativeInteger(summary.submission_sequence_number)) {
    rows.push(
      detailRow("Sequence", `Sequence ${summary.submission_sequence_number}`, {
        allowCopy: false,
      }),
    );
  }
  rows.push(detailRow("Created timestamp", summary.created_at));
  if (summary.published_at) {
    rows.push(detailRow("Published timestamp", summary.published_at));
  }
  if (summary.finalized_at) {
    rows.push(detailRow("Finalized timestamp", summary.finalized_at));
  }
  return rows;
}

function primaryTimestamp(summary) {
  if (summary.finalized_at) {
    return { label: "Finalized", value: summary.finalized_at };
  }
  if (summary.published_at) {
    return { label: "Published", value: summary.published_at };
  }
  return { label: "Created", value: summary.created_at };
}

function fatalSummaryError(error) {
  if (error && error.status === 404) {
    return {
      title: "Scan not found",
      message: "This scan does not exist or is no longer available.",
      code: "SCAN_NOT_FOUND",
    };
  }
  if (error && error.status === 409) {
    const code = ["SCAN_NOT_PUBLISHED", "PRODUCT_CORE_NOT_READY"].includes(error.code)
      ? error.code
      : "SCAN_DATA_NOT_READY";
    return {
      title: "Scan data not ready",
      message: "SecureScan cannot read this durable scan view yet.",
      code,
    };
  }
  return {
    title: "Scan data unavailable",
    message: "SecureScan could not read the durable scan view.",
    code: "QUERY_UNAVAILABLE",
  };
}

export function renderScanPage({
  region,
  route,
  setBreadcrumb,
  services = { getProject, getScanStages, getScanSummary },
  scheduler = {
    setTimeout: (...args) => globalThis.setTimeout(...args),
    clearTimeout: (handle) => globalThis.clearTimeout(handle),
  },
}) {
  const runId = route.runId;
  const projectContext = createElement("div", {
    className: "scan-project-context",
    textContent: "Project context loading",
  });
  const statusRegion = createElement("div", { className: "scan-product-status" }, [
    statusIndicator("Loading", "neutral"),
  ]);
  const statusCopyRegion = createElement("div", { className: "scan-status-copy" }, [
    createElement("h2", { textContent: "Loading scan" }),
    createElement("p", { textContent: "Reading the durable scan summary." }),
  ]);
  const timestampRegion = createElement("dl", { className: "scan-primary-time" });
  const metricsRegion = createElement("div", {
    className: "resource-region",
    attributes: { "aria-busy": "true", "aria-label": "Scan summary" },
  }, [loadingState("Loading scan summary")]);
  const stagesRegion = createElement("div", {
    className: "resource-region",
    attributes: { "aria-busy": "true", "aria-label": "Analysis stages" },
  }, [loadingState("Loading analysis stages")]);
  const warningRegion = createElement("div", {
    className: "scan-update-warning",
    attributes: { role: "status" },
  });
  const announcement = createElement("span", {
    className: "visually-hidden",
    attributes: { role: "status", "aria-live": "polite" },
  });
  const refreshButton = createElement("button", {
    className: "button button-secondary scan-refresh",
    textContent: "Refresh",
    attributes: { type: "button", "aria-label": "Refresh scan summary and analysis stages" },
  });
  const detailsList = createElement("dl", { className: "scan-technical-list" });
  const technicalDetails = createElement("details", { className: "scan-technical-details" }, [
    createElement("summary", { textContent: "Technical details" }),
    detailsList,
  ]);

  region.replaceChildren(
    createElement("div", { className: "route-stack scan-overview" }, [
      createElement("header", { className: "scan-header" }, [
        createElement("p", { className: "eyebrow", textContent: "Project" }),
        projectContext,
        createElement("h1", { textContent: "Security scan" }),
        statusRegion,
        statusCopyRegion,
        timestampRegion,
        createElement("div", { className: "scan-actions" }, [refreshButton, announcement]),
        warningRegion,
      ]),
      createElement("section", {
        className: "page-section",
        attributes: { "aria-labelledby": "scan-summary-title" },
      }, [
        sectionHeading("Summary", "", "scan-summary-title"),
        metricsRegion,
      ]),
      createElement("section", {
        className: "page-section",
        attributes: { "aria-labelledby": "scan-analysis-title" },
      }, [
        sectionHeading("Analysis", "", "scan-analysis-title"),
        stagesRegion,
      ]),
      createElement("section", {
        className: "page-section scan-details-section",
        attributes: { "aria-labelledby": "scan-details-title" },
      }, [
        sectionHeading("Scan details", "", "scan-details-title"),
        technicalDetails,
      ]),
    ]),
  );
  region.setAttribute("aria-busy", "false");

  let disposed = false;
  let pollTimer = null;
  let refreshPromise = null;
  let lastSummary = null;
  let lastStages = null;
  let projectId = null;
  let projectName = null;
  let projectAttempted = false;

  function clearPollTimer() {
    if (pollTimer !== null) {
      scheduler.clearTimeout(pollTimer);
      pollTimer = null;
    }
  }

  let unregisterCleanup = () => {};
  function dispose() {
    if (disposed) {
      return;
    }
    disposed = true;
    clearPollTimer();
    unregisterCleanup();
  }
  unregisterCleanup = registerRouteCleanup(dispose);

  function updateBreadcrumb() {
    const label = projectName ? boundedDisplayText(projectName, 80) : "Project unavailable";
    const projectItem = { label };
    if (isCanonicalUuid(projectId)) {
      projectItem.href = `/projects/${projectId}`;
    }
    setBreadcrumb([
      { label: "Projects", href: "/projects" },
      projectItem,
      { label: "Security scan" },
    ]);
  }

  function updateProjectContext() {
    const label = projectName ? boundedDisplayText(projectName, 160) : "Project unavailable";
    const content = [createElement("strong", { textContent: label })];
    if (isCanonicalUuid(projectId)) {
      content.push(
        createElement("a", {
          className: "text-link",
          textContent: "Open project",
          attributes: { href: `/projects/${projectId}` },
        }),
      );
    }
    projectContext.replaceChildren(...content);
    updateBreadcrumb();
  }

  async function resolveProject({ force = false } = {}) {
    if (!isCanonicalUuid(projectId) || projectName || (projectAttempted && !force)) {
      updateProjectContext();
      return;
    }
    const cached = cachedProjectName(projectId);
    if (cached) {
      projectName = cached;
      updateProjectContext();
      return;
    }
    projectAttempted = true;
    const request = beginRequest();
    try {
      const project = await services.getProject(projectId, { signal: request.signal });
      if (request.isCurrent() && !disposed) {
        rememberProject(project);
        projectName = cachedProjectName(projectId);
      }
    } catch (error) {
      if (isAbortError(error)) {
        return;
      }
    } finally {
      if (request.isCurrent() && !disposed) {
        updateProjectContext();
      }
      request.finish();
    }
  }

  function updateSummary(summary) {
    const previousStatus = lastSummary && lastSummary.product_status;
    lastSummary = summary;
    const presentation = productStatus(summary.product_status);
    const copy = statusCopy(summary.product_status);
    statusRegion.replaceChildren(statusIndicator(presentation.label, presentation.tone));
    statusCopyRegion.replaceChildren(
      createElement("h2", { textContent: copy.title }),
      createElement("p", { textContent: copy.message }),
    );
    const timestamp = primaryTimestamp(summary);
    timestampRegion.replaceChildren(
      createElement("div", {}, [
        createElement("dt", { textContent: timestamp.label }),
        createElement("dd", { textContent: formatDateTime(timestamp.value) }),
      ]),
    );
    metricsRegion.replaceChildren(renderMetrics(summary));
    metricsRegion.setAttribute("aria-busy", "false");
    detailsList.replaceChildren(...renderTechnicalDetails(summary));

    if (projectId !== summary.project_id) {
      projectId = summary.project_id;
      projectName = cachedProjectName(projectId);
      projectAttempted = false;
      updateProjectContext();
    }
    const becameTerminal = Boolean(
      previousStatus &&
      NONTERMINAL_PRODUCT_STATUSES.has(previousStatus) &&
      TERMINAL_PRODUCT_STATUSES.has(summary.product_status)
    );
    if (becameTerminal) {
      announcement.textContent = `${presentation.label}. Scan updates stopped.`;
    }
    return becameTerminal;
  }

  function updateStages(payload) {
    lastStages = payload;
    stagesRegion.replaceChildren(renderStages(payload));
    stagesRegion.setAttribute("aria-busy", "false");
  }

  function schedulePoll() {
    clearPollTimer();
    if (
      disposed ||
      !lastSummary ||
      !NONTERMINAL_PRODUCT_STATUSES.has(lastSummary.product_status)
    ) {
      return;
    }
    pollTimer = scheduler.setTimeout(() => {
      pollTimer = null;
      void refresh({ source: "poll", allowProjectLookup: false });
    }, SCAN_POLL_DELAY_MS);
  }

  async function performRefresh({ source, allowProjectLookup }) {
    const hadSummary = lastSummary !== null;
    const hadStages = lastStages !== null;
    const summaryRequest = beginRequest();
    const stagesRequest = beginRequest();
    refreshButton.setAttribute("aria-busy", "true");
    warningRegion.replaceChildren();

    const [summaryResult, stagesResult] = await Promise.allSettled([
      services.getScanSummary(runId, { signal: summaryRequest.signal }),
      services.getScanStages(runId, { signal: stagesRequest.signal }),
    ]);
    if (disposed || !summaryRequest.isCurrent() || !stagesRequest.isCurrent()) {
      summaryRequest.finish();
      stagesRequest.finish();
      return;
    }

    let updateFailed = false;
    let becameTerminal = false;
    let projectLookup = null;
    if (summaryResult.status === "fulfilled") {
      if (!isRecord(summaryResult.value)) {
        if (!hadSummary) {
          dispose();
          region.replaceChildren(
            createElement("div", { className: "route-stack" }, [
              createElement("header", { className: "page-header" }, [
                createElement("p", { className: "eyebrow", textContent: "Scan" }),
                createElement("h1", { textContent: "Scan data unavailable" }),
                createElement("p", {
                  className: "page-description",
                  textContent: "SecureScan returned an invalid durable scan view.",
                }),
              ]),
              errorState(
                "Scan data unavailable",
                "SecureScan returned an invalid durable scan view.",
                "INVALID_RESPONSE",
              ),
            ]),
          );
        } else {
          updateFailed = true;
        }
      } else {
        becameTerminal = updateSummary(summaryResult.value);
        if (allowProjectLookup && !projectName) {
          projectLookup = resolveProject({ force: source === "manual" });
        }
      }
    } else if (!hadSummary && !isAbortError(summaryResult.reason)) {
      const failure = fatalSummaryError(summaryResult.reason);
      dispose();
      region.replaceChildren(
        createElement("div", { className: "route-stack" }, [
          createElement("header", { className: "page-header" }, [
            createElement("p", { className: "eyebrow", textContent: "Scan" }),
            createElement("h1", { textContent: failure.title }),
            createElement("p", { className: "page-description", textContent: failure.message }),
          ]),
          errorState(failure.title, failure.message, failure.code),
        ]),
      );
    } else if (!isAbortError(summaryResult.reason)) {
      updateFailed = true;
    }

    if (!disposed) {
      if (stagesResult.status === "fulfilled") {
        try {
          updateStages(stagesResult.value);
        } catch (_error) {
          if (!hadStages) {
            stagesRegion.replaceChildren(
              errorState(
                "Analysis unavailable",
                "SecureScan could not read the authoritative stage roster.",
                "INVALID_STAGE_ROSTER",
              ),
            );
            stagesRegion.setAttribute("aria-busy", "false");
          }
          updateFailed = true;
        }
      } else if (!hadStages && !isAbortError(stagesResult.reason)) {
        stagesRegion.replaceChildren(
          errorState(
            "Analysis unavailable",
            "SecureScan could not read the authoritative stage roster.",
            "QUERY_UNAVAILABLE",
          ),
        );
        stagesRegion.setAttribute("aria-busy", "false");
      } else if (!isAbortError(stagesResult.reason)) {
        updateFailed = true;
      }

      if (projectLookup) {
        await projectLookup;
      }

      if (updateFailed) {
        warningRegion.replaceChildren(
          createElement("p", {
            textContent: "Scan update delayed. Last successful information remains displayed.",
          }),
        );
      }
      if (source === "manual" && !becameTerminal) {
        announcement.textContent = updateFailed
          ? "Refresh delayed. Previous scan information remains displayed."
          : "Scan information refreshed.";
      }
      refreshButton.setAttribute("aria-busy", "false");
      schedulePoll();
    }
    summaryRequest.finish();
    stagesRequest.finish();
  }

  function refresh(options) {
    if (disposed) {
      return Promise.resolve();
    }
    if (refreshPromise) {
      return refreshPromise;
    }
    clearPollTimer();
    refreshPromise = performRefresh(options).finally(() => {
      refreshPromise = null;
    });
    return refreshPromise;
  }

  refreshButton.addEventListener("click", () => {
    void refresh({ source: "manual", allowProjectLookup: !projectName });
  });

  setBreadcrumb([
    { label: "Projects", href: "/projects" },
    { label: "Project unavailable" },
    { label: "Security scan" },
  ]);
  const settled = refresh({ source: "initial", allowProjectLookup: true });
  return {
    dispose,
    refresh: () => refresh({ source: "manual", allowProjectLookup: !projectName }),
    settled,
  };
}

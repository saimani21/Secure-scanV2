"use strict";

import { getProject, getProjectScans } from "/assets/api.js";
import {
  codeValue,
  copyButton,
  createElement,
  emptyState,
  errorState,
  loadingState,
  pageHeader,
  paginationControls,
  sectionHeading,
  statusIndicator,
} from "/assets/components.js";
import {
  boundedDisplayText,
  formatDate,
  formatDateTime,
  paginationLabel,
  productStatus,
} from "/assets/format.js";
import { isCanonicalUuid } from "/assets/router.js";
import { beginRequest } from "/assets/state.js";

const PROJECT_SCAN_LIMIT = 50;

export function trustedHostScanCommand(projectId) {
  if (!isCanonicalUuid(projectId)) {
    throw new TypeError("Project ID must be a canonical UUID.");
  }
  return `securescan scan /path/to/repository \\
  --project-id ${projectId}`;
}

function commandDrawer(projectId) {
  const command = trustedHostScanCommand(projectId);
  const titleId = `scan-command-title-${projectId}`;
  const descriptionId = `scan-command-description-${projectId}`;
  const openButton = createElement("button", {
    className: "button button-primary",
    textContent: "Scan repository",
    attributes: { type: "button" },
  });
  const closeButton = createElement("button", {
    className: "button button-secondary",
    textContent: "Close",
    attributes: { type: "button", "aria-label": "Close scan command" },
  });
  const dialog = createElement("dialog", {
    className: "command-drawer",
    attributes: { "aria-labelledby": titleId, "aria-describedby": descriptionId },
  }, [
    createElement("div", { className: "command-drawer-header" }, [
      createElement("div", {}, [
        createElement("p", { className: "eyebrow", textContent: "Scan from trusted host" }),
        createElement("h2", { textContent: "Run a repository scan", attributes: { id: titleId } }),
      ]),
      closeButton,
    ]),
    createElement("p", {
      textContent: "Run this command on the SecureScan host. The browser does not inspect or upload repository files.",
      attributes: { id: descriptionId },
    }),
    createElement("div", { className: "command-block" }, [
      createElement("pre", {}, [createElement("code", { textContent: command })]),
      copyButton(command, "Copy command"),
    ]),
  ]);
  let previousFocus = null;
  openButton.addEventListener("click", () => {
    previousFocus = document.activeElement;
    dialog.showModal();
    closeButton.focus();
  });
  closeButton.addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) {
      dialog.close();
    }
  });
  dialog.addEventListener("close", () => {
    if (previousFocus instanceof HTMLElement && previousFocus.isConnected) {
      previousFocus.focus();
    }
  });
  return { dialog, openButton };
}

function projectHeader(project, projectId) {
  const name = boundedDisplayText(project && project.name, 160);
  const drawer = commandDrawer(projectId);
  return createElement("div", { className: "project-heading-stack" }, [
    pageHeader({
      eyebrow: "Project",
      title: name,
      description: "Durable project identity and scan history.",
    }),
    createElement("dl", { className: "project-metadata" }, [
      createElement("div", {}, [
        createElement("dt", { textContent: "Created" }),
        createElement("dd", { textContent: formatDate(project && project.created_at) }),
      ]),
      createElement("div", {}, [
        createElement("dt", { textContent: "Technical ID" }),
        createElement("dd", {}, [codeValue(projectId)]),
      ]),
    ]),
    createElement("div", { className: "project-actions" }, [drawer.openButton]),
    drawer.dialog,
  ]);
}

function projectNotFound() {
  return createElement("div", { className: "route-stack" }, [
    pageHeader({
      eyebrow: "Project",
      title: "Project not found",
      description: "This project does not exist or is no longer available.",
    }),
    errorState(
      "Project not found",
      "Return to Projects and choose an available project.",
      "PROJECT_NOT_FOUND",
    ),
  ]);
}

function projectUnavailable() {
  return createElement("div", { className: "route-stack" }, [
    pageHeader({
      eyebrow: "Project",
      title: "Project data unavailable",
      description: "SecureScan could not read the durable project view.",
    }),
    errorState(
      "Project data unavailable",
      "The project navigation service is currently unavailable.",
      "PROJECT_QUERY_UNAVAILABLE",
    ),
  ]);
}

function replaceHeaderPreservingFocus(region, content) {
  const active = document.activeElement;
  const restoreHeadingFocus = (
    active instanceof HTMLElement &&
    active.tagName === "H1" &&
    region.contains(active)
  );
  region.replaceChildren(content);
  if (restoreHeadingFocus) {
    const heading = region.querySelector("h1");
    if (heading) {
      heading.setAttribute("tabindex", "-1");
      heading.focus();
    }
  }
}

function scanStatusLink(scan) {
  const presentation = productStatus(scan && scan.product_status);
  const indicator = statusIndicator(presentation.label, presentation.tone);
  if (!scan || !isCanonicalUuid(scan.run_id)) {
    return indicator;
  }
  return createElement("a", {
    className: "scan-status-link",
    attributes: {
      href: `/scans/${scan.run_id}`,
      "aria-label": `Open scan, status ${presentation.label}`,
    },
  }, [indicator]);
}

function projectScanTable(items, { caption = "Project scan history", maximum = items.length } = {}) {
  const table = createElement("table", { className: "data-table scan-table project-scan-table" });
  table.append(
    createElement("caption", { className: "visually-hidden", textContent: caption }),
    createElement("thead", {}, [
      createElement("tr", {}, [
        createElement("th", { textContent: "Status", attributes: { scope: "col" } }),
        createElement("th", { textContent: "Created", attributes: { scope: "col" } }),
        createElement("th", {
          className: "column-secondary",
          textContent: "Published",
          attributes: { scope: "col" },
        }),
        createElement("th", {
          className: "column-secondary",
          textContent: "Finalized",
          attributes: { scope: "col" },
        }),
        createElement("th", { textContent: "Sequence", attributes: { scope: "col" } }),
      ]),
    ]),
  );
  const body = createElement("tbody");
  for (const scan of items.slice(0, maximum)) {
    const sequence = Number.isInteger(scan.submission_sequence_number)
      ? `Sequence ${scan.submission_sequence_number}`
      : "Not provided";
    body.append(
      createElement("tr", {}, [
        createElement("td", { attributes: { "data-label": "Status" } }, [scanStatusLink(scan)]),
        createElement("td", {
          textContent: formatDateTime(scan.created_at),
          attributes: { "data-label": "Created" },
        }),
        createElement("td", {
          className: "column-secondary",
          textContent: formatDateTime(scan.published_at),
          attributes: { "data-label": "Published" },
        }),
        createElement("td", {
          className: "column-secondary",
          textContent: formatDateTime(scan.finalized_at),
          attributes: { "data-label": "Finalized" },
        }),
        createElement("td", { textContent: sequence, attributes: { "data-label": "Sequence" } }),
      ]),
    );
  }
  table.append(body);
  return createElement("div", { className: "table-frame" }, [table]);
}

function noProjectScans() {
  return emptyState(
    "No scans yet",
    "Run a scan from the trusted SecureScan host.",
    "Use Scan repository to copy the exact host command.",
  );
}

function historyError() {
  return errorState(
    "Scan history unavailable",
    "The project is available, but its durable scan history could not be read.",
    "QUERY_UNAVAILABLE",
  );
}

export function renderProjectPage({ region, route, services = { getProject, getProjectScans } }) {
  const projectId = route.projectId;
  const headerRegion = createElement("div", {
    className: "project-header-region",
    attributes: { "aria-busy": "true" },
  }, [pageHeader({ eyebrow: "Project", title: "Project", description: "Loading project." })]);
  const latestRegion = createElement("div", {
    className: "resource-region",
    attributes: { "aria-busy": "true" },
  }, [loadingState("Loading latest scan")]);
  const historyRegion = createElement("div", {
    className: "resource-region",
    attributes: { "aria-busy": "true" },
  }, [loadingState("Loading scan history")]);
  region.replaceChildren(
    createElement("div", { className: "route-stack" }, [
      headerRegion,
      createElement("section", { className: "page-section" }, [
        sectionHeading("Latest scan"),
        latestRegion,
      ]),
      createElement("section", { className: "page-section" }, [
        sectionHeading("Scan history"),
        historyRegion,
      ]),
    ]),
  );
  region.setAttribute("aria-busy", "false");

  const projectRequest = beginRequest();
  async function loadProject() {
    try {
      const project = await services.getProject(projectId, { signal: projectRequest.signal });
      if (projectRequest.isCurrent()) {
        replaceHeaderPreservingFocus(headerRegion, projectHeader(project, projectId));
      }
    } catch (error) {
      if (projectRequest.isCurrent() && error.name !== "AbortError") {
        replaceHeaderPreservingFocus(
          headerRegion,
          error.status === 404 ? projectNotFound() : projectUnavailable(),
        );
      }
    } finally {
      if (projectRequest.isCurrent()) {
        headerRegion.setAttribute("aria-busy", "false");
      }
      projectRequest.finish();
    }
  }

  let historyGeneration = 0;
  async function loadHistory(offset, { updateLatest = false } = {}) {
    const generation = ++historyGeneration;
    const request = beginRequest();
    historyRegion.setAttribute("aria-busy", "true");
    historyRegion.replaceChildren(loadingState("Loading scan history"));
    if (updateLatest) {
      latestRegion.setAttribute("aria-busy", "true");
      latestRegion.replaceChildren(loadingState("Loading latest scan"));
    }
    try {
      const page = await services.getProjectScans(projectId, {
        limit: PROJECT_SCAN_LIMIT,
        offset,
        signal: request.signal,
      });
      if (!request.isCurrent() || generation !== historyGeneration) {
        return;
      }
      if (updateLatest) {
        latestRegion.replaceChildren(
          page.items.length
            ? projectScanTable(page.items, { caption: "Latest scan", maximum: 1 })
            : noProjectScans(),
        );
      }
      if (!page.items.length) {
        historyRegion.replaceChildren(
          page.total === 0
            ? emptyState("No scan history", "No durable scans exist for this project.")
            : emptyState("No scans on this page", "Use Previous to return to available history."),
        );
      } else {
        historyRegion.replaceChildren(
          projectScanTable(page.items),
          paginationControls(
            { ...page, label: paginationLabel(page) },
            () => loadHistory(Math.max(0, page.offset - page.limit)),
            () => loadHistory(page.offset + page.limit),
          ),
        );
      }
    } catch (error) {
      if (request.isCurrent() && generation === historyGeneration && error.name !== "AbortError") {
        historyRegion.replaceChildren(historyError());
        if (updateLatest) {
          latestRegion.replaceChildren(historyError());
        }
      }
    } finally {
      if (request.isCurrent() && generation === historyGeneration) {
        historyRegion.setAttribute("aria-busy", "false");
        if (updateLatest) {
          latestRegion.setAttribute("aria-busy", "false");
        }
      }
      request.finish();
    }
  }

  return { settled: Promise.allSettled([loadProject(), loadHistory(0, { updateLatest: true })]) };
}

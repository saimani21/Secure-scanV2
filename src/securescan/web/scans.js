"use strict";

import { getProjects, getScans } from "/assets/api.js";
import {
  codeValue,
  createElement,
  emptyState,
  errorState,
  loadingState,
  pageHeader,
  paginationControls,
  statusIndicator,
} from "/assets/components.js";
import {
  boundedDisplayText,
  formatDateTime,
  paginationLabel,
  productStatus,
} from "/assets/format.js";
import { isCanonicalUuid } from "/assets/router.js";
import { beginRequest } from "/assets/state.js";

export const SCAN_PAGE_LIMIT = 50;
export const PROJECT_LOOKUP_PAGE_LIMIT = 50;
export const MAX_PROJECT_LOOKUP_PAGES = 4;

const projectNameCache = new Map();

export function rememberProjectPage(page) {
  for (const project of page && Array.isArray(page.items) ? page.items : []) {
    if (isCanonicalUuid(project.project_id) && typeof project.name === "string") {
      projectNameCache.set(project.project_id, project.name);
    }
  }
}

export async function resolveProjectNames(
  projectIds,
  { signal, seedPage = null, projectLoader = getProjects } = {},
) {
  if (seedPage) {
    rememberProjectPage(seedPage);
  }
  const requested = new Set(projectIds.filter((projectId) => isCanonicalUuid(projectId)));
  let unresolved = new Set(
    [...requested].filter((projectId) => !projectNameCache.has(projectId)),
  );
  let pagesUsed = seedPage && seedPage.offset === 0 ? 1 : 0;
  let offset = seedPage && seedPage.offset === 0 ? seedPage.limit : 0;
  let knownTotal = seedPage && seedPage.offset === 0 ? seedPage.total : null;

  while (
    unresolved.size &&
    pagesUsed < MAX_PROJECT_LOOKUP_PAGES &&
    (knownTotal === null || offset < knownTotal)
  ) {
    let page;
    try {
      page = await projectLoader({
        limit: PROJECT_LOOKUP_PAGE_LIMIT,
        offset,
        signal,
      });
    } catch (error) {
      if (error.name === "AbortError") {
        throw error;
      }
      break;
    }
    pagesUsed += 1;
    rememberProjectPage(page);
    knownTotal = page.total;
    unresolved = new Set(
      [...unresolved].filter((projectId) => !projectNameCache.has(projectId)),
    );
    const nextOffset = page.offset + page.limit;
    if (!page.items.length || nextOffset <= offset) {
      break;
    }
    offset = nextOffset;
  }

  return new Map(
    [...requested]
      .filter((projectId) => projectNameCache.has(projectId))
      .map((projectId) => [projectId, projectNameCache.get(projectId)]),
  );
}

function projectCell(scan, projectNames) {
  const projectId = scan && scan.project_id;
  const resolved = isCanonicalUuid(projectId) ? projectNames.get(projectId) : null;
  if (resolved) {
    const label = boundedDisplayText(resolved, 160);
    return createElement("a", {
      className: "row-primary-link",
      textContent: label,
      attributes: { href: `/projects/${projectId}`, title: resolved },
    });
  }
  const content = [createElement("span", { textContent: "Project unavailable" })];
  if (isCanonicalUuid(projectId)) {
    const details = createElement("details", { className: "row-technical-detail" }, [
      createElement("summary", { textContent: "Technical ID" }),
      codeValue(projectId),
    ]);
    content.push(details);
  }
  return createElement("div", { className: "cell-stack" }, content);
}

function scanStatusLink(scan, projectNames) {
  const presentation = productStatus(scan && scan.product_status);
  const indicator = statusIndicator(presentation.label, presentation.tone);
  if (!scan || !isCanonicalUuid(scan.run_id)) {
    return indicator;
  }
  const projectName = projectNames.get(scan.project_id);
  const context = projectName ? ` for ${boundedDisplayText(projectName, 80)}` : "";
  return createElement("a", {
    className: "scan-status-link",
    attributes: {
      href: `/scans/${scan.run_id}`,
      "aria-label": `Open scan${context}, status ${presentation.label}`,
    },
  }, [indicator]);
}

export function scanTable(
  items,
  projectNames,
  { caption = "Global scans", maximum = items.length } = {},
) {
  const table = createElement("table", { className: "data-table scan-table" });
  table.append(
    createElement("caption", { className: "visually-hidden", textContent: caption }),
    createElement("thead", {}, [
      createElement("tr", {}, [
        createElement("th", { textContent: "Project", attributes: { scope: "col" } }),
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
      ]),
    ]),
  );
  const body = createElement("tbody");
  for (const scan of items.slice(0, maximum)) {
    body.append(
      createElement("tr", {}, [
        createElement("td", { attributes: { "data-label": "Project" } }, [
          projectCell(scan, projectNames),
        ]),
        createElement("td", { attributes: { "data-label": "Status" } }, [
          scanStatusLink(scan, projectNames),
        ]),
        createElement("td", {
          textContent: formatDateTime(scan && scan.created_at),
          attributes: { "data-label": "Created" },
        }),
        createElement("td", {
          className: "column-secondary",
          textContent: formatDateTime(scan && scan.published_at),
          attributes: { "data-label": "Published" },
        }),
        createElement("td", {
          className: "column-secondary",
          textContent: formatDateTime(scan && scan.finalized_at),
          attributes: { "data-label": "Finalized" },
        }),
      ]),
    );
  }
  table.append(body);
  return createElement("div", { className: "table-frame" }, [table]);
}

export function noScansState(message = "SecureScan has no durable scan history to display.") {
  return emptyState("No scans yet", message);
}

export function scanListError() {
  return errorState(
    "Scan data unavailable",
    "SecureScan could not read the durable scan view.",
    "QUERY_UNAVAILABLE",
  );
}

export function renderScansPage({ region, services = { getProjects, getScans } }) {
  const listRegion = createElement("section", {
    className: "page-section",
    attributes: { "aria-labelledby": "scan-list-title", "aria-busy": "true" },
  }, [
    createElement("h2", {
      className: "section-title",
      textContent: "Scan history",
      attributes: { id: "scan-list-title" },
    }),
    loadingState("Loading scans"),
  ]);
  region.replaceChildren(
    createElement("div", { className: "route-stack" }, [
      pageHeader({
        eyebrow: "Scans",
        title: "Global scan history",
        description: "Open a durable scan without copying or pasting its run ID.",
      }),
      listRegion,
    ]),
  );
  region.setAttribute("aria-busy", "false");

  let loadGeneration = 0;
  async function load(offset) {
    const generation = ++loadGeneration;
    const request = beginRequest();
    listRegion.setAttribute("aria-busy", "true");
    listRegion.replaceChildren(
      createElement("h2", {
        className: "section-title",
        textContent: "Scan history",
        attributes: { id: "scan-list-title" },
      }),
      loadingState("Loading scans"),
    );
    try {
      const page = await services.getScans({
        limit: SCAN_PAGE_LIMIT,
        offset,
        signal: request.signal,
      });
      const names = await resolveProjectNames(
        page.items.map((scan) => scan.project_id),
        { signal: request.signal, projectLoader: services.getProjects },
      );
      if (!request.isCurrent() || generation !== loadGeneration) {
        return;
      }
      const content = [
        createElement("h2", {
          className: "section-title",
          textContent: "Scan history",
          attributes: { id: "scan-list-title" },
        }),
      ];
      if (!page.items.length) {
        content.push(noScansState());
      } else {
        content.push(scanTable(page.items, names));
        content.push(
          paginationControls(
            { ...page, label: paginationLabel(page) },
            () => load(Math.max(0, page.offset - page.limit)),
            () => load(page.offset + page.limit),
          ),
        );
      }
      listRegion.replaceChildren(...content);
    } catch (error) {
      if (request.isCurrent() && generation === loadGeneration && error.name !== "AbortError") {
        listRegion.replaceChildren(
          createElement("h2", {
            className: "section-title",
            textContent: "Scan history",
            attributes: { id: "scan-list-title" },
          }),
          scanListError(),
        );
      }
    } finally {
      if (request.isCurrent() && generation === loadGeneration) {
        listRegion.setAttribute("aria-busy", "false");
      }
      request.finish();
    }
  }

  return { settled: load(0) };
}

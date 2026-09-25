"use strict";

import { getProjects } from "/assets/api.js";
import {
  copyButton,
  createElement,
  emptyState,
  errorState,
  loadingState,
  pageHeader,
  paginationControls,
} from "/assets/components.js";
import { boundedDisplayText, formatDate, paginationLabel } from "/assets/format.js";
import { isCanonicalUuid } from "/assets/router.js";
import { beginRequest } from "/assets/state.js";

export const PROJECT_PAGE_LIMIT = 50;
const CREATE_PROJECT_COMMAND = 'securescan project create "my-service"';

function projectName(project) {
  return boundedDisplayText(project && project.name, 160);
}

function projectLink(project) {
  const name = projectName(project);
  if (!project || !isCanonicalUuid(project.project_id)) {
    return createElement("span", { textContent: name, attributes: { title: name } });
  }
  return createElement("a", {
    className: "row-primary-link",
    textContent: name,
    attributes: {
      href: `/projects/${project.project_id}`,
      title: typeof project.name === "string" ? project.name : name,
    },
  });
}

export function projectTable(items, { caption = "Projects", maximum = items.length } = {}) {
  const table = createElement("table", { className: "data-table project-table" });
  table.append(
    createElement("caption", { className: "visually-hidden", textContent: caption }),
    createElement("thead", {}, [
      createElement("tr", {}, [
        createElement("th", { textContent: "Project", attributes: { scope: "col" } }),
        createElement("th", { textContent: "Created", attributes: { scope: "col" } }),
      ]),
    ]),
  );
  const body = createElement("tbody");
  for (const project of items.slice(0, maximum)) {
    body.append(
      createElement("tr", {}, [
        createElement("td", { attributes: { "data-label": "Project" } }, [projectLink(project)]),
        createElement("td", {
          textContent: formatDate(project && project.created_at),
          attributes: { "data-label": "Created" },
        }),
      ]),
    );
  }
  table.append(body);
  return createElement("div", { className: "table-frame" }, [table]);
}

export function noProjectsState() {
  const command = createElement("div", { className: "command-block" }, [
    createElement("pre", {}, [createElement("code", { textContent: CREATE_PROJECT_COMMAND })]),
    copyButton(CREATE_PROJECT_COMMAND, "Copy command"),
  ]);
  return createElement("div", { className: "state-stack" }, [
    emptyState(
      "No projects yet",
      "Create a project from the trusted SecureScan host.",
      "Browser project creation is not available.",
    ),
    command,
  ]);
}

export function projectListError() {
  return errorState(
    "Project data unavailable",
    "SecureScan could not read the durable project view.",
    "PROJECT_QUERY_UNAVAILABLE",
  );
}

export function renderProjectsPage({ region, services = { getProjects } }) {
  const listRegion = createElement("section", {
    className: "page-section",
    attributes: { "aria-labelledby": "projects-list-title", "aria-busy": "true" },
  }, [
    createElement("h2", {
      className: "section-title",
      textContent: "Projects",
      attributes: { id: "projects-list-title" },
    }),
    loadingState("Loading projects"),
  ]);
  region.replaceChildren(
    createElement("div", { className: "route-stack" }, [
      pageHeader({
        eyebrow: "Projects",
        title: "Repository projects",
        description: "Open a project to review its durable scan history.",
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
        textContent: "Projects",
        attributes: { id: "projects-list-title" },
      }),
      loadingState("Loading projects"),
    );
    try {
      const page = await services.getProjects({
        limit: PROJECT_PAGE_LIMIT,
        offset,
        signal: request.signal,
      });
      if (!request.isCurrent() || generation !== loadGeneration) {
        return;
      }
      const content = [
        createElement("h2", {
          className: "section-title",
          textContent: "Projects",
          attributes: { id: "projects-list-title" },
        }),
      ];
      if (!page.items.length) {
        content.push(noProjectsState());
      } else {
        content.push(projectTable(page.items));
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
            textContent: "Projects",
            attributes: { id: "projects-list-title" },
          }),
          projectListError(),
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

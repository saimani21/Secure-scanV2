"use strict";

import { getProjects, getScans } from "/assets/api.js";
import {
  createElement,
  loadingState,
  pageHeader,
  resourceRegion,
  sectionHeading,
} from "/assets/components.js";
import { noProjectsState, projectListError, projectTable } from "/assets/projects.js";
import {
  noScansState,
  resolveProjectNames,
  scanListError,
  scanTable,
} from "/assets/scans.js";
import { beginRequest } from "/assets/state.js";

const OVERVIEW_PROJECT_LIMIT = 50;
const OVERVIEW_SCAN_LIMIT = 6;
const OVERVIEW_PROJECT_DISPLAY = 5;
const OVERVIEW_SCAN_DISPLAY = 6;

function overviewMetric(label) {
  const value = createElement("dd", { textContent: "Loading" });
  return {
    node: createElement("div", { className: "overview-metric" }, [
      createElement("dt", { textContent: label }),
      value,
    ]),
    value,
  };
}

function sectionLink(href, label) {
  return createElement("a", {
    className: "section-link",
    textContent: `${label} →`,
    attributes: { href },
  });
}

export function renderOverviewPage({ region, services = { getProjects, getScans } }) {
  const projectMetric = overviewMetric("Projects");
  const scanMetric = overviewMetric("Scans");
  const summary = createElement("dl", { className: "overview-summary" }, [
    projectMetric.node,
    scanMetric.node,
  ]);
  const scansRegion = resourceRegion("Recent scans");
  const projectsRegion = resourceRegion("Projects");
  region.replaceChildren(
    createElement("div", { className: "route-stack" }, [
      pageHeader({
        eyebrow: "Overview",
        title: "Repository security workspace",
        description: "Navigate durable projects and recent scans from one restrained workspace.",
      }),
      summary,
      createElement("section", {
        className: "page-section",
        attributes: { "aria-labelledby": "overview-scans-title" },
      }, [
        sectionHeading("Recent scans", "", "overview-scans-title"),
        scansRegion,
        sectionLink("/scans", "View all scans"),
      ]),
      createElement("section", {
        className: "page-section",
        attributes: { "aria-labelledby": "overview-projects-title" },
      }, [
        sectionHeading("Projects", "", "overview-projects-title"),
        projectsRegion,
        sectionLink("/projects", "View all projects"),
      ]),
    ]),
  );
  region.setAttribute("aria-busy", "false");

  const projectsRequest = beginRequest();
  const scansRequest = beginRequest();
  const projectPromise = services.getProjects({
    limit: OVERVIEW_PROJECT_LIMIT,
    offset: 0,
    signal: projectsRequest.signal,
  });
  const scanPromise = services.getScans({
    limit: OVERVIEW_SCAN_LIMIT,
    offset: 0,
    signal: scansRequest.signal,
  });

  async function loadProjects() {
    try {
      const page = await projectPromise;
      if (!projectsRequest.isCurrent()) {
        return null;
      }
      projectMetric.value.textContent = String(page.total);
      if (!page.items.length) {
        projectsRegion.replaceChildren(noProjectsState());
      } else {
        projectsRegion.replaceChildren(
          projectTable(page.items, {
            caption: "Projects in API order",
            maximum: OVERVIEW_PROJECT_DISPLAY,
          }),
        );
      }
      return page;
    } catch (error) {
      if (projectsRequest.isCurrent() && error.name !== "AbortError") {
        projectMetric.value.textContent = "Unavailable";
        projectsRegion.replaceChildren(projectListError());
      }
      return null;
    } finally {
      if (projectsRequest.isCurrent()) {
        projectsRegion.setAttribute("aria-busy", "false");
      }
      projectsRequest.finish();
    }
  }

  async function loadScans() {
    try {
      const page = await scanPromise;
      let seedPage = null;
      try {
        seedPage = await projectPromise;
      } catch (_error) {
        seedPage = null;
      }
      const names = await resolveProjectNames(
        page.items.map((scan) => scan.project_id),
        {
          signal: scansRequest.signal,
          seedPage,
          projectLoader: services.getProjects,
        },
      );
      if (!scansRequest.isCurrent()) {
        return;
      }
      scanMetric.value.textContent = String(page.total);
      if (!page.items.length) {
        scansRegion.replaceChildren(noScansState());
      } else {
        scansRegion.replaceChildren(
          scanTable(page.items, names, {
            caption: "Recent scans in API order",
            maximum: OVERVIEW_SCAN_DISPLAY,
          }),
        );
      }
    } catch (error) {
      if (scansRequest.isCurrent() && error.name !== "AbortError") {
        scanMetric.value.textContent = "Unavailable";
        scansRegion.replaceChildren(scanListError());
      }
    } finally {
      if (scansRequest.isCurrent()) {
        scansRegion.setAttribute("aria-busy", "false");
      }
      scansRequest.finish();
    }
  }

  projectsRegion.replaceChildren(loadingState("Loading projects"));
  scansRegion.replaceChildren(loadingState("Loading recent scans"));
  return { settled: Promise.allSettled([loadProjects(), loadScans()]) };
}

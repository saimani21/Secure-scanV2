"use strict";

const UUID_SOURCE = "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const PROJECT_ROUTE = new RegExp(`^/projects/(${UUID_SOURCE})$`);
const SCAN_ROUTE = new RegExp(
  `^/scans/(${UUID_SOURCE})(?:/(findings|assurance|dependencies|coverage|gaps|report))?$`,
);
const RESERVED_PREFIXES = ["/assets", "/health", "/ready", "/v1"];

export function isCanonicalUuid(value) {
  return new RegExp(`^${UUID_SOURCE}$`).test(value);
}

export function parseRoute(pathname) {
  if (
    typeof pathname !== "string" ||
    pathname.includes("\\") ||
    /%2f|%5c/i.test(pathname) ||
    RESERVED_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`))
  ) {
    return null;
  }
  if (pathname === "/") {
    return { name: "overview", path: pathname, projectId: null, runId: null };
  }
  if (pathname === "/projects") {
    return { name: "projects", path: pathname, projectId: null, runId: null };
  }
  if (pathname === "/scans") {
    return { name: "scans", path: pathname, projectId: null, runId: null };
  }
  const project = PROJECT_ROUTE.exec(pathname);
  if (project && isCanonicalUuid(project[1])) {
    return { name: "project", path: pathname, projectId: project[1], runId: null };
  }
  const scan = SCAN_ROUTE.exec(pathname);
  if (scan && isCanonicalUuid(scan[1])) {
    return {
      name: scan[2] || "scan",
      path: pathname,
      projectId: null,
      runId: scan[1],
    };
  }
  return null;
}

function approvedAnchor(anchor) {
  if (anchor.target && anchor.target !== "_self") {
    return null;
  }
  if (anchor.hasAttribute("download")) {
    return null;
  }
  const url = new URL(anchor.href, window.location.href);
  if (url.origin !== window.location.origin || url.search || url.hash) {
    return null;
  }
  return parseRoute(url.pathname);
}

export function installNavigation(onNavigate) {
  document.addEventListener("click", (event) => {
    if (
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey
    ) {
      return;
    }
    if (!(event.target instanceof Element)) {
      return;
    }
    const anchor = event.target.closest("a[href]");
    if (!anchor) {
      return;
    }
    const route = approvedAnchor(anchor);
    if (!route) {
      return;
    }
    event.preventDefault();
    if (window.location.pathname !== route.path) {
      window.history.pushState({ securescanRoute: route.name }, "", route.path);
    }
    onNavigate(route);
  });
  window.addEventListener("popstate", () => onNavigate(parseRoute(window.location.pathname)));
}

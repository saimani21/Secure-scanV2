"use strict";

import { getReadiness } from "/assets/api.js";
import {
  breadcrumb,
  codeValue,
  createElement,
  emptyState,
  errorState,
  loadingState,
  pageHeader,
  statusIndicator,
} from "/assets/components.js";
import { formatDateTime, statusLabel, truncateMiddle } from "/assets/format.js";
import { installNavigation, parseRoute } from "/assets/router.js";
import { beginRequest, beginRoute } from "/assets/state.js";

const ROUTE_SHELLS = Object.freeze({
  overview: {
    eyebrow: "Overview",
    title: "Repository security. Evidence first.",
    description: "Project and recent-scan navigation will be implemented in V1.1C2.",
  },
  projects: {
    eyebrow: "Projects",
    title: "Durable project navigation",
    description: "Project listing will be implemented in V1.1C2.",
  },
  project: {
    eyebrow: "Project",
    title: "Project workspace",
    description: "Project detail and scan history will be implemented in V1.1C2.",
  },
  scans: {
    eyebrow: "Scans",
    title: "Source scan history",
    description: "Global scan navigation will be implemented in V1.1C2.",
  },
  scan: {
    eyebrow: "Current scan",
    title: "Scan overview",
    description: "Authoritative scan progress will be implemented in V1.1C3.",
  },
  findings: {
    eyebrow: "Current scan",
    title: "Findings",
    description: "Finding navigation and evidence detail will be implemented in V1.1C4.",
  },
  dependencies: {
    eyebrow: "Current scan",
    title: "Dependencies",
    description: "Dependency evaluation detail will be implemented in V1.1C5.",
  },
  coverage: {
    eyebrow: "Current scan",
    title: "Coverage",
    description: "Capability coverage will be implemented in V1.1C6.",
  },
  gaps: {
    eyebrow: "Current scan",
    title: "Analysis gaps",
    description: "Explicit analysis gaps will be implemented in V1.1C6.",
  },
  report: {
    eyebrow: "Current scan",
    title: "Verified report",
    description: "The report workspace will be implemented in V1.1C6.",
  },
});

const GLOBAL_LINKS = Object.freeze([
  { href: "/", label: "Overview", shortLabel: "O", routeName: "overview" },
  { href: "/projects", label: "Projects", shortLabel: "P", routeName: "projects" },
  { href: "/scans", label: "Scans", shortLabel: "S", routeName: "scans" },
]);

const SCAN_LINKS = Object.freeze([
  { suffix: "", label: "Overview", shortLabel: "OV", routeName: "scan" },
  { suffix: "/findings", label: "Findings", shortLabel: "FI", routeName: "findings" },
  {
    suffix: "/dependencies",
    label: "Dependencies",
    shortLabel: "DE",
    routeName: "dependencies",
  },
  { suffix: "/coverage", label: "Coverage", shortLabel: "CO", routeName: "coverage" },
  { suffix: "/gaps", label: "Gaps", shortLabel: "GA", routeName: "gaps" },
  { suffix: "/report", label: "Report", shortLabel: "RE", routeName: "report" },
]);

const root = document.getElementById("app-root");
const mobileMedia = window.matchMedia("(max-width: 767px)");
let mobileNavigation = null;

function navLink({ href, label, shortLabel, selected }) {
  const link = createElement("a", {
    className: "nav-link",
    attributes: { href },
  });
  if (selected) {
    link.setAttribute("aria-current", "page");
  }
  link.append(
    createElement("span", {
      className: "nav-short",
      textContent: shortLabel,
      attributes: { "aria-hidden": "true" },
    }),
    createElement("span", { className: "nav-label", textContent: label }),
  );
  return link;
}

function buildNavigation(route) {
  const fragment = document.createDocumentFragment();
  const global = createElement("nav", {
    className: "nav-group",
    attributes: { "aria-label": "Primary" },
  });
  for (const item of GLOBAL_LINKS) {
    global.append(navLink({ ...item, selected: route.name === item.routeName }));
  }
  fragment.append(global);

  if (route.runId) {
    fragment.append(createElement("div", { className: "nav-divider" }));
    const context = createElement("section", {
      className: "scan-navigation",
      attributes: { "aria-labelledby": "scan-navigation-label" },
    });
    context.append(
      createElement("p", {
        className: "nav-section-label",
        textContent: "Current scan",
        attributes: { id: "scan-navigation-label" },
      }),
      codeValue(truncateMiddle(route.runId, 18), "nav-run-id"),
    );
    const scan = createElement("nav", {
      className: "nav-group",
      attributes: { "aria-label": "Current scan" },
    });
    for (const item of SCAN_LINKS) {
      scan.append(
        navLink({
          href: `/scans/${route.runId}${item.suffix}`,
          label: item.label,
          shortLabel: item.shortLabel,
          selected: route.name === item.routeName,
        }),
      );
    }
    context.append(scan);
    fragment.append(context);
  }
  return fragment;
}

function breadcrumbItems(route) {
  if (route.name === "overview") {
    return [{ label: "Overview" }];
  }
  if (route.name === "projects") {
    return [{ label: "Projects" }];
  }
  if (route.name === "project") {
    return [{ label: "Projects", href: "/projects" }, { label: "Project" }];
  }
  if (route.name === "scans") {
    return [{ label: "Scans" }];
  }
  const items = [{ label: "Scans", href: "/scans" }];
  if (route.name === "scan") {
    items.push({ label: "Scan" });
  } else {
    items.push({ label: "Scan", href: `/scans/${route.runId}` });
    items.push({ label: ROUTE_SHELLS[route.name].title });
  }
  return items;
}

function renderRouteShell(route, region) {
  const contract = ROUTE_SHELLS[route.name];
  const content = createElement("div", { className: "route-stack" });
  content.append(pageHeader(contract));
  if (route.projectId || route.runId) {
    const identity = createElement("dl", { className: "route-identity" });
    const label = route.projectId ? "Project ID" : "Run ID";
    const value = route.projectId || route.runId;
    identity.append(
      createElement("dt", { textContent: label }),
      createElement("dd", {}, [codeValue(value)]),
    );
    content.append(identity);
  }
  content.append(
    emptyState(
      "Checkpoint shell",
      contract.description,
      "No product data is loaded by this C1 route.",
    ),
  );
  region.replaceChildren(content);
  region.setAttribute("aria-busy", "false");
}

function statusDetails(payload) {
  const details = createElement("details", { className: "system-details" });
  details.append(createElement("summary", { textContent: "System details" }));
  const values = createElement("dl", { className: "system-detail-list" });
  const rows = [
    ["Database reachable", payload.database_reachable ? "Yes" : "No"],
    ["Schema current", payload.schema_at_head ? "Yes" : "No"],
    ["Reason", statusLabel(payload.reason)],
    ["Checked", formatDateTime(payload.checked_at)],
  ];
  for (const [label, value] of rows) {
    values.append(
      createElement("dt", { textContent: label }),
      createElement("dd", { textContent: value }),
    );
  }
  details.append(values);
  return details;
}

function renderSystemStatus(containers, result) {
  const payload = result.payload;
  const ready = payload.status === "ready";
  const label = ready ? "System ready" : "System not ready";
  const tone = ready ? "success" : "failure";
  for (const container of containers) {
    container.replaceChildren(statusIndicator(label, tone));
    if (container.dataset.details === "true") {
      container.append(statusDetails(payload));
    }
  }
}

function renderSystemUnavailable(containers, error) {
  const code = typeof error.code === "string" ? error.code : "API_UNAVAILABLE";
  const message = typeof error.message === "string"
    ? error.message
    : "SecureScan API is unavailable.";
  for (const container of containers) {
    container.replaceChildren(statusIndicator("System unavailable", "failure"));
    if (container.dataset.details === "true") {
      container.append(
        createElement("p", {
          className: "system-error",
          textContent: `${code}: ${message}`,
        }),
      );
    }
  }
}

async function loadSystemStatus(containers) {
  const request = beginRequest();
  for (const container of containers) {
    container.replaceChildren(statusIndicator("Checking system", "neutral"));
  }
  try {
    const result = await getReadiness({ signal: request.signal });
    if (request.isCurrent()) {
      renderSystemStatus(containers, result);
    }
  } catch (error) {
    if (request.isCurrent() && error.name !== "AbortError") {
      renderSystemUnavailable(containers, error);
    }
  } finally {
    request.finish();
  }
}

function focusableElements(container) {
  return Array.from(
    container.querySelectorAll(
      'a[href], button:not([disabled]), details > summary, [tabindex]:not([tabindex="-1"])',
    ),
  ).filter((item) => !item.hidden);
}

function closeMobileNavigation({ restoreFocus = true } = {}) {
  if (!mobileNavigation || !mobileNavigation.open) {
    return;
  }
  const { sidebar, backdrop, main, button, previousFocus } = mobileNavigation;
  mobileNavigation.open = false;
  sidebar.removeAttribute("role");
  sidebar.removeAttribute("aria-modal");
  sidebar.removeAttribute("data-open");
  backdrop.hidden = true;
  main.inert = false;
  button.setAttribute("aria-expanded", "false");
  document.body.classList.remove("navigation-open");
  if (mobileMedia.matches) {
    sidebar.inert = true;
    sidebar.setAttribute("aria-hidden", "true");
  } else {
    sidebar.inert = false;
    sidebar.removeAttribute("aria-hidden");
  }
  if (restoreFocus && previousFocus instanceof HTMLElement && previousFocus.isConnected) {
    previousFocus.focus();
  }
}

function openMobileNavigation() {
  if (!mobileNavigation || mobileNavigation.open || !mobileMedia.matches) {
    return;
  }
  const { sidebar, backdrop, main, button } = mobileNavigation;
  mobileNavigation.open = true;
  mobileNavigation.previousFocus = document.activeElement;
  sidebar.inert = false;
  sidebar.removeAttribute("aria-hidden");
  sidebar.setAttribute("role", "dialog");
  sidebar.setAttribute("aria-modal", "true");
  sidebar.setAttribute("data-open", "true");
  backdrop.hidden = false;
  main.inert = true;
  button.setAttribute("aria-expanded", "true");
  document.body.classList.add("navigation-open");
  const first = focusableElements(sidebar)[0];
  if (first) {
    first.focus();
  }
}

function handleGlobalKeydown(event) {
  if (!mobileNavigation || !mobileNavigation.open) {
    return;
  }
  if (event.key === "Escape") {
    event.preventDefault();
    closeMobileNavigation();
    return;
  }
  if (event.key !== "Tab") {
    return;
  }
  const focusable = focusableElements(mobileNavigation.sidebar);
  if (!focusable.length) {
    event.preventDefault();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function buildShell(route) {
  closeMobileNavigation({ restoreFocus: false });
  const sidebarStatus = createElement("div", {
    className: "sidebar-status",
    dataset: { details: "true" },
  });
  const topbarStatus = createElement("div", {
    className: "topbar-status",
    attributes: { role: "status", "aria-live": "polite" },
  });

  const brand = createElement("a", {
    className: "wordmark",
    attributes: { href: "/", "aria-label": "SecureScan Source overview" },
  }, [
    createElement("span", { className: "wordmark-primary", textContent: "SecureScan" }),
    createElement("span", { className: "wordmark-secondary", textContent: "Source" }),
  ]);
  const sidebar = createElement("aside", {
    className: "sidebar",
    attributes: { id: "application-navigation", "aria-label": "SecureScan navigation" },
  });
  const closeButton = createElement("button", {
    className: "sidebar-close",
    textContent: "Close",
    attributes: { type: "button", "aria-label": "Close navigation" },
  });
  sidebar.append(
    createElement("div", { className: "sidebar-header" }, [brand, closeButton]),
    createElement("div", { className: "sidebar-navigation" }, [buildNavigation(route)]),
    sidebarStatus,
  );

  const menuButton = createElement("button", {
    className: "menu-button",
    textContent: "Menu",
    attributes: {
      type: "button",
      "aria-controls": "application-navigation",
      "aria-expanded": "false",
    },
  });
  const header = createElement("header", { className: "topbar" });
  header.append(
    createElement("div", { className: "topbar-leading" }, [
      menuButton,
      breadcrumb(breadcrumbItems(route)),
    ]),
    topbarStatus,
  );

  const region = createElement("section", {
    className: "route-region",
    attributes: { id: "route-content", "aria-busy": "true" },
  });
  region.append(loadingState("Loading route"));
  const main = createElement("main", {
    className: "main-content",
    attributes: { id: "main-content", tabindex: "-1" },
  }, [header, region]);
  const backdrop = createElement("button", {
    className: "navigation-backdrop",
    textContent: "Close navigation",
    attributes: { type: "button", "aria-label": "Close navigation", hidden: "" },
  });
  const shell = createElement("div", { className: "app-shell" }, [sidebar, main, backdrop]);
  root.replaceChildren(shell);

  mobileNavigation = {
    backdrop,
    button: menuButton,
    main,
    open: false,
    previousFocus: null,
    sidebar,
  };
  if (mobileMedia.matches) {
    sidebar.inert = true;
    sidebar.setAttribute("aria-hidden", "true");
  }
  menuButton.addEventListener("click", openMobileNavigation);
  closeButton.addEventListener("click", () => closeMobileNavigation());
  backdrop.addEventListener("click", () => closeMobileNavigation());

  renderRouteShell(route, region);
  loadSystemStatus([sidebarStatus, topbarStatus]);
  return region;
}

function renderInvalidRoute() {
  beginRoute({ name: "invalid", projectId: null, runId: null });
  closeMobileNavigation({ restoreFocus: false });
  const main = createElement("main", {
    className: "standalone-error",
    attributes: { id: "main-content", tabindex: "-1" },
  });
  main.append(
    pageHeader({
      eyebrow: "Navigation",
      title: "Page not found",
      description: "This path is not an approved SecureScan interface route.",
    }),
    errorState("Route unavailable", "Return to the SecureScan overview.", "INVALID_ROUTE"),
    createElement("a", { className: "text-link", textContent: "Open Overview", attributes: { href: "/" } }),
  );
  root.replaceChildren(main);
}

function renderLocation({ focusHeading = false } = {}) {
  const route = parseRoute(window.location.pathname);
  if (!route) {
    renderInvalidRoute();
    return;
  }
  beginRoute(route);
  buildShell(route);
  if (focusHeading) {
    const heading = document.querySelector("h1");
    if (heading) {
      heading.setAttribute("tabindex", "-1");
      heading.focus();
    }
  }
}

document.addEventListener("keydown", handleGlobalKeydown);
mobileMedia.addEventListener("change", (event) => {
  if (event.matches && mobileNavigation && !mobileNavigation.open) {
    mobileNavigation.sidebar.inert = true;
    mobileNavigation.sidebar.setAttribute("aria-hidden", "true");
  } else if (!event.matches) {
    closeMobileNavigation({ restoreFocus: false });
    if (mobileNavigation) {
      mobileNavigation.sidebar.inert = false;
      mobileNavigation.sidebar.removeAttribute("aria-hidden");
    }
  }
});
installNavigation(() => renderLocation({ focusHeading: true }));
renderLocation();

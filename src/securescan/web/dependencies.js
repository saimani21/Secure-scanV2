"use strict";

import { getDependencies } from "/assets/api.js";
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
  boundedDisplayText,
  dependencyEvaluation,
  packageTypeLabel,
  paginationLabel,
  priorityPresentation,
} from "/assets/format.js";
import { beginRequest, registerRouteCleanup } from "/assets/state.js";

export const DEPENDENCY_PAGE_LIMIT = 50;
export const COMPONENT_REF_PATTERN = /^[0-9a-f]{64}$/;

function isRecord(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function isAbortError(error) {
  return Boolean(error && typeof error === "object" && error.name === "AbortError");
}

function exactString(value, maximum = 520) {
  return typeof value === "string" && value ? boundedDisplayText(value, maximum) : null;
}

function packageName(item) {
  return exactString(item && item.name, 256) || "Package name unavailable";
}

function packageVersion(item) {
  return exactString(item && item.version, 160) || "Version not reported";
}

function countLabel(total) {
  return `${total} ${total === 1 ? "package" : "packages"}`;
}

export function readDependencyUrlState(search) {
  const query = new URLSearchParams(typeof search === "string" ? search : "");
  const rawOffset = query.get("offset");
  const offset = rawOffset && /^\d+$/.test(rawOffset) ? Number(rawOffset) : 0;
  const component = query.get("component");
  return {
    offset: Number.isSafeInteger(offset) && offset >= 0 ? offset : 0,
    component: component && COMPONENT_REF_PATTERN.test(component) ? component : null,
  };
}

export function dependencyQuery(state) {
  const query = new URLSearchParams();
  if (Number.isSafeInteger(state.offset) && state.offset > 0) {
    query.set("offset", String(state.offset));
  }
  if (COMPONENT_REF_PATTERN.test(state.component || "")) {
    query.set("component", state.component);
  }
  const rendered = query.toString();
  return rendered ? `?${rendered}` : "";
}

export function dependencyPresentation(item) {
  const advisories = Array.isArray(item && item.advisories) ? item.advisories.length : 0;
  return dependencyEvaluation(
    item && item.vulnerability_evaluation,
    item && item.known_vulnerability_count,
    advisories,
  );
}

function repositoryLocations(item) {
  if (!Array.isArray(item && item.locations)) return [];
  return item.locations
    .filter((location) => isRecord(location) && location.kind === "REPOSITORY_PATH")
    .map((location) => exactString(location.path, 1100))
    .filter(Boolean);
}

function bdi(value, className = "") {
  return createElement("bdi", { className, textContent: value });
}

function fact(label, content, { code = false, copy = false } = {}) {
  const value = content instanceof Node
    ? content
    : code
    ? codeValue(boundedDisplayText(content, 1100))
    : bdi(boundedDisplayText(content, 1100));
  const values = [value];
  if (copy && typeof content === "string" && content) {
    values.push(copyButton(content, `Copy ${label.toLowerCase()}`));
  }
  return createElement("div", { className: "dependency-fact" }, [
    createElement("dt", { textContent: label }),
    createElement("dd", {}, values),
  ]);
}

function textList(values, className = "technical-code-list") {
  return createElement("ul", { className }, values.map((value) =>
    createElement("li", {}, [bdi(boundedDisplayText(value, 1100))])
  ));
}

function codeList(values) {
  return createElement("ul", { className: "technical-code-list" }, values.map((value) =>
    createElement("li", {}, [codeValue(boundedDisplayText(value, 520))])
  ));
}

function exactStringArray(value, maximum = 520) {
  return Array.isArray(value)
    ? value.map((item) => exactString(item, maximum)).filter(Boolean)
    : [];
}

function otherAliases(advisory) {
  const cve = new Set(exactStringArray(advisory.cve_aliases));
  const ghsa = new Set(exactStringArray(advisory.ghsa_aliases));
  return exactStringArray(advisory.aliases).filter((value) => !cve.has(value) && !ghsa.has(value));
}

function advisoryCard(advisory) {
  const priority = priorityPresentation(advisory && advisory.priority_band);
  const canonical = exactString(advisory && advisory.canonical_advisory_id, 320) ||
    "Advisory identity unavailable";
  const facts = [];
  const cve = exactStringArray(advisory && advisory.cve_aliases);
  const ghsa = exactStringArray(advisory && advisory.ghsa_aliases);
  const other = isRecord(advisory) ? otherAliases(advisory) : [];
  const fixed = exactStringArray(advisory && advisory.fixed_versions);
  if (cve.length) facts.push(fact("CVE aliases", textList(cve)));
  if (ghsa.length) facts.push(fact("GHSA aliases", textList(ghsa)));
  if (other.length) facts.push(fact("Other aliases", textList(other)));
  if (fixed.length) {
    facts.push(fact("Fixed versions reported by advisory", textList(fixed)));
  }
  const technical = [
    fact("Finding ID", exactString(advisory && advisory.finding_id) || "Not provided", {
      code: true,
    }),
  ];
  const records = exactStringArray(advisory && advisory.osv_record_ids);
  if (records.length) technical.push(fact("OSV record IDs", codeList(records)));
  return createElement("article", { className: "dependency-advisory" }, [
    createElement("div", { className: "dependency-advisory-heading" }, [
      createElement("h3", { textContent: canonical }),
      statusIndicator(priority.label, priority.tone),
    ]),
    createElement("p", {
      className: "dependency-priority-label",
      textContent: `SecureScan priority · ${priority.label}`,
    }),
    ...(facts.length ? [createElement("dl", { className: "dependency-facts" }, facts)] : []),
    createElement("details", { className: "dependency-technical" }, [
      createElement("summary", { textContent: "Technical evidence" }),
      createElement("dl", { className: "dependency-facts" }, technical),
    ]),
  ]);
}

function dependencyDetail(item) {
  const presentation = dependencyPresentation(item);
  const purl = exactString(item && item.purl, 1100);
  const locations = repositoryLocations(item);
  const advisories = Array.isArray(item && item.advisories)
    ? item.advisories.filter(isRecord)
    : [];
  const evaluationFacts = [
    fact("Evaluation", presentation.state),
    fact("Known vulnerabilities", presentation.result),
  ];
  if (presentation.observed) {
    evaluationFacts.push(fact("Observed advisories", String(advisories.length)));
  }
  const reason = exactString(item && item.vulnerability_evaluation_reason, 320);
  const technical = [fact("Component reference", item.component_ref, { code: true, copy: true })];
  if (reason) technical.push(fact("Evaluation reason", reason, { code: true }));

  const content = [
    createElement("div", { className: "dependency-detail-status" }, [
      statusIndicator(presentation.result, presentation.tone),
      createElement("span", { className: "dependency-evaluation", textContent: presentation.state }),
    ]),
    createElement("h2", { textContent: packageName(item), attributes: { id: "dependency-detail-title" } }),
    createElement("p", { className: "dependency-detail-version", textContent: packageVersion(item) }),
    createElement("p", { className: "dependency-package-type", textContent: packageTypeLabel(item.package_type) }),
  ];
  const identityFacts = [];
  if (purl) identityFacts.push(fact("PURL", purl, { code: true, copy: true }));
  identityFacts.push(fact(
    "Observed in",
    locations.length ? textList(locations, "dependency-location-list") : "Location unavailable",
  ));
  content.push(createElement("dl", { className: "dependency-facts" }, identityFacts));
  content.push(createElement("section", { className: "dependency-evaluation-panel" }, [
    createElement("h3", { textContent: "Vulnerability evaluation" }),
    createElement("dl", { className: "dependency-facts" }, evaluationFacts),
  ]));
  content.push(createElement("section", { className: "dependency-advisories" }, [
    createElement("h3", { className: "section-label", textContent: "Advisories" }),
    ...(advisories.length
      ? advisories.map(advisoryCard)
      : [emptyState("No observed advisories", "No canonical advisory group is present for this package result.")]),
  ]));
  content.push(createElement("details", { className: "dependency-technical" }, [
    createElement("summary", { textContent: "Package technical evidence" }),
    createElement("dl", { className: "dependency-facts" }, technical),
  ]));
  return createElement("article", {
    className: "dependency-detail",
    attributes: { "aria-labelledby": "dependency-detail-title" },
  }, content);
}

function dependencyRow(item, selected, href, onSelect) {
  const presentation = dependencyPresentation(item);
  const link = createElement("a", {
    className: "dependency-row-link",
    dataset: { componentRef: item.component_ref },
    attributes: {
      href,
      "aria-label": `Open package ${packageName(item)} ${packageVersion(item)}, ${presentation.result}`,
    },
  }, [
    createElement("div", { className: "dependency-row-heading" }, [
      createElement("h3", { textContent: packageName(item) }),
      createElement("span", { className: "dependency-row-version", textContent: packageVersion(item) }),
    ]),
    createElement("span", { className: "dependency-package-type", textContent: packageTypeLabel(item.package_type) }),
    statusIndicator(presentation.result, presentation.tone),
    ...(presentation.observed
      ? [createElement("span", { className: "dependency-observed", textContent: presentation.observed })]
      : []),
  ]);
  if (selected) link.setAttribute("aria-current", "true");
  link.addEventListener("click", (event) => {
    if (
      event.defaultPrevented ||
      (event.button !== undefined && event.button !== 0) ||
      event.metaKey || event.ctrlKey || event.shiftKey || event.altKey
    ) return;
    event.preventDefault();
    onSelect();
  });
  return createElement("li", { className: "dependency-row" }, [link]);
}

function searchCandidates(item) {
  const values = [
    packageName(item), packageVersion(item), packageTypeLabel(item && item.package_type),
    exactString(item && item.purl, 1100) || "", ...repositoryLocations(item),
  ];
  if (Array.isArray(item && item.advisories)) {
    for (const advisory of item.advisories) {
      if (isRecord(advisory)) {
        values.push(exactString(advisory.canonical_advisory_id, 320) || "");
      }
    }
  }
  return values.join("\n").toLocaleLowerCase();
}

function noPackageSelected() {
  return emptyState("Select a package", "Choose a package to inspect dependency evaluation and advisory evidence.");
}

function missingSelectedPackage() {
  return errorState(
    "Package not present in this page",
    "This component reference is not in the currently loaded result page. Change pages or clear the selection.",
    "PACKAGE_NOT_IN_PAGE",
  );
}

function fatalDependencyError(error, runId) {
  if (error && error.status === 404) {
    return ["Scan not found", "This scan does not exist or is no longer available.", "SCAN_NOT_FOUND"];
  }
  if (error && error.status === 409) {
    const code = ["SCAN_NOT_PUBLISHED", "PRODUCT_CORE_NOT_READY"].includes(error.code)
      ? error.code : "DEPENDENCIES_NOT_READY";
    return [
      "Dependencies not ready",
      "Verified dependency data is not available for this scan yet.",
      code,
      `/scans/${runId}`,
    ];
  }
  return [
    "Dependency data unavailable",
    "SecureScan could not reconstruct the verified dependency result. The system did not substitute an empty result.",
    "QUERY_UNAVAILABLE",
  ];
}

export function renderDependenciesPage({
  region,
  route,
  services = { getDependencies },
  navigation = {
    search: () => window.location.search,
    push: (url) => window.history.pushState({ securescanRoute: "dependencies" }, "", url),
  },
  responsive = {
    desktop: window.matchMedia("(min-width: 1200px)"),
    mobile: window.matchMedia("(max-width: 767px)"),
  },
}) {
  const runId = route.runId;
  const state = readDependencyUrlState(navigation.search());
  const countRegion = createElement("p", {
    className: "dependencies-total",
    textContent: "Loading packages",
    attributes: { role: "status", "aria-live": "polite" },
  });
  const updateWarning = createElement("div", { className: "dependencies-update-warning", attributes: { role: "status" } });
  const controlsRegion = createElement("div", { className: "dependencies-controls" });
  const listRegion = createElement("div", {
    className: "dependency-list-region",
    attributes: { "aria-busy": "true" },
  }, [loadingState("Loading packages")]);
  const detailRegion = createElement("div", { className: "dependency-detail-region", attributes: { "aria-label": "Dependency detail" } }, [noPackageSelected()]);
  const mobileBack = createElement("button", { className: "button button-secondary dependency-mobile-back", textContent: "Back to dependencies", attributes: { type: "button" } });
  const mobileDetailRegion = createElement("div", { className: "dependency-mobile-detail", attributes: { "aria-label": "Dependency detail" } });
  const dialogClose = createElement("button", { className: "button button-secondary", textContent: "Close", attributes: { type: "button", "aria-label": "Close dependency detail" } });
  const dialogContent = createElement("div", { className: "dependency-drawer-content" });
  const detailDialog = createElement("dialog", {
    className: "dependency-detail-drawer",
    attributes: { role: "dialog", "aria-modal": "true", "aria-labelledby": "dependency-drawer-title" },
  }, [
    createElement("header", { className: "dependency-drawer-header" }, [
      createElement("h2", { textContent: "Dependency detail", attributes: { id: "dependency-drawer-title" } }),
      dialogClose,
    ]),
    dialogContent,
  ]);
  const workspace = createElement("div", { className: "dependencies-workspace" }, [
    createElement("div", { className: "dependency-list-pane" }, [controlsRegion, listRegion]),
    detailRegion,
    createElement("div", { className: "dependency-mobile-detail-shell" }, [mobileBack, mobileDetailRegion]),
  ]);
  region.replaceChildren(createElement("div", { className: "route-stack dependencies-page" }, [
    createElement("header", { className: "page-header dependencies-header" }, [
      createElement("p", { className: "eyebrow", textContent: "Dependencies" }),
      createElement("h1", { textContent: "Package inventory" }),
      createElement("p", { className: "page-description", textContent: "Package inventory and dependency vulnerability evaluation." }),
      countRegion,
      updateWarning,
    ]),
    workspace,
    detailDialog,
  ]));
  region.setAttribute("aria-busy", "false");

  let disposed = false;
  let page = null;
  let searchTerm = "";
  let generation = 0;
  let listRequest = null;
  let suppressDialogClose = false;
  const removeResponsiveListeners = [];
  let unregisterCleanup = () => {};

  function dispose() {
    if (disposed) return;
    disposed = true;
    if (listRequest) listRequest.cancel();
    for (const remove of removeResponsiveListeners) remove();
    if (detailDialog.open) {
      suppressDialogClose = true;
      detailDialog.close();
    }
    unregisterCleanup();
  }
  unregisterCleanup = registerRouteCleanup(dispose);

  function currentUrl() {
    return `/scans/${runId}/dependencies${dependencyQuery(state)}`;
  }

  function writeUrl() {
    navigation.push(currentUrl());
  }

  function selectedPackage() {
    return page && state.component
      ? page.items.find((item) => item.component_ref === state.component) || null
      : null;
  }

  function renderDetailTarget() {
    const selected = selectedPackage();
    const content = state.component
      ? selected ? dependencyDetail(selected) : missingSelectedPackage()
      : noPackageSelected();
    workspace.className = `dependencies-workspace${state.component ? " dependencies-has-selection" : ""}`;
    if (responsive.desktop.matches) {
      if (detailDialog.open) { suppressDialogClose = true; detailDialog.close(); }
      dialogContent.replaceChildren();
      mobileDetailRegion.replaceChildren();
      detailRegion.replaceChildren(content);
      return;
    }
    if (responsive.mobile.matches) {
      if (detailDialog.open) { suppressDialogClose = true; detailDialog.close(); }
      detailRegion.replaceChildren();
      dialogContent.replaceChildren();
      mobileDetailRegion.replaceChildren(content);
      return;
    }
    detailRegion.replaceChildren();
    mobileDetailRegion.replaceChildren();
    dialogContent.replaceChildren(content);
    if (state.component && !detailDialog.open) {
      detailDialog.showModal();
      dialogClose.focus();
    } else if (!state.component && detailDialog.open) {
      suppressDialogClose = true;
      detailDialog.close();
    }
  }

  function selectPackage(componentRef) {
    if (!COMPONENT_REF_PATTERN.test(componentRef || "")) return;
    state.component = componentRef;
    writeUrl();
    renderList();
    renderDetailTarget();
  }

  function clearSelection({ restoreFocus = true } = {}) {
    const restoreId = state.component;
    state.component = null;
    writeUrl();
    renderList();
    renderDetailTarget();
    const restore = restoreId
      ? listRegion.querySelector(`[data-component-ref="${restoreId}"]`)
      : null;
    if (restoreFocus && restore instanceof HTMLElement && restore.isConnected) restore.focus();
  }

  mobileBack.addEventListener("click", () => clearSelection());
  dialogClose.addEventListener("click", () => {
    suppressDialogClose = true;
    detailDialog.close();
    clearSelection();
  });
  detailDialog.addEventListener("close", () => {
    if (suppressDialogClose) { suppressDialogClose = false; return; }
    if (state.component) clearSelection();
  });

  function renderControls() {
    const id = "dependency-current-page-search";
    const search = createElement("input", {
      className: "dependency-search-input",
      attributes: { id, type: "search", placeholder: "Name, version, ecosystem, PURL, location, or advisory", autocomplete: "off" },
    });
    search.value = searchTerm;
    search.addEventListener("input", () => { searchTerm = search.value; renderList(); });
    controlsRegion.replaceChildren(createElement("div", { className: "dependency-page-search" }, [
      createElement("label", { textContent: "Search this page", attributes: { for: id } }),
      search,
      createElement("span", { className: "dependency-search-scope", textContent: "Filters only the currently loaded page." }),
    ]));
  }

  function renderList() {
    if (!page) return;
    const needle = searchTerm.trim().toLocaleLowerCase();
    const visible = needle ? page.items.filter((item) => searchCandidates(item).includes(needle)) : page.items;
    const content = [];
    if (!page.total) {
      content.push(emptyState(
        "No packages",
        "No package inventory was published for this scan.",
        "Review Coverage to understand whether package analysis applied.",
      ));
    } else if (!visible.length) {
      content.push(emptyState("No matches on this page", "No loaded package matches the current-page search.", `${page.items.length} packages are loaded on this page.`));
    } else {
      content.push(
        createElement("p", { className: "dependency-page-count", textContent: needle ? `${visible.length} ${visible.length === 1 ? "match" : "matches"} on this page · ${countLabel(page.total)} total` : `${page.items.length} loaded on this page` }),
        createElement("ol", { className: "dependency-list", attributes: { "aria-label": "Packages" } }, visible.map((item) => dependencyRow(
          item,
          item.component_ref === state.component,
          `/scans/${runId}/dependencies${dependencyQuery({ ...state, component: item.component_ref })}`,
          () => selectPackage(item.component_ref),
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
    state.component = null;
    writeUrl();
    void loadDependencies();
  }

  async function loadDependencies() {
    const currentGeneration = ++generation;
    const hadPage = page !== null;
    if (listRequest) listRequest.cancel();
    const request = beginRequest();
    listRequest = request;
    listRegion.setAttribute("aria-busy", "true");
    updateWarning.replaceChildren();
    if (!hadPage) listRegion.replaceChildren(loadingState("Loading packages"));
    try {
      const result = await services.getDependencies(runId, {
        limit: DEPENDENCY_PAGE_LIMIT,
        offset: state.offset,
        signal: request.signal,
      });
      if (!request.isCurrent() || disposed || currentGeneration !== generation) return;
      page = result;
      countRegion.textContent = countLabel(page.total);
      renderControls();
      renderList();
      renderDetailTarget();
    } catch (error) {
      if (isAbortError(error) || !request.isCurrent() || disposed) return;
      if (hadPage) {
        updateWarning.replaceChildren(createElement("p", { textContent: "Dependency update delayed. The previous result page remains displayed." }));
        listRegion.setAttribute("aria-busy", "false");
      } else {
        const [title, message, code, overview] = fatalDependencyError(error, runId);
        dispose();
        const content = [
          createElement("header", { className: "page-header" }, [
            createElement("p", { className: "eyebrow", textContent: "Dependencies" }),
            createElement("h1", { textContent: title }),
            createElement("p", { className: "page-description", textContent: message }),
          ]),
          errorState(title, message, code),
        ];
        if (overview) content.push(createElement("a", { className: "text-link", textContent: "Open Scan Overview", attributes: { href: overview } }));
        region.replaceChildren(createElement("div", { className: "route-stack" }, content));
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
  const settled = loadDependencies();
  return { dispose, settled };
}

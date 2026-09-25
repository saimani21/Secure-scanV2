"use strict";

import { getGaps } from "/assets/api.js";
import { codeValue, createElement, emptyState, errorState, loadingState, paginationControls } from "/assets/components.js";
import { authorityLabel, boundedDisplayText, capabilityLabel, paginationLabel } from "/assets/format.js";
import { beginRequest } from "/assets/state.js";

const GAP_PAGE_LIMIT = 50;
const AUTHORITY_CAPABILITIES = Object.freeze({
  "semgrep-ce": "python_sast",
  gitleaks: "secret_detection",
  syft: "package_inventory",
  "osv.dev": "dependency_advisory_matching",
  checkov: "configuration_security",
});

function isRecord(value) { return Boolean(value && typeof value === "object" && !Array.isArray(value)); }
function safe(value, maximum = 1100) { return typeof value === "string" && value ? boundedDisplayText(value, maximum) : null; }
function gapScope(scope) {
  if (!isRecord(scope)) return { primary: "Scope unavailable", detail: [] };
  const primary = safe(scope.value) || "Scope unavailable";
  const detail = [];
  if (safe(scope.kind, 128)) detail.push(["Scope kind", scope.kind]);
  if (safe(scope.framework, 128)) detail.push(["Framework", scope.framework]);
  if (safe(scope.component_ref, 128)) detail.push(["Component reference", scope.component_ref]);
  return { primary, detail };
}

function gapRow(item) {
  const scope = gapScope(item && item.scope);
  const message = safe(item && item.message, 520);
  const capability = AUTHORITY_CAPABILITIES[item && item.authority];
  const details = [
    createElement("p", {}, [createElement("span", { textContent: "Gap ID · " }), codeValue(safe(item && item.gap_id, 128) || "Not provided")]),
    ...scope.detail.map(([label, value]) => createElement("p", {}, [createElement("span", { textContent: `${label} · ` }), codeValue(value)])),
  ];
  return createElement("li", { className: "gap-row" }, [
    createElement("article", {}, [
      createElement("header", { className: "gap-heading" }, [
        createElement("div", {}, [
          createElement("p", { className: "eyebrow", textContent: "Partial coverage" }),
          createElement("h2", { textContent: capabilityLabel(capability) }),
          createElement("p", { textContent: authorityLabel(item && item.authority) }),
        ]),
        codeValue(safe(item && item.code, 256) || "REASON_UNAVAILABLE"),
      ]),
      createElement("bdi", { className: "gap-scope", textContent: scope.primary }),
      ...(message ? [createElement("p", { className: "gap-message", textContent: message })] : []),
      createElement("details", { className: "gap-technical" }, [createElement("summary", { textContent: "Technical scope" }), ...details]),
    ]),
  ]);
}

function fatal(error, runId) {
  if (error && error.status === 404) return ["Scan not found", "This scan does not exist or is no longer available.", "SCAN_NOT_FOUND"];
  if (error && error.status === 409) return ["Gaps not ready", "Published analysis gaps are not available for this scan yet.", error.code === "SCAN_NOT_PUBLISHED" ? error.code : "GAPS_NOT_READY", `/scans/${runId}`];
  return ["Gap data unavailable", "SecureScan could not reconstruct the published analysis gaps. The system did not substitute an empty result.", "QUERY_UNAVAILABLE"];
}

export function renderGapsPage({ region, route, services = { getGaps }, navigation = { search: () => window.location.search, push: (url) => window.history.pushState({ securescanRoute: "gaps" }, "", url) } }) {
  const rawOffset = new URLSearchParams(navigation.search()).get("offset");
  let offset = rawOffset && /^\d+$/.test(rawOffset) && Number.isSafeInteger(Number(rawOffset)) ? Number(rawOffset) : 0;
  let currentRequest = null;
  let disposed = false;
  region.replaceChildren(createElement("div", { className: "route-stack" }, [loadingState("Loading analysis gaps")]));
  region.setAttribute("aria-busy", "true");

  function changePage(nextOffset) {
    offset = nextOffset;
    navigation.push(`/scans/${route.runId}/gaps${offset ? `?offset=${offset}` : ""}`);
    void load();
  }

  async function load() {
    if (currentRequest) currentRequest.cancel();
    const request = beginRequest(); currentRequest = request;
    try {
      const page = await services.getGaps(route.runId, { limit: GAP_PAGE_LIMIT, offset, signal: request.signal });
      if (!request.isCurrent() || disposed) return;
      const body = [
        createElement("header", { className: "page-header" }, [
          createElement("p", { className: "eyebrow", textContent: "Gaps" }),
          createElement("h1", { textContent: "Analysis gaps" }),
          createElement("p", { className: "page-description", textContent: "Published scope that SecureScan could not analyze reliably." }),
          createElement("p", { className: "gaps-total", textContent: `${page.total} ${page.total === 1 ? "gap" : "gaps"}` }),
        ]),
      ];
      if (!page.total) body.push(emptyState("No published gaps", "SecureScan did not publish an analysis gap for this scan.", "Review Coverage for authoritative capability results."));
      else body.push(createElement("ol", { className: "gap-list" }, page.items.map(gapRow)));
      if (page.total > 0) body.push(paginationControls({ ...page, label: paginationLabel(page) }, () => changePage(Math.max(0, offset - page.limit)), () => changePage(offset + page.limit)));
      region.replaceChildren(createElement("div", { className: "route-stack gaps-page" }, body));
    } catch (error) {
      if (!request.isCurrent() || disposed || (error && error.name === "AbortError")) return;
      const [title, message, code, overview] = fatal(error, route.runId);
      const body = [errorState(title, message, code)];
      if (overview) body.push(createElement("a", { className: "text-link", textContent: "Open Scan Overview", attributes: { href: overview } }));
      region.replaceChildren(createElement("div", { className: "route-stack gaps-page" }, body));
    } finally { request.finish(); if (currentRequest === request) currentRequest = null; region.setAttribute("aria-busy", "false"); }
  }
  const settled = load();
  return { dispose() { disposed = true; if (currentRequest) currentRequest.cancel(); }, settled };
}

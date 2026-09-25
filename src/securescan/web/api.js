"use strict";

import { isCanonicalUuid } from "/assets/router.js";

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export function encodePathSegment(value) {
  return encodeURIComponent(String(value));
}

function pageQuery(limit, offset) {
  if (
    !Number.isInteger(limit) ||
    limit < 1 ||
    limit > 200 ||
    !Number.isInteger(offset) ||
    offset < 0
  ) {
    throw new TypeError("SecureScan pagination must use a valid limit and offset.");
  }
  return new URLSearchParams({ limit: String(limit), offset: String(offset) }).toString();
}

function optionalExactFilter(query, name, value, allowed) {
  if (value === null || value === undefined || value === "") {
    return;
  }
  if (typeof value !== "string" || !allowed.has(value)) {
    throw new TypeError(`SecureScan ${name} filter is invalid.`);
  }
  query.set(name, value);
}

function uuidSegment(value, label) {
  if (!isCanonicalUuid(value)) {
    throw new TypeError(`${label} must be a canonical UUID.`);
  }
  return encodePathSegment(value);
}

function validatedPage(payload, status) {
  if (
    !Array.isArray(payload.items) ||
    !Number.isInteger(payload.total) ||
    payload.total < 0 ||
    !Number.isInteger(payload.limit) ||
    payload.limit < 1 ||
    !Number.isInteger(payload.offset) ||
    payload.offset < 0
  ) {
    throw new ApiError(status, "INVALID_RESPONSE", "SecureScan returned an invalid response.");
  }
  return payload;
}

function normalizedError(response, payload) {
  const detail = payload && typeof payload.detail === "object" ? payload.detail : null;
  const code = detail && typeof detail.code === "string"
    ? detail.code
    : `HTTP_${response.status}`;
  const message = detail && typeof detail.message === "string"
    ? detail.message
    : "SecureScan request failed.";
  return new ApiError(response.status, code, message);
}

export async function getJson(path, { signal, acceptedStatuses = [] } = {}) {
  if (
    typeof path !== "string" ||
    !path.startsWith("/") ||
    path.startsWith("//") ||
    path.includes("\\")
  ) {
    throw new TypeError("SecureScan API paths must be same-origin absolute paths.");
  }
  const url = new URL(path, window.location.origin);
  if (url.origin !== window.location.origin) {
    throw new TypeError("SecureScan API paths must be same-origin absolute paths.");
  }
  let response;
  try {
    response = await fetch(`${url.pathname}${url.search}`, {
      method: "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    throw new ApiError(0, "API_UNAVAILABLE", "SecureScan API is unavailable.");
  }

  let payload;
  try {
    payload = await response.json();
  } catch (_error) {
    throw new ApiError(response.status, "INVALID_RESPONSE", "SecureScan returned an invalid response.");
  }
  if (!response.ok && !acceptedStatuses.includes(response.status)) {
    throw normalizedError(response, payload);
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ApiError(response.status, "INVALID_RESPONSE", "SecureScan returned an invalid response.");
  }
  return { payload, status: response.status };
}

export function getReadiness({ signal } = {}) {
  return getJson("/health/ready", { signal, acceptedStatuses: [503] });
}

export async function getProjects({ limit = 50, offset = 0, signal } = {}) {
  const result = await getJson(`/v1/projects?${pageQuery(limit, offset)}`, { signal });
  return validatedPage(result.payload, result.status);
}

export async function getProject(projectId, { signal } = {}) {
  const segment = uuidSegment(projectId, "Project ID");
  const result = await getJson(`/v1/projects/${segment}`, { signal });
  return result.payload;
}

export async function getProjectScans(
  projectId,
  { limit = 50, offset = 0, signal } = {},
) {
  const segment = uuidSegment(projectId, "Project ID");
  const result = await getJson(
    `/v1/projects/${segment}/scans?${pageQuery(limit, offset)}`,
    { signal },
  );
  return validatedPage(result.payload, result.status);
}

export async function getScans({ limit = 50, offset = 0, signal } = {}) {
  const result = await getJson(`/v1/scans?${pageQuery(limit, offset)}`, { signal });
  return validatedPage(result.payload, result.status);
}

export async function getScanSummary(runId, { signal } = {}) {
  const segment = uuidSegment(runId, "Run ID");
  const result = await getJson(`/v1/scans/${segment}`, { signal });
  return result.payload;
}

export async function getScanStages(runId, { signal } = {}) {
  const segment = uuidSegment(runId, "Run ID");
  const result = await getJson(`/v1/scans/${segment}/stages`, { signal });
  return result.payload;
}

export async function getFindings(
  runId,
  {
    authority = null,
    category = null,
    priority = null,
    lifecycleState = null,
    limit = 50,
    offset = 0,
    signal,
  } = {},
) {
  const segment = uuidSegment(runId, "Run ID");
  const query = new URLSearchParams(pageQuery(limit, offset));
  optionalExactFilter(
    query,
    "authority",
    authority,
    new Set(["semgrep-ce", "gitleaks", "osv.dev", "checkov"]),
  );
  optionalExactFilter(
    query,
    "category",
    category,
    new Set([
      "CODE_SECURITY",
      "SECRET_EXPOSURE",
      "DEPENDENCY_VULNERABILITY",
      "CONFIGURATION_SECURITY",
    ]),
  );
  optionalExactFilter(
    query,
    "priority",
    priority,
    new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRANKED"]),
  );
  optionalExactFilter(
    query,
    "lifecycle_state",
    lifecycleState,
    new Set(["NEW", "EXISTING", "RESOLVED", "REOPENED"]),
  );
  const result = await getJson(`/v1/scans/${segment}/findings?${query.toString()}`, {
    signal,
  });
  return validatedPage(result.payload, result.status);
}

export async function getScanReport(runId, { signal } = {}) {
  const segment = uuidSegment(runId, "Run ID");
  const result = await getJson(`/v1/scans/${segment}/report`, { signal });
  return result.payload;
}

export async function getDependencies(
  runId,
  { limit = 50, offset = 0, signal } = {},
) {
  const segment = uuidSegment(runId, "Run ID");
  const result = await getJson(
    `/v1/scans/${segment}/dependencies?${pageQuery(limit, offset)}`,
    { signal },
  );
  return validatedPage(result.payload, result.status);
}

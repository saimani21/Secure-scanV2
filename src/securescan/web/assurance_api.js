"use strict";

import { ApiError, getJson, getScanSummary } from "/assets/api.js";
import { isCanonicalUuid } from "/assets/router.js";

export async function runScope(runId, { signal } = {}) {
  if (!isCanonicalUuid(runId)) throw new TypeError("A canonical run ID is required.");
  const summary = await getScanSummary(runId, { signal });
  if (!summary || summary.run_id !== runId ||
      !isCanonicalUuid(summary.project_id) || !isCanonicalUuid(summary.lineage_id)) {
    throw new ApiError(503, "INVALID_RUN_SCOPE", "Run scope is unavailable.");
  }
  return { projectId: summary.project_id, lineageId: summary.lineage_id, runId, summary };
}

function root(scope) {
  if (!scope || !isCanonicalUuid(scope.projectId) || !isCanonicalUuid(scope.lineageId) ||
      !isCanonicalUuid(scope.runId)) throw new TypeError("Invalid server-known run scope.");
  return `/v1/projects/${scope.projectId}/lineages/${scope.lineageId}`;
}

async function mutate(path, method, body, signal) {
  if (!path.startsWith("/v1/projects/") || path.includes("\\") ||
      !["PUT", "POST"].includes(method)) throw new TypeError("Invalid assurance mutation target.");
  let response;
  try {
    response = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "API_UNAVAILABLE", "SecureScan API is unavailable.");
  }
  let payload;
  try {
    payload = await response.json();
  } catch (_error) {
    throw new ApiError(response.status, "INVALID_RESPONSE", "SecureScan returned an invalid response.");
  }
  if (!response.ok) {
    const detail = payload && typeof payload.detail === "object" ? payload.detail : null;
    throw new ApiError(response.status,
      detail && typeof detail.code === "string" ? detail.code : `HTTP_${response.status}`,
      detail && typeof detail.message === "string" ? detail.message : "Assurance operation failed.");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ApiError(response.status, "INVALID_RESPONSE", "SecureScan returned an invalid response.");
  }
  return payload;
}

export async function getBaseline(scope, { signal } = {}) {
  return (await getJson(`${root(scope)}/baseline`, { signal })).payload;
}

export async function getBaselineHistory(scope, { signal } = {}) {
  return (await getJson(`${root(scope)}/baseline/history?limit=20&offset=0`, { signal })).payload;
}

export function promoteBaseline(scope, expectedRevision, { signal } = {}) {
  if (!Number.isInteger(expectedRevision) || expectedRevision < 0) throw new TypeError("Invalid baseline revision.");
  return mutate(`${root(scope)}/baseline`, "PUT", {
    run_id: scope.runId,
    expected_revision: expectedRevision,
  }, signal);
}

export async function getSecurityDelta(scope, { signal } = {}) {
  return (await getJson(`${root(scope)}/runs/${scope.runId}/security-delta`, { signal })).payload;
}

export async function getTrustedPolicy(scope, { signal } = {}) {
  return (await getJson(`${root(scope)}/policy`, { signal })).payload;
}

export function evaluatePolicy(scope, { signal } = {}) {
  return mutate(`${root(scope)}/runs/${scope.runId}/policy-evaluations`, "POST", {}, signal);
}

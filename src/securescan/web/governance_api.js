"use strict";

import { ApiError, getJson } from "/assets/api.js";
import { isCanonicalUuid } from "/assets/router.js";

function findingPath(projectId, lineageId, findingId) {
  if (!isCanonicalUuid(projectId) || !isCanonicalUuid(lineageId) ||
      typeof findingId !== "string" || !/^[0-9a-f]{64}$/.test(findingId)) {
    throw new TypeError("A server-known project, lineage and finding are required.");
  }
  return `/v1/projects/${projectId}/lineages/${lineageId}/findings/${findingId}`;
}

async function writeJson(path, method, body, signal) {
  if (!path.startsWith("/v1/projects/") || path.includes("\\") ||
      !["PUT", "POST"].includes(method)) {
    throw new TypeError("Invalid governance mutation target.");
  }
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
    throw new ApiError(
      response.status,
      detail && typeof detail.code === "string" ? detail.code : `HTTP_${response.status}`,
      detail && typeof detail.message === "string" ? detail.message : "Governance operation failed.",
    );
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ApiError(response.status, "INVALID_RESPONSE", "SecureScan returned an invalid response.");
  }
  return payload;
}

export async function getFindingGovernance(projectId, lineageId, findingId, { signal } = {}) {
  const result = await getJson(`${findingPath(projectId, lineageId, findingId)}/governance`, { signal });
  return result.payload;
}

export async function getFindingSuppression(projectId, lineageId, findingId, { signal } = {}) {
  const result = await getJson(`${findingPath(projectId, lineageId, findingId)}/suppression`, { signal });
  return result.payload;
}

export async function getEffectiveGovernance(projectId, lineageId, findingId, { signal } = {}) {
  const result = await getJson(`${findingPath(projectId, lineageId, findingId)}/effective-governance`, { signal });
  return result.payload;
}

export function putFindingGovernance(projectId, lineageId, findingId, body, { signal } = {}) {
  return writeJson(`${findingPath(projectId, lineageId, findingId)}/governance`, "PUT", body, signal);
}

export function putFindingSuppression(projectId, lineageId, findingId, body, { signal } = {}) {
  return writeJson(`${findingPath(projectId, lineageId, findingId)}/suppression`, "PUT", body, signal);
}

export function revokeFindingSuppression(projectId, lineageId, findingId, expectedRevision, { signal } = {}) {
  return writeJson(
    `${findingPath(projectId, lineageId, findingId)}/suppression/revoke`,
    "POST",
    { expected_revision: expectedRevision },
    signal,
  );
}

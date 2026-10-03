"use strict";

import { ApiError, getJson } from "/assets/api.js";
import { encodePathSegment } from "/assets/api.js";
import { isCanonicalUuid } from "/assets/router.js";

const SHA256 = /^[0-9a-f]{64}$/;

function query(scope) {
  if (!scope || !isCanonicalUuid(scope.projectId) || !isCanonicalUuid(scope.lineageId) ||
      !isCanonicalUuid(scope.runId) || !SHA256.test(scope.bundleId || "") ||
      !SHA256.test(scope.proofId || "")) {
    throw new TypeError("Invalid V1.5 assurance scope.");
  }
  return new URLSearchParams({
    project_id: scope.projectId,
    lineage_id: scope.lineageId,
    bundle_id: scope.bundleId,
    proof_id: scope.proofId,
  });
}

export async function getV15Assurance(scope, { signal } = {}) {
  const result = await getJson(
    `/v1/assurance/runs/${encodePathSegment(scope.runId)}?${query(scope)}`,
    { signal },
  );
  return result.payload;
}

export async function getFindingKnowledgeCard(scope, findingId, { signal } = {}) {
  if (!SHA256.test(findingId || "")) throw new TypeError("Invalid finding ID.");
  const result = await getJson(
    `/v1/assurance/runs/${encodePathSegment(scope.runId)}/findings/${findingId}?${query(scope)}`,
    { signal },
  );
  return result.payload;
}

export async function askAssistant(scope, body, { signal } = {}) {
  const path = `/v1/assurance/runs/${encodePathSegment(scope.runId)}/assistant`;
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({
        project_id: scope.projectId,
        lineage_id: scope.lineageId,
        bundle_id: scope.bundleId,
        proof_id: scope.proofId,
        ...body,
      }),
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "AI_UNAVAILABLE", "AI Assistant is unavailable.");
  }
  let payload;
  try { payload = await response.json(); } catch (_error) {
    throw new ApiError(response.status, "INVALID_RESPONSE", "AI Assistant returned invalid data.");
  }
  if (!response.ok) throw new ApiError(response.status, "AI_UNAVAILABLE", "AI Assistant is not configured.");
  return payload;
}

export function v15Scope(base, search = globalThis.window?.location?.search || "") {
  const values = new URLSearchParams(search);
  const bundleId = values.get("bundle");
  const proofId = values.get("proof");
  if (!SHA256.test(bundleId || "") || !SHA256.test(proofId || "")) return null;
  return { ...base, bundleId, proofId };
}

"use strict";

import { encodePathSegment, getJson } from "/assets/api.js";
import { isCanonicalUuid } from "/assets/router.js";

function uuid(value, label) {
  if (!isCanonicalUuid(value)) throw new TypeError(`${label} must be a canonical UUID.`);
  return encodePathSegment(value);
}

export async function getFindingGuidance(
  projectId, lineageId, runId, findingId, { signal } = {},
) {
  const project = uuid(projectId, "Project ID");
  const lineage = uuid(lineageId, "Lineage ID");
  const run = uuid(runId, "Run ID");
  if (typeof findingId !== "string" || !/^[0-9a-f]{64}$/.test(findingId)) {
    throw new TypeError("Finding ID must be 64 lowercase hex characters.");
  }
  const result = await getJson(
    `/v1/projects/${project}/lineages/${lineage}/runs/${run}/findings/${findingId}/guidance`,
    { signal },
  );
  return result.payload;
}

export async function getRunProductFindings(
  runId, { authority = null, category = null, priority = null, lifecycleState = null,
    limit = 50, offset = 0, signal } = {},
) {
  const run = uuid(runId, "Run ID");
  if (!Number.isInteger(limit) || limit < 1 || limit > 200 ||
      !Number.isInteger(offset) || offset < 0) {
    throw new TypeError("Invalid findings pagination.");
  }
  const scopeResult = await getJson(`/v1/scans/${run}`, { signal });
  const scope = scopeResult.payload;
  if (scope.run_id !== runId) throw new TypeError("Run scope did not match.");
  const project = uuid(scope.project_id, "Project ID");
  const lineage = uuid(scope.lineage_id, "Lineage ID");
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  for (const [name, value] of Object.entries({
    authority, category, priority, lifecycle_state: lifecycleState,
  })) {
    if (value !== null && value !== undefined && value !== "") query.set(name, value);
  }
  const result = await getJson(
    `/v1/projects/${project}/lineages/${lineage}/runs/${run}/findings?${query}`,
    { signal },
  );
  if (!Array.isArray(result.payload.items) || !Number.isInteger(result.payload.total)) {
    throw new TypeError("Invalid product findings response.");
  }
  return result.payload;
}

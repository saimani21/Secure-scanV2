"use strict";

import { ApiError } from "/assets/api.js";
import { isCanonicalUuid } from "/assets/router.js";

export async function createProject(name, { signal } = {}) {
  if (typeof name !== "string" || name !== name.trim() || !name) {
    throw new TypeError("A non-empty project name is required.");
  }
  let response;
  try {
    response = await fetch("/v1/projects", {
      method: "POST",
      credentials: "same-origin",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
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
      detail && typeof detail.message === "string" ? detail.message : "Project creation failed.",
    );
  }
  if (!payload || !isCanonicalUuid(payload.project_id) || payload.name !== name) {
    throw new ApiError(response.status, "INVALID_RESPONSE", "SecureScan returned an invalid project.");
  }
  return payload;
}

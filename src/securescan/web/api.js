"use strict";

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

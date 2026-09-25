"use strict";

export function formatDateTime(value) {
  if (typeof value !== "string" || !value) {
    return "Not provided";
  }
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) {
    return "Invalid timestamp";
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function formatDate(value) {
  if (typeof value !== "string" || !value) {
    return "Not provided";
  }
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) {
    return "Invalid timestamp";
  }
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date);
}

export function formatDuration(milliseconds) {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) {
    return "Not provided";
  }
  const seconds = Math.floor(milliseconds / 1000);
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return minutes ? `${minutes}m ${remainder}s` : `${remainder}s`;
}

export function truncateMiddle(value, maximum = 32) {
  const text = String(value);
  if (text.length <= maximum || maximum < 9) {
    return text;
  }
  const side = Math.floor((maximum - 1) / 2);
  return `${text.slice(0, side)}…${text.slice(-side)}`;
}

export function statusLabel(value) {
  if (typeof value !== "string" || !value) {
    return "Not provided";
  }
  return value.toLowerCase().replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function productStatus(value) {
  const statuses = {
    QUEUED: { label: "Queued", tone: "neutral" },
    RUNNING: { label: "Running", tone: "warning" },
    PUBLISHED_PENDING_FINALIZATION: {
      label: "Published, finalization pending",
      tone: "warning",
    },
    BLOCKED_BY_PREDECESSOR: { label: "Blocked by predecessor", tone: "warning" },
    COMPLETED: { label: "Completed", tone: "success" },
    CANCELLED: { label: "Cancelled", tone: "neutral" },
    FAILED: { label: "Failed", tone: "failure" },
  };
  return statuses[value] || { label: "Unknown status", tone: "neutral" };
}

export function stageProgress(value) {
  const states = {
    PENDING: { label: "Pending", tone: "neutral" },
    WAITING: { label: "Waiting", tone: "neutral" },
    RUNNING: { label: "Running", tone: "warning" },
    COMPLETE: { label: "Complete", tone: "success" },
    PARTIAL: { label: "Partial", tone: "warning" },
    FAILED: { label: "Failed", tone: "failure" },
    CANCELLED: { label: "Cancelled", tone: "neutral" },
    NOT_APPLICABLE: { label: "Not applicable", tone: "neutral" },
  };
  return states[value] || { label: "Unknown state", tone: "neutral" };
}

export function coverageState(value) {
  const states = {
    COMPLETE: "Complete",
    COMPLETE_WITH_FINDINGS: "Complete with findings",
    COMPLETE_WITH_SUPPRESSIONS: "Complete with suppressions",
    PARTIAL: "Partial",
    FAILED: "Failed",
    NOT_APPLICABLE: "Not applicable",
  };
  return states[value] || "Unknown state";
}

export function priorityLabel(value) {
  const priorities = {
    CRITICAL: "Critical",
    HIGH: "High",
    MEDIUM: "Medium",
    LOW: "Low",
    INFO: "Info",
    UNRANKED: "Priority not assigned",
  };
  return priorities[value] || "Unknown priority";
}

export function priorityPresentation(value) {
  const tones = {
    CRITICAL: "failure",
    HIGH: "failure",
    MEDIUM: "warning",
    LOW: "warning",
    INFO: "neutral",
    UNRANKED: "neutral",
  };
  return {
    label: priorityLabel(value),
    tone: tones[value] || "neutral",
  };
}

export function lifecycleState(value) {
  const states = {
    NEW: "New",
    EXISTING: "Existing",
    RESOLVED: "Resolved",
    REOPENED: "Reopened",
  };
  return states[value] || "Unknown lifecycle";
}

export function authorityLabel(value) {
  const authorities = {
    "semgrep-ce": "Semgrep",
    gitleaks: "Gitleaks",
    "osv.dev": "OSV",
    checkov: "Checkov",
  };
  return authorities[value] || "Unknown authority";
}

export function findingCategory(value) {
  const categories = {
    CODE_SECURITY: "Code security",
    SECRET_EXPOSURE: "Secret exposure",
    DEPENDENCY_VULNERABILITY: "Dependency vulnerability",
    CONFIGURATION_SECURITY: "Configuration security",
  };
  return categories[value] || "Unknown category";
}

export function paginationLabel({ total, limit, offset }) {
  if (!total) {
    return "Showing 0 of 0";
  }
  const start = Math.min(offset + 1, total);
  const end = Math.min(offset + limit, total);
  return `Showing ${start}–${end} of ${total}`;
}

export function boundedDisplayText(value, maximum = 160) {
  const text = typeof value === "string" && value ? value : "Not provided";
  if (text.length <= maximum) {
    return text;
  }
  return `${text.slice(0, maximum - 1)}…`;
}

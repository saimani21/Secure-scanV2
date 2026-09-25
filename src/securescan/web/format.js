"use strict";

export function formatDateTime(value) {
  if (typeof value !== "string" || !value) {
    return "Not provided";
  }
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
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

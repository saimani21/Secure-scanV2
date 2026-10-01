"use strict";

import { createElement, errorState, loadingState } from "/assets/components.js";
import { boundedDisplayText } from "/assets/format.js";

const BASIS = new Set(["EXACT_EVIDENCE", "CLASSIFICATION", "FAMILY", "EVIDENCE_ONLY"]);

function steps(label, values) {
  if (!Array.isArray(values)) return null;
  const items = values.slice(0, 12).filter((value) => typeof value === "string");
  return createElement("section", { className: "guidance-section" }, [
    createElement("h4", { textContent: label }),
    createElement("ol", {}, items.map((value) =>
      createElement("li", { textContent: boundedDisplayText(value, 1200) })
    )),
  ]);
}

export function renderGuidance(state) {
  if (!state || !state.attempted) return null;
  if (state.loading) return loadingState("Loading exact-run guidance");
  const value = state.payload;
  if (!value || state.failed || !BASIS.has(value.basis_level)) {
    return errorState(
      "Guidance unavailable",
      "Verified guidance for this exact run could not be loaded. No fix was inferred.",
      "GUIDANCE_UNAVAILABLE",
    );
  }
  const content = [
    createElement("h3", { textContent: "Deterministic guidance" }),
    createElement("p", { textContent: `Guidance basis: ${value.basis_level}` }),
    createElement("p", { textContent: boundedDisplayText(value.summary, 1200) }),
  ];
  for (const section of [
    steps("Recommended actions", value.remediation_steps),
    steps("Verification", value.verification_steps),
    steps("Limitations", value.limitations),
  ]) {
    if (section) content.push(section);
  }
  return createElement("section", {
    className: "finding-guidance",
    attributes: { "aria-label": "Finding guidance" },
  }, content);
}

"use strict";

import { createElement } from "/assets/components.js";
import { createProject } from "/assets/project_mutations.js";
import { isCanonicalUuid } from "/assets/router.js";
import { beginRequest } from "/assets/state.js";

export function projectCreateForm({ create = createProject, navigate = (path) => window.location.assign(path) } = {}) {
  const input = createElement("input", {
    className: "project-name-input",
    attributes: { id: "project-create-name", name: "name", type: "text", required: "", maxlength: "200", autocomplete: "off" },
  });
  const submit = createElement("button", {
    className: "button button-primary",
    textContent: "Create project",
    attributes: { type: "submit" },
  });
  const message = createElement("p", {
    className: "project-create-message",
    attributes: { role: "status", "aria-live": "polite" },
  });
  const form = createElement("form", { className: "project-create-form" }, [
    createElement("label", { textContent: "Project name", attributes: { for: "project-create-name" } }),
    input,
    submit,
    message,
  ]);
  let pending = false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (pending) return;
    pending = true;
    submit.disabled = true;
    message.textContent = "Creating project…";
    const request = beginRequest();
    try {
      const project = await create(input.value, { signal: request.signal });
      if (request.isCurrent() && isCanonicalUuid(project.project_id)) {
        navigate(`/projects/${project.project_id}`);
      }
    } catch (error) {
      if (request.isCurrent() && error.name !== "AbortError") {
        message.textContent = error instanceof TypeError || error.code === "INVALID_PROJECT_NAME"
          ? "Enter a valid project name without control characters or surrounding spaces (maximum 200 bytes)."
          : "Project creation failed. Check the API and try again.";
      }
    } finally {
      if (request.isCurrent()) {
        pending = false;
        submit.disabled = false;
      }
      request.finish();
    }
  });
  return form;
}

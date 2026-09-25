"use strict";

const STATUS_TONES = new Set(["success", "warning", "failure", "neutral"]);

export function createElement(tagName, options = {}, children = []) {
  const node = document.createElement(tagName);
  if (options.className) {
    node.className = options.className;
  }
  if (options.textContent !== undefined) {
    node.textContent = String(options.textContent);
  }
  for (const [name, value] of Object.entries(options.attributes || {})) {
    if (name.toLowerCase().startsWith("on")) {
      throw new TypeError("Inline event attributes are prohibited.");
    }
    node.setAttribute(name, String(value));
  }
  for (const [name, value] of Object.entries(options.dataset || {})) {
    node.dataset[name] = String(value);
  }
  for (const child of children) {
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function codeValue(value, className = "") {
  return createElement("code", {
    className: ["code-value", className].filter(Boolean).join(" "),
    textContent: value || "Not provided",
  });
}

export function statusIndicator(label, tone = "neutral") {
  const safeTone = STATUS_TONES.has(tone) ? tone : "neutral";
  return createElement("span", {
    className: `status-indicator status-${safeTone}`,
  }, [
    createElement("span", {
      className: "status-dot",
      attributes: { "aria-hidden": "true" },
    }),
    createElement("span", { textContent: label }),
  ]);
}

export function breadcrumb(items) {
  const navigation = createElement("nav", {
    className: "breadcrumb",
    attributes: { "aria-label": "Breadcrumb" },
  });
  const list = createElement("ol");
  items.forEach((item, index) => {
    const current = index === items.length - 1;
    const entry = createElement("li");
    if (item.href && !current) {
      entry.append(createElement("a", { textContent: item.label, attributes: { href: item.href } }));
    } else {
      entry.append(
        createElement("span", {
          textContent: item.label,
          attributes: current ? { "aria-current": "page" } : {},
        }),
      );
    }
    list.append(entry);
  });
  navigation.append(list);
  return navigation;
}

export function pageHeader({ eyebrow, title, description }) {
  return createElement("header", { className: "page-header" }, [
    createElement("p", { className: "eyebrow", textContent: eyebrow }),
    createElement("h1", { textContent: title }),
    createElement("p", { className: "page-description", textContent: description }),
  ]);
}

export function loadingState(label) {
  return createElement("div", {
    className: "state-message state-loading",
    attributes: { role: "status" },
  }, [
    createElement("span", { className: "loading-mark", attributes: { "aria-hidden": "true" } }),
    createElement("span", { textContent: label }),
  ]);
}

export function emptyState(title, message, note = "") {
  const content = [
    createElement("h2", { textContent: title }),
    createElement("p", { textContent: message }),
  ];
  if (note) {
    content.push(createElement("p", { className: "state-note", textContent: note }));
  }
  return createElement("section", {
    className: "state-message state-empty",
    attributes: { role: "status" },
  }, content);
}

export function errorState(title, message, code) {
  return createElement("section", {
    className: "state-message state-error",
    attributes: { role: "alert" },
  }, [
    createElement("h2", { textContent: title }),
    createElement("p", { textContent: message }),
    codeValue(code, "state-code"),
  ]);
}

export function copyButton(value, label = "Copy") {
  const button = createElement("button", {
    className: "button button-secondary",
    textContent: label,
    attributes: { type: "button" },
  });
  const announcement = createElement("span", {
    className: "visually-hidden",
    attributes: { role: "status", "aria-live": "polite" },
  });
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(String(value));
      announcement.textContent = "Copied to clipboard.";
    } catch (_error) {
      announcement.textContent = "Copy failed.";
    }
  });
  return createElement("span", { className: "copy-control" }, [button, announcement]);
}

export function sectionHeading(title, description = "", id = "") {
  const content = [
    createElement("h2", { textContent: title, attributes: id ? { id } : {} }),
  ];
  if (description) {
    content.push(createElement("p", { textContent: description }));
  }
  return createElement("header", { className: "section-heading" }, content);
}

export function resourceRegion(label) {
  const region = createElement("div", {
    className: "resource-region",
    attributes: { "aria-label": label, "aria-busy": "true" },
  });
  region.append(loadingState(`Loading ${label.toLowerCase()}`));
  return region;
}

export function paginationControls(page, onPrevious, onNext) {
  const previous = createElement("button", {
    className: "button button-secondary",
    textContent: "Previous",
    attributes: { type: "button", "aria-label": "Previous page" },
  });
  const next = createElement("button", {
    className: "button button-secondary",
    textContent: "Next",
    attributes: { type: "button", "aria-label": "Next page" },
  });
  previous.disabled = page.offset <= 0;
  next.disabled = page.offset + page.limit >= page.total;
  previous.addEventListener("click", onPrevious);
  next.addEventListener("click", onNext);
  return createElement("nav", {
    className: "pagination",
    attributes: { "aria-label": "Pagination" },
  }, [
    previous,
    createElement("span", { className: "pagination-label", textContent: page.label }),
    next,
  ]);
}

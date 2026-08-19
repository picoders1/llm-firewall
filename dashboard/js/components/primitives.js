/**
 * Shared UI primitives: states, badges, cards, tables.
 *
 * Two rules run through all of them:
 *
 * 1. **Status is never colour alone.** Every badge carries a glyph and a word,
 *    so the interface still reads on a monochrome display or to a colour-blind
 *    operator (§5, §29).
 * 2. **Absence is stated, never defaulted.** `empty`, `degraded` and `error` are
 *    distinct states with distinct copy, because "no traffic" and "the database
 *    is unreachable" are different facts about the system.
 */

import { el, icon, fragment } from "../dom.js";
import { NOT_AVAILABLE } from "../formatters.js";

/** Decision/status vocabulary: glyph + label + token class, in one place. */
export const DECISION = {
  allow:   { label: "Allow",   glyph: "●", cls: "allow" },
  warn:    { label: "Warn",    glyph: "▲", cls: "warn" },
  redact:  { label: "Redact",  glyph: "◆", cls: "redact" },
  block:   { label: "Block",   glyph: "■", cls: "block" },
  detector_failure: { label: "Detector failure", glyph: "✕", cls: "failure" },
  upstream_failure: { label: "Upstream failure", glyph: "✕", cls: "failure" },
  not_evaluated:    { label: "Not evaluated",    glyph: "○", cls: "unknown" },
};

export function decisionMeta(value) {
  return DECISION[value] ?? { label: value ? String(value) : "Unknown", glyph: "○", cls: "unknown" };
}

export function badge(text, variant = "unknown", glyph = null) {
  return el("span", { class: `badge badge--${variant}` }, [
    glyph ? el("span", { class: "badge__glyph", text: glyph, "aria-hidden": "true" }) : null,
    el("span", { text }),
  ]);
}

export function decisionBadge(value) {
  const meta = decisionMeta(value);
  return badge(meta.label, meta.cls, meta.glyph);
}

export function card(title, body, { hint = null, flush = false, actions = null } = {}) {
  return el("section", { class: "card" }, [
    title
      ? el("header", { class: "card__head" }, [
          el("h2", { class: "card__title", text: title }),
          hint ? el("span", { class: "card__hint", text: hint }) : null,
          actions,
        ])
      : null,
    el("div", { class: `card__body${flush ? " card__body--flush" : ""}` }, [body]),
  ]);
}

export function emptyState(title, body, iconName = "empty") {
  return el("div", { class: "state" }, [
    el("div", { class: "state__icon" }, [icon(iconName, 32)]),
    el("p", { class: "state__title", text: title }),
    body ? el("p", { class: "state__body", text: body }) : null,
  ]);
}

export function errorState(error, { onRetry = null } = {}) {
  const message = error?.userMessage ?? "Something went wrong.";
  return el("div", { class: "state state--error" }, [
    el("div", { class: "state__icon" }, [icon("alert", 32)]),
    el("p", { class: "state__title", text: "Could not load this data" }),
    el("p", { class: "state__body", text: message }),
    onRetry ? el("button", { class: "btn", type: "button", onClick: onRetry }, ["Try again"]) : null,
  ]);
}

export function degradedState(title, body) {
  return el("div", { class: "state state--degraded" }, [
    el("div", { class: "state__icon" }, [icon("info", 32)]),
    el("p", { class: "state__title", text: title }),
    el("p", { class: "state__body", text: body }),
  ]);
}

/** A degraded banner that still lets the rest of the page render (§38). */
export function degradedBanner(title, body) {
  return el("div", { class: "banner banner--degraded", role: "status" }, [
    icon("info", 16),
    el("div", {}, [el("strong", { text: title }), el("span", { text: body })]),
  ]);
}

export function errorBanner(title, body) {
  return el("div", { class: "banner banner--error", role: "alert" }, [
    icon("alert", 16),
    el("div", {}, [el("strong", { text: title }), el("span", { text: body })]),
  ]);
}

export function skeletonBlock(lines = 3) {
  return el(
    "div",
    { class: "stack", "aria-hidden": "true" },
    Array.from({ length: lines }, (_, index) =>
      el("div", {
        class: "skeleton skeleton--text",
        style: `width:${[92, 74, 60, 84][index % 4]}%`,
      }),
    ),
  );
}

export function skeletonCards(count = 6) {
  return el(
    "div",
    { class: "grid grid--kpi", "aria-hidden": "true" },
    Array.from({ length: count }, () =>
      el("div", { class: "kpi" }, [
        el("div", { class: "skeleton skeleton--text", style: "width:50%" }),
        el("div", { class: "skeleton skeleton--value" }),
      ]),
    ),
  );
}

/** Loading region announced to assistive technology rather than silently blank. */
export function loading(node) {
  return el("div", { role: "status", "aria-busy": "true", "aria-label": "Loading" }, [node]);
}

export function kpi({ label, value, foot = null, state = null, glyph = null }) {
  return el("article", { class: "kpi", dataset: state ? { state } : {} }, [
    el("div", { class: "kpi__label" }, [
      glyph ? el("span", { text: glyph, "aria-hidden": "true" }) : null,
      el("span", { text: label }),
    ]),
    el("div", { class: "kpi__value", text: value }),
    foot ? el("div", { class: "kpi__foot", text: foot }) : null,
  ]);
}

export function defineList(rows) {
  return el(
    "dl",
    { class: "dl" },
    fragment(
      rows.flatMap(([term, value]) => [
        el("dt", { text: term }),
        el("dd", {}, [
          value === null || value === undefined
            ? el("span", { class: "not-available", text: NOT_AVAILABLE })
            : value instanceof Node
              ? value
              : el("span", { text: String(value) }),
        ]),
      ]),
    ),
  );
}

/**
 * Dense data table.
 * @param {{columns: Array, rows: Array, onRowActivate?: Function, caption?: string}} spec
 */
export function dataTable({ columns, rows, onRowActivate = null, caption = null }) {
  const head = el("thead", {}, [
    el(
      "tr",
      {},
      columns.map((column) =>
        el("th", { class: column.numeric ? "num" : "", scope: "col", text: column.label }),
      ),
    ),
  ]);

  const body = el(
    "tbody",
    {},
    rows.map((row) => {
      const cells = columns.map((column) => {
        const content = column.render(row);
        return el(
          "td",
          { class: column.numeric ? "num" : "", title: column.title?.(row) ?? null },
          [content instanceof Node ? content : el("span", { text: content ?? "" })],
        );
      });
      const attrs = { };
      if (onRowActivate) {
        // Rows are reachable and activatable from the keyboard, not just the mouse.
        attrs.tabindex = "0";
        attrs.role = "link";
        attrs.onClick = () => onRowActivate(row);
        attrs.onKeydown = (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onRowActivate(row);
          }
        };
      }
      return el("tr", attrs, cells);
    }),
  );

  return el("div", { class: "table-wrap" }, [
    el("table", { class: `table${onRowActivate ? " table--clickable" : ""}` }, [
      caption ? el("caption", { class: "sr-only", text: caption }) : null,
      head,
      body,
    ]),
  ]);
}

export function pagination({ page, pageSize, total, hasMore, onPage }) {
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);
  return el("div", { class: "pagination" }, [
    el("span", { text: `${from}–${to} of ${total}` }),
    el("div", { class: "pagination__spacer" }),
    el(
      "button",
      { class: "btn btn--sm", type: "button", disabled: page <= 1, onClick: () => onPage(page - 1) },
      [icon("back", 14), "Previous"],
    ),
    el("span", { class: "muted", text: `Page ${page}` }),
    el(
      "button",
      { class: "btn btn--sm", type: "button", disabled: !hasMore, onClick: () => onPage(page + 1) },
      ["Next", icon("chevron", 14)],
    ),
  ]);
}

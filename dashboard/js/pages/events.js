/**
 * Security Events explorer.
 *
 * Filtering and pagination are **server-side**. The browser never holds more
 * than one page, both because the backend caps `page_size` at 200 and because
 * re-filtering locally would show a filtered heading over an unfiltered subset
 * (§12).
 *
 * Filter state lives in the URL so a view can be shared or reloaded. Only filter
 * values go there — never event content.
 */

import { el, icon } from "../dom.js";
import { path } from "../router.js";
import { endpoints } from "../api.js";
import { formatTimestamp, titleCase } from "../formatters.js";
import {
  dataTable, decisionBadge, degradedState, emptyState, errorState,
  loading, pagination, skeletonBlock,
} from "../components/primitives.js";

const DECISIONS = ["allow", "warn", "redact", "block", "detector_failure", "upstream_failure"];
const DIRECTIONS = ["input", "output"];
const PROVENANCES = ["system_config", "user_input", "model_output", "tool_result", "external", "unknown"];
const TRUST = ["operator", "principal", "derived", "untrusted", "unknown"];
const WINDOWS = [
  { value: "1", label: "Last hour" },
  { value: "6", label: "Last 6 hours" },
  { value: "24", label: "Last 24 hours" },
  { value: "168", label: "Last 7 days" },
  { value: "720", label: "Last 30 days" },
];

function params(query) {
  return {
    hours: query.hours || "24",
    page: Number(query.page || 1),
    page_size: 50,
    decision: query.decision || "",
    detector: query.detector || "",
    direction: query.direction || "",
    provenance: query.provenance || "",
    trust: query.trust || "",
    request_id: query.request_id || "",
  };
}

export function skeleton() {
  return loading(el("div", { class: "card" }, [el("div", { class: "card__body" }, [skeletonBlock(10)])]));
}

export async function load(signal, { query }) {
  const active = params(query);
  try {
    return { ok: true, data: await endpoints.events({ ...active, signal }), active };
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    return { ok: false, error, active };
  }
}

function select({ label, name, value, options, onChange, includeAll = true }) {
  const node = el("select", { name, "aria-label": label, onChange: (event) => onChange(name, event.target.value) });
  if (includeAll) node.append(el("option", { value: "", text: "All" }));
  for (const option of options) {
    const isObject = typeof option === "object";
    const optionValue = isObject ? option.value : option;
    const optionLabel = isObject ? option.label : titleCase(option);
    const item = el("option", { value: optionValue, text: optionLabel });
    if (String(value) === String(optionValue)) item.selected = true;
    node.append(item);
  }
  return el("div", { class: "field" }, [el("label", { class: "field__label", text: label }), node]);
}

export function view(result, { navigate, setQuery }) {
  const active = result.active;

  const update = (name, value) => {
    // Any filter change returns to page 1; keeping the old page would silently
    // land the operator on an empty page of a smaller result set.
    const next = { ...active, [name]: value, page: 1 };
    delete next.page_size;
    setQuery(next);
  };

  const filters = el("div", { class: "filters" }, [
    select({ label: "Window", name: "hours", value: active.hours, options: WINDOWS, onChange: update, includeAll: false }),
    select({ label: "Decision", name: "decision", value: active.decision, options: DECISIONS, onChange: update }),
    select({ label: "Direction", name: "direction", value: active.direction, options: DIRECTIONS, onChange: update }),
    select({ label: "Provenance", name: "provenance", value: active.provenance, options: PROVENANCES, onChange: update }),
    select({ label: "Trust", name: "trust", value: active.trust, options: TRUST, onChange: update }),
    el("div", { class: "field" }, [
      el("label", { class: "field__label", text: "Detector", for: "filter-detector" }),
      el("input", {
        id: "filter-detector",
        type: "search",
        value: active.detector,
        placeholder: "injection.heuristic",
        onChange: (event) => update("detector", event.target.value.trim()),
      }),
    ]),
    el("div", { class: "field" }, [
      el("label", { class: "field__label", text: "Request ID", for: "filter-request" }),
      el("input", {
        id: "filter-request",
        type: "search",
        value: active.request_id,
        placeholder: "correlation id",
        onChange: (event) => update("request_id", event.target.value.trim()),
      }),
    ]),
    el(
      "button",
      {
        class: "btn",
        type: "button",
        onClick: () => setQuery({ hours: active.hours, page: 1 }),
      },
      ["Clear filters"],
    ),
  ]);

  if (!result.ok) {
    return el("div", { class: "card" }, [filters, errorState(result.error)]);
  }

  const payload = result.data;

  if (payload.status === "degraded") {
    return el("div", { class: "card" }, [
      filters,
      degradedState(
        "Security event data unavailable",
        "Audit persistence is not configured for this instance. System status, detector configuration and evaluation results remain available.",
      ),
    ]);
  }

  if (!payload.items.length) {
    return el("div", { class: "card" }, [
      filters,
      emptyState(
        "No security events",
        "No security events match these filters in the selected time window. A quiet firewall is a normal state — try widening the window or clearing filters.",
      ),
    ]);
  }

  const table = dataTable({
    caption: "Security events",
    columns: [
      {
        label: "Time",
        render: (row) => el("span", { class: "mono", text: formatTimestamp(row.timestamp) }),
      },
      { label: "Decision", render: (row) => decisionBadge(row.event_type) },
      {
        label: "Detector",
        render: (row) => el("span", { class: "mono truncate", style: "max-width:180px;display:inline-block", text: row.detector ?? "—" }),
        title: (row) => row.detector ?? "",
      },
      { label: "Category", render: (row) => titleCase(row.category) || "—" },
      { label: "Direction", render: (row) => row.direction },
      { label: "Provenance", render: (row) => el("span", { class: "tag", text: row.provenance }) },
      { label: "Severity", numeric: true, render: (row) => String(row.severity) },
      { label: "Score", numeric: true, render: (row) => (row.score === null ? "—" : row.score.toFixed(4)) },
      {
        label: "Request",
        render: (row) =>
          el("span", { class: "mono truncate", style: "max-width:110px;display:inline-block", text: row.request_id }),
        title: (row) => row.request_id,
      },
    ],
    rows: payload.items,
    onRowActivate: (row) => navigate(path(`/events/${row.event_id}`)),
  });

  return el("div", { class: "card" }, [
    filters,
    table,
    pagination({
      page: payload.page.page,
      pageSize: payload.page.page_size,
      total: payload.page.total,
      hasMore: payload.page.has_more,
      onPage: (page) => setQuery({ ...active, page }),
    }),
  ]);
}

export const meta = {
  title: "Security Events",
  subtitle: "Every non-benign decision, filtered server-side",
};
export { icon };

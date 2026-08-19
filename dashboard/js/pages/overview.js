/**
 * Overview — the command centre.
 *
 * Renders whatever loaded. If the events endpoint fails but the overview
 * succeeds, the page still shows the overview and says the events panel is
 * unavailable: one failing endpoint must not blank a security console (§38).
 *
 * No comparison figure is shown. The API returns a single window with no
 * previous-period counterpart, so a "+12% vs last week" badge would be invented
 * — and §8 says to omit the comparison rather than fabricate one.
 */

import { el, icon } from "../dom.js";
import { path } from "../router.js";
import { endpoints, getAll } from "../api.js";
import { distribution, barList } from "../charts.js";
import { formatCount, formatTimestamp, titleCase } from "../formatters.js";
import {
  card, decisionBadge, degradedBanner, emptyState, errorBanner, errorState,
  kpi, loading, skeletonCards, dataTable,
} from "../components/primitives.js";

const WINDOW_HOURS = 24;

export function skeleton() {
  return loading(el("div", { class: "stack" }, [skeletonCards(6)]));
}

export async function load(signal) {
  return getAll(
    {
      overview: () => endpoints.overview({ hours: WINDOW_HOURS }),
      events: () => endpoints.events({ hours: WINDOW_HOURS, page_size: 8 }),
    },
    { signal },
  );
}

export function view(data, { navigate }) {
  const nodes = [];

  if (!data.overview.ok) {
    return errorState(data.overview.error);
  }

  const overview = data.overview.data;

  if (overview.status === "degraded") {
    nodes.push(
      degradedBanner(
        "Audit data unavailable",
        "Persistence is not configured for this instance, so traffic and event counts cannot be reported. Detector, policy and system views remain available.",
      ),
    );
  } else if (overview.window?.clamped) {
    nodes.push(
      degradedBanner(
        "Time window reduced",
        `Requested ${overview.window.requested_hours}h; the maximum supported window is ${overview.window.granted_hours}h.`,
      ),
    );
  }

  const totals = [
    { label: "Total Requests", value: overview.total_requests, state: null, glyph: null },
    { label: "Allowed", value: overview.allowed_requests, state: "allow", glyph: "●" },
    { label: "Warned", value: overview.warned_requests, state: "warn", glyph: "▲" },
    { label: "Redacted", value: overview.redacted_requests, state: "redact", glyph: "◆" },
    { label: "Blocked", value: overview.blocked_requests, state: "block", glyph: "■" },
    { label: "Detector Failures", value: overview.detector_failures, state: "failure", glyph: "✕" },
  ];

  nodes.push(
    el(
      "div",
      { class: "grid grid--kpi" },
      totals.map((entry) =>
        kpi({
          label: entry.label,
          value: formatCount(entry.value),
          state: entry.state,
          glyph: entry.glyph,
          foot: entry.label === "Total Requests" ? `Last ${overview.window.granted_hours}h` : null,
        }),
      ),
    ),
  );

  const decisionSegments = [
    { label: "Allow", value: overview.allowed_requests, cls: "allow" },
    { label: "Warn", value: overview.warned_requests, cls: "warn" },
    { label: "Redact", value: overview.redacted_requests, cls: "redact" },
    { label: "Block", value: overview.blocked_requests, cls: "block" },
    { label: "Not evaluated", value: overview.not_evaluated_requests, cls: "unknown" },
  ];

  nodes.push(
    el("div", { class: "grid grid--2" }, [
      card(
        "Decision distribution",
        distribution({
          segments: decisionSegments,
          total: overview.total_requests,
          summary: `Decision distribution over ${overview.window.granted_hours} hours: ${decisionSegments
            .map((segment) => `${segment.label} ${segment.value}`)
            .join(", ")}.`,
        }),
        { hint: `${formatCount(overview.total_requests)} requests` },
      ),
      card(
        "Detections by detector",
        overview.requests_by_detector.length
          ? barList({
              items: overview.requests_by_detector.map((entry) => ({
                label: entry.key,
                value: entry.count,
              })),
            })
          : emptyState("No detections", "No detector reported a positive finding in this window."),
      ),
    ]),
  );

  if (overview.requests_by_category.length) {
    nodes.push(
      card(
        "Security events by category",
        barList({
          items: overview.requests_by_category.map((entry) => ({
            label: titleCase(entry.key),
            value: entry.count,
          })),
          color: "var(--block)",
        }),
      ),
    );
  }

  // Recent events: an independent failure surface.
  if (!data.events.ok) {
    nodes.push(
      card(
        "Recent security events",
        errorBanner("Event data unavailable", data.events.error.userMessage),
      ),
    );
  } else {
    const events = data.events.data;
    const body = events.items.length
      ? dataTable({
          caption: "Most recent security events",
          columns: [
            { label: "Time", render: (row) => el("span", { class: "mono", text: formatTimestamp(row.timestamp, { seconds: false }) }) },
            { label: "Decision", render: (row) => decisionBadge(row.event_type) },
            { label: "Detector", render: (row) => el("span", { class: "mono truncate", text: row.detector ?? "—" }) },
            { label: "Category", render: (row) => titleCase(row.category) || "—" },
            { label: "Direction", render: (row) => row.direction },
            { label: "Score", numeric: true, render: (row) => (row.score === null ? "—" : row.score.toFixed(4)) },
          ],
          rows: events.items,
          onRowActivate: (row) => navigate(path(`/events/${row.event_id}`)),
        })
      : emptyState(
          "No security events",
          `No security events were recorded in the last ${overview.window.granted_hours} hours.`,
        );

    nodes.push(
      card("Recent security events", body, {
        flush: events.items.length > 0,
        actions: el("a", { class: "btn btn--sm", href: path("/events") }, ["View all", icon("chevron", 14)]),
      }),
    );
  }

  return el("div", { class: "stack" }, nodes);
}

export const meta = {
  title: "Overview",
  subtitle: "Live security posture across inspected traffic",
};

/**
 * Traffic & Latency.
 *
 * The rule this screen exists to honour: **a percentile with no observations
 * renders "No observations", never "0 ms"** (§15). The backend returns `null`
 * percentiles with `n: 0`, and every percentile is shown with its `n` so a p99
 * from four samples is visibly different from one from forty thousand.
 */

import { el } from "../dom.js";
import { endpoints, getAll } from "../api.js";
import { lineChart } from "../charts.js";
import { NO_OBSERVATIONS, formatCount, formatDuration, formatTime } from "../formatters.js";
import {
  card, degradedBanner, emptyState, errorState, errorBanner,
  kpi, loading, skeletonCards, skeletonBlock,
} from "../components/primitives.js";

const WINDOWS = [
  { value: "1", label: "Last hour" },
  { value: "6", label: "Last 6 hours" },
  { value: "24", label: "Last 24 hours" },
  { value: "168", label: "Last 7 days" },
];

export function skeleton() {
  return loading(el("div", { class: "stack" }, [skeletonCards(3), el("div", { class: "card" }, [el("div", { class: "card__body" }, [skeletonBlock(6)])])]));
}

export async function load(signal, { query }) {
  const hours = query.hours || "24";
  return {
    hours,
    ...(await getAll(
      {
        latency: (abort) => endpoints.latency({ hours }, { signal: abort }),
        traffic: (abort) => endpoints.traffic({ hours }, { signal: abort }),
      },
      { signal },
    )),
  };
}

/**
 * A percentile block. When `n` is 0 the values are rendered as prose, in a muted
 * italic style that cannot be mistaken for a measurement.
 */
function percentiles(title, block) {
  const measured = block && block.n > 0;
  return card(
    title,
    el("div", { class: "stack" }, [
      el("div", { class: "percentiles" }, [
        pct("p50", block?.p50, measured),
        pct("p95", block?.p95, measured),
        pct("p99", block?.p99, measured),
      ]),
      el("div", { class: "sample-note" }, [
        measured
          ? el("span", { text: `${formatCount(block.n)} observations` })
          : el("span", { text: "No observations in this window — nothing was measured." }),
      ]),
    ]),
  );
}

function pct(label, value, measured) {
  return el("div", { class: "pct" }, [
    el("span", { class: "pct__label", text: label }),
    measured && value !== null && value !== undefined
      ? el("span", { class: "pct__value", text: formatDuration(value) })
      : el("span", { class: "pct__value pct__value--none", text: NO_OBSERVATIONS }),
  ]);
}

export function view(data, { setQuery }) {
  const nodes = [];

  const windowPicker = el("div", { class: "field" }, [
    el("label", { class: "field__label", text: "Window", for: "traffic-window" }),
    (() => {
      const node = el("select", {
        id: "traffic-window",
        onChange: (event) => setQuery({ hours: event.target.value }),
      });
      for (const option of WINDOWS) {
        const item = el("option", { value: option.value, text: option.label });
        if (option.value === String(data.hours)) item.selected = true;
        node.append(item);
      }
      return node;
    })(),
  ]);
  nodes.push(el("div", { class: "u-row u-row--end" }, [windowPicker]));

  if (!data.latency.ok) {
    nodes.push(errorBanner("Latency unavailable", data.latency.error.userMessage));
  } else {
    const latency = data.latency.data;
    if (latency.status === "degraded") {
      nodes.push(
        degradedBanner(
          "Latency data unavailable",
          latency.note ?? "Audit persistence is not configured, so no observations exist to summarise.",
        ),
      );
    }
    nodes.push(
      el("div", { class: "grid grid--3" }, [
        percentiles("Gateway latency", latency.gateway_ms),
        percentiles("Detector latency", latency.detector_ms),
        percentiles("Upstream latency", latency.upstream_ms),
      ]),
    );

    const byDetector = Object.entries(latency.by_detector ?? {});
    if (byDetector.length) {
      nodes.push(
        card(
          "Latency by detector",
          el("div", { class: "table-wrap" }, [
            el("table", { class: "table" }, [
              el("thead", {}, [
                el("tr", {}, [
                  el("th", { scope: "col", text: "Detector" }),
                  el("th", { scope: "col", class: "num", text: "p50" }),
                  el("th", { scope: "col", class: "num", text: "p95" }),
                  el("th", { scope: "col", class: "num", text: "p99" }),
                  el("th", { scope: "col", class: "num", text: "n" }),
                ]),
              ]),
              el(
                "tbody",
                {},
                byDetector.map(([name, block]) =>
                  el("tr", {}, [
                    el("td", {}, [el("span", { class: "mono", text: name })]),
                    el("td", { class: "num", text: block.n ? formatDuration(block.p50) : NO_OBSERVATIONS }),
                    el("td", { class: "num", text: block.n ? formatDuration(block.p95) : NO_OBSERVATIONS }),
                    el("td", { class: "num", text: block.n ? formatDuration(block.p99) : NO_OBSERVATIONS }),
                    el("td", { class: "num", text: formatCount(block.n) }),
                  ]),
                ),
              ),
            ]),
          ]),
          { flush: true },
        ),
      );
    }
  }

  if (!data.traffic.ok) {
    nodes.push(errorBanner("Traffic unavailable", data.traffic.error.userMessage));
    return el("div", { class: "stack" }, nodes);
  }

  const traffic = data.traffic.data;
  const totals = traffic.totals;

  if (traffic.status === "degraded") {
    nodes.push(degradedBanner("Traffic data unavailable", "Audit persistence is not configured for this instance."));
  } else if (totals) {
    nodes.push(
      el("div", { class: "grid grid--kpi" }, [
        kpi({ label: "Requests", value: formatCount(totals.requests) }),
        kpi({ label: "Success", value: formatCount(totals.success), state: "allow", glyph: "●" }),
        kpi({ label: "4xx", value: formatCount(totals.client_errors), state: "warn", glyph: "▲" }),
        kpi({ label: "5xx", value: formatCount(totals.server_errors), state: "block", glyph: "■" }),
        kpi({ label: "Upstream failures", value: formatCount(totals.upstream_failures), state: "failure", glyph: "✕" }),
        kpi({ label: "Detector failures", value: formatCount(totals.detector_failures), state: "failure", glyph: "✕" }),
      ]),
    );
  }

  const points = traffic.points ?? [];
  const volume = points.length
    ? lineChart({
        series: [
          {
            key: "requests",
            label: "Requests",
            color: "var(--accent)",
            points: points.map((point) => ({ label: formatTime(point.bucket), value: point.requests })),
          },
          {
            key: "success",
            label: "Success",
            color: "var(--allow)",
            points: points.map((point) => ({ label: formatTime(point.bucket), value: point.success })),
          },
          {
            key: "client",
            label: "4xx",
            color: "var(--warn)",
            points: points.map((point) => ({ label: formatTime(point.bucket), value: point.client_errors })),
          },
          {
            key: "server",
            label: "5xx",
            color: "var(--block)",
            points: points.map((point) => ({ label: formatTime(point.bucket), value: point.server_errors })),
          },
        ],
        summary: `Request volume in ${traffic.interval} buckets over the selected window.`,
      })
    : emptyState("No traffic in this window", "No requests reached the gateway during the selected period.");

  nodes.push(card("Request volume", volume, { hint: `${traffic.interval} buckets` }));

  return el("div", { class: "stack" }, nodes);
}

export const meta = {
  title: "Traffic & Latency",
  subtitle: "Throughput and where the time goes",
};

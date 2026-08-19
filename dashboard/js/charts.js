/**
 * Charts, drawn as SVG with no charting library.
 *
 * Three requirements shape the implementation:
 *
 * 1. **Accessible.** Every chart carries a text summary in the accessibility
 *    tree (`role="img"` + `aria-label`) plus a visually-hidden table of the
 *    underlying numbers. A chart nobody can read with a screen reader is not
 *    "information-dense", it is information-hidden (§16, §29).
 * 2. **Honest.** A series with no observations renders an empty state, not a
 *    flat line at zero. A flat line at zero is a measurement.
 * 3. **Responsive.** Charts use a viewBox and `preserveAspectRatio`, so layout
 *    is CSS's job and the SVG scales without re-rendering on resize.
 */

import { el, svg } from "./dom.js";
import { formatCount, formatDuration, formatTime } from "./formatters.js";
import { emptyState } from "./components/primitives.js";

const PAD = { top: 12, right: 12, bottom: 24, left: 44 };

function niceCeiling(value) {
  if (value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  return Math.ceil(value / magnitude) * magnitude;
}

function scale(points, width, height, maxY) {
  const stepX = points.length > 1 ? width / (points.length - 1) : 0;
  return points.map((point, index) => ({
    ...point,
    x: PAD.left + index * stepX,
    y: PAD.top + height - (maxY ? (point.value / maxY) * height : 0),
  }));
}

function linePath(scaled) {
  return scaled.map((point, index) => `${index === 0 ? "M" : "L"}${point.x.toFixed(2)} ${point.y.toFixed(2)}`).join(" ");
}

/** Visually hidden table so the numbers are readable, not just paintable. */
function dataTableFallback(caption, rows, headers) {
  return el("div", { class: "sr-only" }, [
    el("table", {}, [
      el("caption", { text: caption }),
      el("thead", {}, [el("tr", {}, headers.map((h) => el("th", { scope: "col", text: h })))]),
      el("tbody", {}, rows.map((cells) => el("tr", {}, cells.map((cell) => el("td", { text: String(cell) }))))),
    ]),
  ]);
}

function tooltip() {
  let node = null;
  return {
    show(html, x, y) {
      if (!node) {
        node = el("div", { class: "tooltip", role: "presentation" });
        document.body.append(node);
      }
      node.replaceChildren(html);
      const rect = node.getBoundingClientRect();
      const left = Math.min(x + 14, window.innerWidth - rect.width - 8);
      const top = Math.max(8, y - rect.height - 12);
      node.style.left = `${left}px`;
      node.style.top = `${top}px`;
    },
    hide() {
      node?.remove();
      node = null;
    },
  };
}

const shared = tooltip();

/**
 * Multi-series line chart.
 * @param {{series: Array<{key,label,color,points:Array<{label,value}>}>, height?:number, formatValue?:Function, summary:string}} spec
 */
export function lineChart({ series, height = 200, formatValue = formatCount, summary }) {
  const populated = series.filter((s) => s.points.length > 0);
  if (populated.length === 0) {
    return emptyState("No data in this window", "Nothing has been recorded for the selected time range.");
  }

  const width = 720;
  const innerW = width - PAD.left - PAD.right;
  const innerH = height - PAD.top - PAD.bottom;
  const maxValue = Math.max(...populated.flatMap((s) => s.points.map((p) => p.value)), 0);
  const maxY = niceCeiling(maxValue);
  const length = Math.max(...populated.map((s) => s.points.length));

  const gridLines = [0, 0.25, 0.5, 0.75, 1].map((ratio) => {
    const y = PAD.top + innerH - ratio * innerH;
    return svg("g", {}, [
      svg("line", { class: "chart__grid", x1: PAD.left, x2: width - PAD.right, y1: y, y2: y }),
      svg("text", { class: "chart__axis", x: PAD.left - 8, y: y + 3, "text-anchor": "end" }, [
        String(formatValue(maxY * ratio)),
      ]),
    ]);
  });

  const drawn = populated.map((s) => {
    const scaled = scale(s.points, innerW, innerH, maxY);
    return svg("g", {}, [
      svg("path", { class: "chart__line", d: linePath(scaled), stroke: s.color }),
    ]);
  });

  // X labels: at most six, so they never collide at narrow widths.
  const step = Math.max(1, Math.ceil(length / 6));
  const xLabels = populated[0].points
    .map((point, index) => ({ point, index }))
    .filter(({ index }) => index % step === 0)
    .map(({ point, index }) => {
      const x = PAD.left + (length > 1 ? (index / (length - 1)) * innerW : 0);
      return svg("text", { class: "chart__axis", x, y: height - 6, "text-anchor": "middle" }, [point.label]);
    });

  const cursor = svg("line", { class: "chart__cursor", y1: PAD.top, y2: PAD.top + innerH, x1: 0, x2: 0, opacity: 0 });
  const markers = populated.map((s) => svg("circle", { class: "chart__dot", r: 3.5, fill: s.color, opacity: 0 }));

  const hit = svg("rect", {
    class: "chart__hit",
    x: PAD.left,
    y: PAD.top,
    width: innerW,
    height: innerH,
  });

  const chart = svg(
    "svg",
    {
      class: "chart",
      viewBox: `0 0 ${width} ${height}`,
      preserveAspectRatio: "none",
      role: "img",
      "aria-label": summary,
    },
    [...gridLines, ...drawn, cursor, ...markers, hit],
  );

  hit.addEventListener("pointermove", (event) => {
    const bounds = chart.getBoundingClientRect();
    const ratio = (event.clientX - bounds.left) / bounds.width;
    const index = Math.round(ratio * width >= PAD.left ? ((ratio * width - PAD.left) / innerW) * (length - 1) : 0);
    const clamped = Math.max(0, Math.min(length - 1, index));
    const x = PAD.left + (length > 1 ? (clamped / (length - 1)) * innerW : 0);
    cursor.setAttribute("x1", x);
    cursor.setAttribute("x2", x);
    cursor.setAttribute("opacity", 1);

    const rows = [];
    populated.forEach((s, seriesIndex) => {
      const point = s.points[clamped];
      if (!point) return;
      const y = PAD.top + innerH - (maxY ? (point.value / maxY) * innerH : 0);
      markers[seriesIndex].setAttribute("cx", x);
      markers[seriesIndex].setAttribute("cy", y);
      markers[seriesIndex].setAttribute("opacity", 1);
      rows.push(
        el("div", { class: "tooltip__row" }, [
          el("span", {}, [
            el("span", { class: "legend__swatch", style: `background:${s.color};display:inline-block;margin-right:6px` }),
            s.label,
          ]),
          el("span", { text: String(formatValue(point.value)) }),
        ]),
      );
    });
    const label = populated[0].points[clamped]?.label ?? "";
    shared.show(el("div", {}, [el("div", { class: "tooltip__title", text: label }), ...rows]), event.clientX, event.clientY);
  });

  const hide = () => {
    cursor.setAttribute("opacity", 0);
    markers.forEach((marker) => marker.setAttribute("opacity", 0));
    shared.hide();
  };
  hit.addEventListener("pointerleave", hide);
  hit.addEventListener("pointercancel", hide);

  const legend = el(
    "div",
    { class: "legend" },
    populated.map((s) =>
      el("div", { class: "legend__item" }, [
        el("span", { class: "legend__swatch", style: `background:${s.color}` }),
        el("span", { text: s.label }),
      ]),
    ),
  );

  const rows = populated[0].points.map((point, index) => [
    point.label,
    ...populated.map((s) => formatValue(s.points[index]?.value ?? 0)),
  ]);

  return el("div", {}, [
    chart,
    legend,
    dataTableFallback(summary, rows, ["Time", ...populated.map((s) => s.label)]),
  ]);
}

/**
 * Segmented distribution bar with legend and counts.
 * Shows the numbers next to the bar, so the visual is a summary of the data
 * rather than the only access to it.
 */
export function distribution({ segments, total, summary }) {
  if (!total) {
    return emptyState("No decisions recorded", "No requests were evaluated in this window.");
  }
  const present = segments.filter((segment) => segment.value > 0);
  const bar = el(
    "div",
    { class: "dist", role: "img", "aria-label": summary },
    present.map((segment) =>
      el("div", {
        class: `dist__seg dist__seg--${segment.cls}`,
        style: `width:${(segment.value / total) * 100}%`,
      }),
    ),
  );

  const legend = el(
    "div",
    { class: "legend" },
    segments.map((segment) =>
      el("div", { class: "legend__item" }, [
        el("span", { class: "legend__swatch", style: `background:var(--${segment.cls})` }),
        el("span", { text: segment.label }),
        el("span", { class: "legend__value", text: formatCount(segment.value) }),
        el("span", {
          class: "legend__pct",
          text: `${((segment.value / total) * 100).toFixed(1)}%`,
        }),
      ]),
    ),
  );

  return el("div", {}, [
    bar,
    legend,
    dataTableFallback(summary, segments.map((s) => [s.label, formatCount(s.value)]), ["Decision", "Count"]),
  ]);
}

/** Horizontal bars for a small categorical breakdown. */
export function barList({ items, total, color = "var(--accent)" }) {
  if (!items.length) return emptyState("Nothing recorded", "No categories were observed in this window.");
  const max = Math.max(...items.map((item) => item.value), 1);
  return el(
    "div",
    { class: "stack" },
    items.map((item) =>
      el("div", { class: "stack", style: "gap:6px" }, [
        el("div", { style: "display:flex;justify-content:space-between;gap:12px;font-size:var(--text-sm)" }, [
          el("span", { class: "truncate", text: item.label, title: item.label }),
          el("span", { class: "num", text: formatCount(item.value) }),
        ]),
        el("div", { class: "meter" }, [
          el("div", { class: "meter__fill", style: `width:${(item.value / max) * 100}%;background:${color}` }),
        ]),
      ]),
    ),
  );
}

export const timeLabel = formatTime;
export const durationLabel = formatDuration;

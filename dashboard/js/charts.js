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
 * 3. **Responsive.** Charts are drawn at the container's measured pixel width,
 *    so one SVG unit is one CSS pixel at every size. This replaced a fixed
 *    viewBox stretched by `preserveAspectRatio="none"`, which scaled the axis
 *    **text** along with the geometry and left labels unreadable on a phone.
 *    The trade is a redraw on resize; see `lineChart` for how that is bounded.
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
 * Live-resizing registry for charts.
 *
 * One ResizeObserver for every chart on the page. Elements that leave the DOM
 * are unobserved on the next callback, because the router replaces a page's
 * nodes wholesale and an observer holding a strong reference to a detached
 * subtree is a leak that only shows up after an hour of navigating.
 */
const resizing = new WeakMap();
const observer =
  typeof ResizeObserver === "undefined"
    ? null
    : new ResizeObserver((entries) => {
        for (const entry of entries) {
          if (!entry.target.isConnected) {
            observer.unobserve(entry.target);
            resizing.delete(entry.target);
            continue;
          }
          const draw = resizing.get(entry.target);
          const width = Math.round(entry.contentRect.width);
          if (draw && width > 0) draw(width);
        }
      });

function onResize(node, draw) {
  if (!observer) return;
  resizing.set(node, draw);
  observer.observe(node);
}

/**
 * Multi-series line chart.
 *
 * ## Why this re-renders on resize
 *
 * It used to draw into a fixed 720-unit viewBox with `preserveAspectRatio="none"`
 * and let CSS stretch it. That kept layout in CSS and cost no resize handling,
 * but non-uniform scaling distorts **text** as well as geometry: on a phone the
 * SVG compressed to roughly half its authored width and the axis labels went
 * with it, thin and unreadable; on a wide monitor the same labels stretched.
 *
 * Drawing at the measured pixel width instead means one SVG unit is one CSS
 * pixel, so labels render at their true size at every width, and the point
 * spacing adapts rather than being squeezed. The cost is a redraw when the
 * container changes size, which is what the ResizeObserver above is for.
 *
 * @param {{series: Array<{key,label,color,points:Array<{label,value}>}>, height?:number, formatValue?:Function, summary:string}} spec
 */
export function lineChart({ series, height = 200, formatValue = formatCount, summary }) {
  const populated = series.filter((s) => s.points.length > 0);
  if (populated.length === 0) {
    return emptyState("No data in this window", "Nothing has been recorded for the selected time range.");
  }

  const maxValue = Math.max(...populated.flatMap((s) => s.points.map((p) => p.value)), 0);
  const maxY = niceCeiling(maxValue);
  const length = Math.max(...populated.map((s) => s.points.length));

  const host = el("div", { class: "chart-host" });

  function draw(width) {
    const innerW = Math.max(40, width - PAD.left - PAD.right);
    const innerH = height - PAD.top - PAD.bottom;

    const gridLines = [0, 0.25, 0.5, 0.75, 1].map((ratio) => {
      const y = PAD.top + innerH - ratio * innerH;
      return svg("g", {}, [
        svg("line", { class: "chart__grid", x1: PAD.left, x2: width - PAD.right, y1: y, y2: y }),
        svg("text", { class: "chart__axis", x: PAD.left - 8, y: y + 3, "text-anchor": "end" }, [
          String(formatValue(maxY * ratio)),
        ]),
      ]);
    });

    const drawn = populated.map((s) =>
      svg("g", {}, [
        svg("path", { class: "chart__line", d: linePath(scale(s.points, innerW, innerH, maxY)), stroke: s.color }),
      ]),
    );

    // Label density follows the available width rather than a fixed count, so a
    // narrow chart thins its axis instead of overlapping it.
    const maxLabels = Math.max(2, Math.floor(innerW / 90));
    const step = Math.max(1, Math.ceil(length / maxLabels));
    const xLabels = populated[0].points
      .map((point, index) => ({ point, index }))
      .filter(({ index }) => index % step === 0)
      .map(({ point, index }) => {
        const x = PAD.left + (length > 1 ? (index / (length - 1)) * innerW : 0);
        return svg("text", { class: "chart__axis", x, y: height - 6, "text-anchor": "middle" }, [point.label]);
      });

    const cursor = svg("line", { class: "chart__cursor", y1: PAD.top, y2: PAD.top + innerH, x1: 0, x2: 0, opacity: 0 });
    const markers = populated.map((s) => svg("circle", { class: "chart__dot", r: 3.5, fill: s.color, opacity: 0 }));
    const hit = svg("rect", { class: "chart__hit", x: PAD.left, y: PAD.top, width: innerW, height: innerH });

    const chart = svg(
      "svg",
      {
        class: "chart",
        viewBox: `0 0 ${width} ${height}`,
        width,
        height,
        role: "img",
        "aria-label": summary,
      },
      [...gridLines, ...drawn, ...xLabels, cursor, ...markers, hit],
    );

    hit.addEventListener("pointermove", (event) => {
      const bounds = chart.getBoundingClientRect();
      // One unit is one pixel, so the cursor position needs no rescaling.
      const offset = event.clientX - bounds.left - PAD.left;
      const ratio = innerW > 0 ? offset / innerW : 0;
      const clamped = Math.max(0, Math.min(length - 1, Math.round(ratio * (length - 1))));
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
              el("span", { class: "legend__swatch legend__swatch--inline", style: { background: s.color } }),
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

    host.replaceChildren(chart);
  }

  // Drawn once at an assumed width so the chart is never blank, then corrected
  // the moment the observer reports the real one.
  draw(720);
  onResize(host, draw);

  const legend = el(
    "div",
    { class: "legend" },
    populated.map((s) =>
      el("div", { class: "legend__item" }, [
        el("span", { class: "legend__swatch", style: { background: s.color } }),
        el("span", { text: s.label }),
      ]),
    ),
  );

  const rows = populated[0].points.map((point, index) => [
    point.label,
    ...populated.map((s) => formatValue(s.points[index]?.value ?? 0)),
  ]);

  return el("div", {}, [
    host,
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
        style: { "--seg-width": `${((segment.value / total) * 100).toFixed(3)}%` },
        title: `${segment.label}: ${formatCount(segment.value)}`,
      }),
    ),
  );

  const legend = el(
    "div",
    { class: "legend" },
    segments.map((segment) =>
      el("div", { class: "legend__item" }, [
        el("span", { class: "legend__swatch", style: { background: `var(--${segment.cls})` } }),
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

/**
 * Horizontal bars for a small categorical breakdown.
 *
 * `onSelect` makes a row a real link into the filtered event list. It is a
 * navigation, not a mutation: the console stays read-only (ADR-023), and the
 * row is a `<button>` so it is reachable from the keyboard rather than a
 * click-only affordance.
 */
export function barList({ items, total = null, color = "var(--accent)", onSelect = null, valueLabel = null }) {
  if (!items.length) return emptyState("Nothing recorded", "No categories were observed in this window.");
  const max = Math.max(...items.map((item) => item.value), 1);
  const sum = total ?? items.reduce((acc, item) => acc + item.value, 0);

  return el(
    "div",
    { class: "barlist" },
    items.map((item) => {
      const share = sum > 0 ? (item.value / sum) * 100 : 0;
      const body = [
        el("span", { class: "barlist__label truncate", text: item.label, title: item.label }),
        el("span", { class: "barlist__value num", text: valueLabel ? valueLabel(item) : formatCount(item.value) }),
        sum > 0 ? el("span", { class: "barlist__pct num", text: `${share.toFixed(1)}%` }) : null,
        el("span", { class: "barlist__track" }, [
          el("div", {
            class: "barlist__fill",
            style: { "--bar-width": `${((item.value / max) * 100).toFixed(3)}%`, "--bar-color": color },
          }),
        ]),
      ];

      if (!onSelect) return el("div", { class: "barlist__row" }, body);
      return el(
        "button",
        {
          class: "barlist__row barlist__row--action",
          type: "button",
          onClick: () => onSelect(item),
          title: `Show events for ${item.label}`,
        },
        body,
      );
    }),
  );
}

export const timeLabel = formatTime;
export const durationLabel = formatDuration;

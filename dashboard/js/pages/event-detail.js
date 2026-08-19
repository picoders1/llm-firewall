/**
 * Security event detail.
 *
 * Shows metadata only. There is no prompt, no completion, no header and no
 * payload here — not because they are filtered out, but because the audit schema
 * cannot store them and the API never returns them.
 *
 * Fields the backend returns as `null` render as "Not available", never as zero
 * or an empty string. A latency of 0 ms and an unrecorded latency are different
 * facts (§11).
 */

import { el, icon } from "../dom.js";
import { path } from "../router.js";
import { endpoints } from "../api.js";
import {
  card, decisionMeta, defineList, errorState, loading, skeletonBlock,
} from "../components/primitives.js";
import { NOT_AVAILABLE, formatDuration, formatScore, formatTimestamp, titleCase } from "../formatters.js";

export function skeleton() {
  return loading(el("div", { class: "card" }, [el("div", { class: "card__body" }, [skeletonBlock(8)])]));
}

export async function load(signal, { params }) {
  try {
    return { ok: true, data: await endpoints.event(params[0], { signal }) };
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    return { ok: false, error };
  }
}

const orNotAvailable = (value, format = String) =>
  value === null || value === undefined ? null : format(value);

export function view(result) {
  if (!result.ok) return errorState(result.error);
  const event = result.data;
  const meta = decisionMeta(event.event_type);

  const hero = el(
    "div",
    {
      class: "decision-hero",
      style: `background:var(--${meta.cls}-bg);border-color:color-mix(in srgb, var(--${meta.cls}) 35%, transparent)`,
    },
    [
      el("div", {
        class: "decision-hero__glyph",
        style: `background:var(--${meta.cls});color:var(--text-inverse)`,
        text: meta.glyph,
        "aria-hidden": "true",
      }),
      el("div", {}, [
        el("div", { class: "decision-hero__label", text: meta.label, style: `color:var(--${meta.cls})` }),
        el("div", {
          class: "decision-hero__sub",
          text: `${titleCase(event.category) || "Uncategorised"} · ${event.direction} · severity ${event.severity}`,
        }),
      ]),
    ],
  );

  // Score against threshold. Rendered only when a score exists — an empty bar
  // would imply a measured zero.
  let scoreBlock = el("p", { class: "not-available", text: "No score was recorded for this event." });
  if (event.score !== null && event.score !== undefined) {
    const pct = Math.max(0, Math.min(1, event.score)) * 100;
    scoreBlock = el("div", {}, [
      el("div", { class: "score-bar" }, [
        el("div", {
          class: "score-bar__fill",
          style: `width:${pct}%;background:var(--${meta.cls})`,
        }),
      ]),
      el("div", { class: "score-bar__labels" }, [
        el("span", { text: "0.0000" }),
        el("span", { class: "mono", text: `score ${formatScore(event.score)}` }),
        el("span", { text: "1.0000" }),
      ]),
    ]);
  }

  const identity = defineList([
    ["Event ID", el("span", { class: "mono", text: String(event.event_id) })],
    ["Request ID", el("span", { class: "mono", text: event.request_id })],
    ["Timestamp", formatTimestamp(event.timestamp)],
    ["Direction", event.direction],
    ["Detector", event.detector ? el("span", { class: "mono", text: event.detector }) : null],
    ["Category", titleCase(event.category) || null],
    ["Severity", String(event.severity)],
  ]);

  const context = defineList([
    ["Decision", event.decision ? titleCase(event.decision) : null],
    ["HTTP status", orNotAvailable(event.http_status)],
    ["Policy version", event.policy_version ? el("span", { class: "mono", text: event.policy_version }) : null],
    ["Provenance", el("span", { class: "tag", text: event.provenance })],
    ["Trust", el("span", { class: "tag", text: event.trust })],
    [
      "Upstream called",
      event.upstream_called === null || event.upstream_called === undefined
        ? null
        : event.upstream_called
          ? "Yes"
          : "No — the request never reached the model",
    ],
  ]);

  const latency = defineList([
    ["Gateway", orNotAvailable(event.gateway_latency_ms, formatDuration)],
    ["Detector", orNotAvailable(event.detector_latency_ms, formatDuration)],
    ["Upstream", orNotAvailable(event.upstream_latency_ms, formatDuration)],
  ]);

  const fingerprint = defineList([
    ["Content hash", event.content_hash ? el("span", { class: "mono truncate", text: event.content_hash }) : null],
    ["Content length", orNotAvailable(event.content_length, (value) => `${value} characters`)],
  ]);

  const detailEntries = Object.entries(event.details ?? {});
  const details = detailEntries.length
    ? defineList(
        detailEntries.map(([key, value]) => [
          titleCase(key),
          el("span", { class: "mono", text: Array.isArray(value) ? value.join(", ") : String(value) }),
        ]),
      )
    : el("p", { class: "not-available", text: "No additional detail was recorded." });

  return el("div", { class: "stack" }, [
    el("a", { class: "btn btn--ghost btn--sm", href: path("/events"), style: "align-self:flex-start" }, [
      icon("back", 14),
      "Back to events",
    ]),
    hero,
    el("div", { class: "grid grid--2" }, [
      card("Identity", identity),
      card("Request context", context),
    ]),
    el("div", { class: "grid grid--2" }, [
      card("Score", scoreBlock, { hint: "Comparable only against this detector's own threshold" }),
      card("Latency", latency),
    ]),
    el("div", { class: "grid grid--2" }, [
      card("Content fingerprint", fingerprint, { hint: "Hash and length only — content is never stored" }),
      card("Detector detail", details, { hint: "Rule identifiers and counts" }),
    ]),
    el("p", { class: "muted", style: "font-size:var(--text-xs)" }, [
      `Prompt and response text are never recorded. ${NOT_AVAILABLE} indicates a value the gateway did not observe, not a value of zero.`,
    ]),
  ]);
}

export const meta = { title: "Event detail", subtitle: "Metadata for one security decision" };
